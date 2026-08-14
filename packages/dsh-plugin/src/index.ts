/**
 * dsh-traffic-analysis-plugin —— DeepSeek Harness 的 pcap 分析插件。
 *
 * 设计原则（与 docs/ 保持一致）：
 * - Plugin 输出 observation（可下钻到 frame），不输出「拥塞/攻击」类高级结论；
 * - execute 返回完整规范值（供审计），output.render 输出有界的模型可见文本；
 * - 典型顺序：traffic_open → traffic_overview → traffic_query → traffic_inspect
 *   → traffic_query(scope=event) 下钻证据。
 */
import type { Context } from "@deepseek-ai/cordis";
import z, { type Schema } from "@deepseek-ai/schemastery";
import { defineTool, type ToolContentPart, type ToolParameterSpec } from "@deepseek-ai/dsh-tools";
import {
  TrafficSession,
  BackendUnavailableError,
  renderEnvelope,
  renderRows,
  type InspectResult,
  type OverviewResult,
  type TrafficQuery,
} from "traffic-core";

export const name = "traffic-analysis";
export const inject = ["tools"];

/** 插件配置（cordis config；用户在 cordis.yml 的 config: 下覆盖） */
export interface Config {
  tsharkPath?: string;
  autoDownload: boolean;
}

export const Config: Schema<Config> = z.object({
  tsharkPath: z.string().description("Path to a custom tshark binary (capinfos must sit next to it)"),
  autoDownload: z.boolean().default(true).description("Download the pinned tshark build on first use when no system tshark is found"),
});

const USAGE = "Typical flow: traffic_open(path) → traffic_overview(capture_id) → traffic_query(scope=conversation) → traffic_inspect(conversation_id) → traffic_query(scope=event) for frame-level evidence.";

/** 打开的会话注册表；容量上限防止模型打开过多文件不关闭 */
const MAX_SESSIONS = 8;
const sessions = new Map<string, TrafficSession>();

function getSession(captureId: string): TrafficSession {
  const s = sessions.get(captureId);
  if (!s) {
    throw new Error(
      `capture '${captureId}' is not open. Known: ${[...sessions.keys()].join(", ") || "(none)"}. Call traffic_open first.`,
    );
  }
  return s;
}

async function openSession(path: string): Promise<TrafficSession> {
  if (sessions.size >= MAX_SESSIONS) {
    const oldest = sessions.keys().next().value;
    if (oldest !== undefined) sessions.delete(oldest);
  }
  const session = await TrafficSession.open(path, pluginConfig);
  sessions.set(session.capture.capture_id, session);
  return session;
}

/** apply() 时由插件配置填充 */
let pluginConfig: { tsharkPath?: string; autoDownload?: boolean } = {};

/**
 * output.schema 约定（dsh-tools 的严格 JSON Schema 边界）：
 * 顶层信封枚举全部键 + additionalProperties:false；来自 traffic-core 的嵌套
 * 复杂对象（capture/overview/result…）以 additionalProperties:true 透传，
 * 类型事实源在 traffic-core，避免双处漂移。
 */
const objPassThrough = { type: "object" as const, additionalProperties: true };
const ENVELOPE = (props: Record<string, unknown>) => ({
  type: "object" as const,
  additionalProperties: false,
  properties: props,
});

const p = (spec: ToolParameterSpec): ToolParameterSpec => spec;

export function apply(ctx: Context, config: Config) {
  pluginConfig = { tsharkPath: config.tsharkPath, autoDownload: config.autoDownload };
  ctx.effect(() => () => sessions.clear());

  ctx.tools.register(
    defineTool<{ path: string }, { error?: string; capture?: unknown; hint?: string }>({
      name: "traffic_open",
      description:
        "Open a pcap/pcapng capture and establish its identity (fingerprint, duration, packet count). " +
        "Returns capture_id used by all other traffic_* tools. Does NOT parse packets yet. " +
        USAGE,
      parameters: {
        path: p({ type: "string", required: true, description: "Absolute path to the .pcap/.pcapng file" }),
      },
      output: {
        schema: ENVELOPE({ capture: objPassThrough, error: { type: "string" }, hint: { type: "string" } }),
        render: (_args, value) => {
          if (value.error) return [text(`ERROR: ${value.error}\n${value.hint ?? ""}`)];
          const c = value.capture as Record<string, unknown>;
          return [
            text(
              `capture ${c.capture_id}: ${c.format}, ${c.packet_count} packets, ${(Number(c.duration_ms) / 1000).toFixed(2)}s, ${(Number(c.size_bytes) / 1048576).toFixed(1)}MB\n` +
                `backend ${JSON.stringify(c.backend)}\nnext: traffic_overview(capture_id="${c.capture_id}")`,
            ),
          ];
        },
      },
      async execute({ path }) {
        try {
          const session = await openSession(path);
          return { capture: session.capture };
        } catch (err) {
          if (err instanceof BackendUnavailableError) {
            return { error: err.message, hint: "Install Wireshark CLI (tshark+capinfos), or set plugin config tsharkPath; bundled auto-download is enabled by default on supported platforms." };
          }
          return { error: (err as Error).message };
        }
      },
    }),
  );

  ctx.tools.register(
    defineTool<{ capture_id: string }, { error?: string; overview?: OverviewResult }>({
      name: "traffic_overview",
      description:
        "Get capture overview from the lightweight index: protocol distribution, endpoint/conversation counts, top conversations by bytes. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
      },
      output: {
        schema: ENVELOPE({ overview: objPassThrough, error: { type: "string" } }),
        render: (_args, value) => {
          if (value.error) return [text(`ERROR: ${value.error}`)];
          const o = value.overview!;
          const proto = o.protocol_distribution
            .map((p2) => `${"  ".repeat(p2.depth)}${p2.name}: ${p2.frames} frames`)
            .join("\n");
          const convs = renderRows(
            o.top_conversations_by_bytes.map((c) => ({
              transport: c.transport,
              a: c.endpoint_a,
              b: c.endpoint_b,
              frames: c.frames_a_to_b + c.frames_b_to_a,
              bytes: c.bytes_a_to_b + c.bytes_b_to_a,
              start_s: c.relative_start_s,
            })),
          );
          return [
            text(
              `protocols:\n${proto}\n\nconversations: ${o.conversation_counts.tcp} tcp / ${o.conversation_counts.udp} udp\ntop by bytes:\n${convs}\n\nnext: traffic_query(capture_id, {scope:"conversation"}) or traffic_inspect`,
            ),
          ];
        },
      },
      async execute({ capture_id }) {
        try {
          return { overview: await getSession(capture_id).overview() };
        } catch (err) {
          return { error: (err as Error).message };
        }
      },
    }),
  );

  ctx.tools.register(
    defineTool<
      { capture_id: string; query: TrafficQuery },
      { error?: string; hint?: string; result?: unknown; audit?: unknown }
    >({
      name: "traffic_query",
      description:
        'Run a bounded query over the Traffic Observation IR. scope: "conversation" | "event". ' +
        "where: array of [field, op, value]-style conditions ({field,op,value}) combined with AND; " +
        "ops: eq/ne/gt/gte/lt/lte/in/contains. select/order_by/limit/offset supported. " +
        "Conversation fields include retransmission_count, dns_query_count, tls_handshake_ms, tcp_handshake_ms, bytes_total, duration_ms... " +
        "Event fields: type, conversation_id, time_ms, direction, frame_number. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        query: p({
          type: "object",
          required: true,
          additionalProperties: true,
          description: 'Query AST, e.g. {"scope":"conversation","where":[{"field":"retransmission_count","op":"gt","value":0}],"order_by":[{"field":"retransmission_count","direction":"desc"}],"limit":20}',
        }),
      },
      output: {
        schema: ENVELOPE({ result: objPassThrough, audit: objPassThrough, error: { type: "string" }, hint: { type: "string" } }),
        render: (_args, value) => {
          if (value.error) return [text(`ERROR: ${value.error}${value.hint ? `\n${value.hint}` : ""}`)];
          const r = value.result as { items: Array<Record<string, unknown>> } & Parameters<typeof renderEnvelope>[0];
          const table = renderRows(r.items);
          return [text(`${renderEnvelope(r)}\n${table}`)];
        },
      },
      async execute({ capture_id, query }) {
        try {
          const { result, audit } = await getSession(capture_id).query(query);
          return { result, audit };
        } catch (err) {
          return { error: (err as Error).message, hint: "Fix the query per the message above; conditions are AND-only, fields are whitelisted per scope." };
        }
      },
    }),
  );

  ctx.tools.register(
    defineTool<
      { capture_id: string; conversation_id: string; timeline_limit?: number },
      { error?: string; inspect?: InspectResult }
    >({
      name: "traffic_inspect",
      description:
        "Inspect one conversation in depth: endpoints, direction-split counters, derived metrics (handshake timings, retransmission count with frame evidence) and its event timeline. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        conversation_id: p({ type: "string", required: true, description: 'e.g. "conv:tcp:0" (from traffic_query)' }),
        timeline_limit: p({ type: "number", description: "max timeline events returned (default 200, cap 500)" }),
      },
      output: {
        schema: ENVELOPE({ inspect: objPassThrough, error: { type: "string" } }),
        render: (_args, value) => {
          if (value.error) return [text(`ERROR: ${value.error}`)];
          const i = value.inspect!;
          const c = i.conversation;
          const tl = renderRows(
            i.timeline.items.map((e) => ({
              time_ms: e.time_ms,
              type: e.type,
              dir: e.direction === "initiator_to_responder" ? "fwd" : e.direction === "responder_to_initiator" ? "rev" : "?",
              frame: e.evidence.kind === "frame" ? e.evidence.frame_number : null,
            })),
          );
          return [
            text(
              `${c.conversation_id} ${c.initiator.ip}:${c.initiator.port} → ${c.responder.ip}:${c.responder.port} [${c.protocol_tags.join("+")}]\n` +
                `packets f/r ${c.packets.forward}/${c.packets.reverse}  bytes f/r ${c.bytes.forward}/${c.bytes.reverse}\n` +
                `metrics: ${JSON.stringify(c.metrics)}\n` +
                `retransmission evidence frames: ${JSON.stringify(i.aggregates.retransmissions.evidence.frames)}${i.aggregates.retransmissions.evidence.truncated ? " (truncated)" : ""}\n` +
                `timeline ${renderEnvelope(i.timeline)}\n${tl}`,
            ),
          ];
        },
      },
      async execute({ capture_id, conversation_id, timeline_limit }) {
        try {
          return {
            inspect: await getSession(capture_id).inspect(conversation_id, { limit: timeline_limit }),
          };
        } catch (err) {
          return { error: (err as Error).message };
        }
      },
    }),
  );
}

function text(s: string): ToolContentPart {
  return { type: "text", text: s };
}
