/**
 * dsh-traffic-analysis-plugin —— DeepSeek Harness 的 pcap 分析插件。
 *
 * 设计原则（与 docs/ 保持一致）：
 * - Plugin 输出 observation（可下钻到 frame），不输出「拥塞/攻击」类高级结论；
 * - execute 返回完整规范值（供审计），output.render 输出有界的模型可见文本
 *   （预算截断 + 信封），audit.render_chars 记录渲染开销；
 * - 典型顺序：traffic_open → traffic_overview → traffic_query → traffic_inspect
 *   → traffic_query(scope=event) → traffic_evidence 复核；时序分析用 traffic_timeseries。
 */
import type { Context } from "@deepseek-ai/cordis";
import z, { type Schema } from "@deepseek-ai/schemastery";
import { defineTool, type ToolContentPart, type ToolParameterSpec } from "@deepseek-ai/dsh-tools";
import {
  TrafficSession,
  BackendUnavailableError,
  renderEnvelope,
  renderRows,
  applyRenderBudget,
  type EvidenceResult,
  type InspectResult,
  type OverviewResult,
  type TimeseriesResult,
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
  autoDownload: z
    .boolean()
    .default(true)
    .description("Download the pinned tshark build on first use when no system tshark is found"),
});

const USAGE =
  "Typical flow: traffic_open(path) → traffic_overview(capture_id) → traffic_query(scope=conversation) → traffic_inspect(conversation_id) → traffic_query(scope=event) for frame evidence → traffic_evidence(frames) to verify claims. Use traffic_timeseries for per-bin throughput/window/rtt series.";

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

const p = (spec: ToolParameterSpec): ToolParameterSpec => spec;

/**
 * output.schema 约定（dsh-tools 的严格 JSON Schema 边界）：
 * 顶层信封枚举全部键 + additionalProperties:false；来自 traffic-core 的嵌套
 * 复杂对象以 additionalProperties:true 透传（类型事实源在 traffic-core）。
 */
const objPassThrough = { type: "object" as const, additionalProperties: true };
const ENVELOPE = (props: Record<string, unknown>) => ({
  type: "object" as const,
  additionalProperties: false,
  properties: props,
});

const text = (s: string): ToolContentPart => ({ type: "text", text: s });

// ---------- renderers（execute 内复用以填充 audit.render_chars） ----------

function renderOpen(_args: { path: string }, value: { error?: string; capture?: unknown; hint?: string }): string {
  if (value.error) return `ERROR: ${value.error}\n${value.hint ?? ""}`;
  const c = value.capture as Record<string, unknown>;
  return (
    `capture ${c.capture_id}: ${c.format}, ${c.packet_count} packets, ${(Number(c.duration_ms) / 1000).toFixed(2)}s, ${(Number(c.size_bytes) / 1048576).toFixed(1)}MB\n` +
    `backend ${JSON.stringify(c.backend)}\nnext: traffic_overview(capture_id="${c.capture_id}")`
  );
}

function renderOverview(_args: { capture_id: string }, value: { error?: string; overview?: OverviewResult }): string {
  if (value.error) return `ERROR: ${value.error}`;
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
  return applyRenderBudget(
    `protocols:\n${proto}\n\nconversations: ${o.conversation_counts.tcp} tcp / ${o.conversation_counts.udp} udp\ntop by bytes:`,
    convs.split("\n"),
    `next: traffic_query(capture_id, {scope:"conversation"}) or traffic_inspect`,
  ).text;
}

function renderQuery(_args: unknown, value: { error?: string; hint?: string; result?: unknown }): string {
  if (value.error) return `ERROR: ${value.error}${value.hint ? `\n${value.hint}` : ""}`;
  const r = value.result as { items: Array<Record<string, unknown>> } & Parameters<typeof renderEnvelope>[0];
  return applyRenderBudget(renderEnvelope(r), renderRows(r.items).split("\n"), "").text;
}

function renderInspect(_args: unknown, value: { error?: string; inspect?: InspectResult }): string {
  if (value.error) return `ERROR: ${value.error}`;
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
  return applyRenderBudget(
    `${c.conversation_id} ${c.initiator.ip}:${c.initiator.port} → ${c.responder.ip}:${c.responder.port} [${c.protocol_tags.join("+")}] (direction_basis=${c.direction_basis})\n` +
      `packets f/r ${c.packets.forward}/${c.packets.reverse}  bytes f/r ${c.bytes.forward}/${c.bytes.reverse}\n` +
      `metrics: ${JSON.stringify(c.metrics)}\n` +
      `retransmission evidence frames: ${JSON.stringify(i.aggregates.retransmissions.evidence.frames)}${i.aggregates.retransmissions.evidence.truncated ? " (truncated)" : ""}\n` +
      `timeline ${renderEnvelope(i.timeline)}`,
    tl.split("\n"),
    "",
  ).text;
}

function renderEvidence(_args: unknown, value: { error?: string; evidence?: EvidenceResult }): string {
  if (value.error) return `ERROR: ${value.error}`;
  const e = value.evidence!;
  const head = `frames ${e.returned} of ${e.requested} requested${e.truncated ? " [TRUNCATED at 200]" : ""}${e.missing_frames.length ? ` missing: ${e.missing_frames.join(",")}` : ""}`;
  const rows = renderRows(
    e.frames.map((f) => ({
      frame: f.frame_number,
      t_ms: f.time_ms,
      src: f.ip_src !== null ? `${f.ip_src}:${f.src_port ?? ""}` : "",
      dst: f.ip_dst !== null ? `${f.ip_dst}:${f.dst_port ?? ""}` : "",
      flags: f.tcp_flags ?? "",
      seq: f.tcp_seq_raw ?? "",
      ack: f.tcp_ack_raw ?? "",
      len: f.tcp_len ?? "",
      win: f.tcp_window ?? "",
      rtt_ms: f.ack_rtt_ms ?? "",
      analysis: f.analysis.join("|"),
      info: f.http_method ?? f.http_status ?? f.dns_qname ?? f.tls_handshake_type ?? "",
    })),
  );
  return applyRenderBudget(head, rows.split("\n"), "raw fixed field set; verify claims against these records").text;
}

function renderTimeseries(_args: unknown, value: { error?: string; timeseries?: TimeseriesResult }): string {
  if (value.error) return `ERROR: ${value.error}`;
  const t = value.timeseries!;
  const head =
    `${t.conversation_id} metric=${t.metric} bin_ms=${t.bin_ms}${t.sampled ? ` (auto-widened from ${t.requested_bin_ms})` : ""} bins=${t.bins_count}\n` +
    `t_start_ms  forward  reverse`;
  const rows = t.bins.map((b) => `${b.t_start_ms}  ${b.forward ?? "-"}  ${b.reverse ?? "-"}`);
  return applyRenderBudget(head, rows, "").text;
}

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
        render: (args, value) => [text(renderOpen(args, value))],
      },
      async execute(args) {
        try {
          const session = await openSession(args.path);
          return { capture: session.capture };
        } catch (err) {
          if (err instanceof BackendUnavailableError) {
            return {
              error: err.message,
              hint: "Install Wireshark CLI (tshark+capinfos), or set plugin config tsharkPath; bundled auto-download is enabled by default on supported platforms.",
            };
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
        render: (args, value) => [text(renderOverview(args, value))],
      },
      async execute(args) {
        try {
          const overview = await getSession(args.capture_id).overview();
          overview.audit.render_chars = renderOverview(args, { overview }).length;
          return { overview };
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
        "where: conditions ({field,op,value}) combined with AND; ops: eq/ne/gt/gte/lt/lte/in/contains. " +
        "Conversation metrics include retransmission_count, rtt_median_ms, throughput_bps, missing_segment_count, http_txn_count, duration_ms, bytes_total... " +
        "Event fields: type, conversation_id, time_ms, direction, frame_number, plus typed attributes like attr.qname/attr.rcode_num/attr.status_code (require a matching type condition). " +
        "select/order_by/limit/offset supported; default projection is compact. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        query: p({
          type: "object",
          required: true,
          additionalProperties: true,
          description:
            'Query AST, e.g. {"scope":"conversation","where":[{"field":"retransmission_count","op":"gt","value":0}],"order_by":[{"field":"retransmission_count","direction":"desc"}],"limit":20}',
        }),
      },
      output: {
        schema: ENVELOPE({ result: objPassThrough, audit: objPassThrough, error: { type: "string" }, hint: { type: "string" } }),
        render: (args, value) => [text(renderQuery(args, value))],
      },
      async execute(args) {
        try {
          const { result, audit } = await getSession(args.capture_id).query(args.query);
          audit.render_chars = renderQuery(args, { result }).length;
          return { result, audit };
        } catch (err) {
          return {
            error: (err as Error).message,
            hint: "Fix the query per the message above; conditions are AND-only, fields are whitelisted per scope, attr.* fields need a type condition.",
          };
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
        "Inspect one conversation in depth: endpoints, direction-split counters, derived metrics (handshake/rtt/throughput, retransmission count with frame evidence) and its event timeline. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        conversation_id: p({ type: "string", required: true, description: 'e.g. "conv:tcp:0" (from traffic_query)' }),
        timeline_limit: p({ type: "number", description: "max timeline events returned (default 200, cap 500)" }),
      },
      output: {
        schema: ENVELOPE({ inspect: objPassThrough, error: { type: "string" } }),
        render: (args, value) => [text(renderInspect(args, value))],
      },
      async execute(args) {
        try {
          const inspect = await getSession(args.capture_id).inspect(args.conversation_id, {
            limit: args.timeline_limit,
          });
          inspect.audit.render_chars = renderInspect(args, { inspect }).length;
          return { inspect };
        } catch (err) {
          return { error: (err as Error).message };
        }
      },
    }),
  );

  ctx.tools.register(
    defineTool<
      { capture_id: string; frames?: number[]; event_ids?: string[] },
      { error?: string; evidence?: EvidenceResult }
    >({
      name: "traffic_evidence",
      description:
        "Fetch raw per-frame records (fixed field set: seq/ack/len/flags/window/ack_rtt/analysis flags/dns/http/tls) for given frame numbers or event_ids. " +
        "Use this to VERIFY claims against packet-level facts instead of dumping the whole capture. " +
        "Bounded at 200 frames per call; missing frame numbers are reported. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        frames: p({ type: "array", description: "frame numbers, e.g. [8,11,14]" }),
        event_ids: p({ type: "array", description: 'event ids, e.g. ["evt:000007"] (alternative to frames)' }),
      },
      output: {
        schema: ENVELOPE({ evidence: objPassThrough, error: { type: "string" } }),
        render: (args, value) => [text(renderEvidence(args, value))],
      },
      async execute(args) {
        try {
          const evidence = await getSession(args.capture_id).evidence({
            frames: args.frames,
            event_ids: args.event_ids,
          });
          evidence.audit.render_chars = renderEvidence(args, { evidence }).length;
          return { evidence };
        } catch (err) {
          return { error: (err as Error).message };
        }
      },
    }),
  );

  ctx.tools.register(
    defineTool<
      { capture_id: string; conversation_id: string; metric: string; bin_ms?: number },
      { error?: string; timeseries?: TimeseriesResult }
    >({
      name: "traffic_timeseries",
      description:
        "Server-side per-bin aggregation of one conversation: metric ∈ bytes|packets|window|rtt, " +
        "direction-split (forward=initiator→responder). bin_ms in [10,5000] (default 100); auto-widens beyond 500 bins (sampled=true). " +
        "Use for throughput shape, burst patterns, window starvation and RTT evolution — replaces manual frame dumps. " +
        USAGE,
      parameters: {
        capture_id: p({ type: "string", required: true, description: "capture_id from traffic_open" }),
        conversation_id: p({ type: "string", required: true, description: 'e.g. "conv:tcp:0"' }),
        metric: p({ type: "string", required: true, description: "bytes | packets | window | rtt" }),
        bin_ms: p({ type: "number", description: "bin width in milliseconds [10,5000], default 100" }),
      },
      output: {
        schema: ENVELOPE({ timeseries: objPassThrough, error: { type: "string" } }),
        render: (args, value) => [text(renderTimeseries(args, value))],
      },
      async execute(args) {
        try {
          const metric = args.metric as "bytes" | "packets" | "window" | "rtt";
          const ts = await getSession(args.capture_id).timeseries(
            args.conversation_id,
            metric,
            args.bin_ms ?? 100,
          );
          ts.audit.render_chars = renderTimeseries(args, { timeseries: ts }).length;
          return { timeseries: ts };
        } catch (err) {
          return { error: (err as Error).message };
        }
      },
    }),
  );
}
