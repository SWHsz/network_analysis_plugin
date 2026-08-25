/**
 * AstArm 工具面：完整 v0.4 八工具（含 raw_query 逃生口，不许稻草人，RFC-002 §5.2）。
 * 渲染语义逐字移植 packages/dsh-plugin/src/index.ts（信封 + 预算截断 + audit.render_chars），
 * 底层直接 import traffic-core。zod 用 v3 写法（Stirrup 1.0.7 依赖 zod^3）。
 */
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { Tool } from "@stirrup/stirrup";
import {
  TrafficSession,
  renderEnvelope,
  renderRows,
  applyRenderBudget,
  type Capture,
  type EvidenceResult,
  type HttpTimelineResult,
  type InspectResult,
  type OverviewResult,
  type RawQueryResult,
  type TimeseriesResult,
  type TrafficQuery,
} from "traffic-core";
import { withTiming } from "./bash-arm.js";
import { paramValidationError } from "./tool-errors.js";
import type { Arm, ToolCallRecord } from "./types.js";
import { buildSystemPrompt } from "./prompts.js";

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

function validCapturePath(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const resolved = path.resolve(raw);
  if (!path.isAbsolute(resolved)) return null;
  if (!/\.(pcap|pcapng)$/i.test(resolved)) return null;
  if (resolved.includes("\0")) return null;
  return resolved;
}

type ToolResult = { content: string; success: boolean };
const ok = (content: string): ToolResult => ({ content, success: true });
const fail = (content: string): ToolResult => ({ content, success: false });

async function errText(fn: () => Promise<string>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    return fail(`ERROR: ${(err as Error).message}`);
  }
}

// ---------- 渲染器（移植自 dsh-plugin） ----------

function renderCapture(c: Capture): string {
  return (
    `capture ${c.capture_id}: ${c.format}, ${c.packet_count} packets, ${(c.duration_ms / 1000).toFixed(2)}s, ` +
    `${(c.size_bytes / 1048576).toFixed(1)}MB\n` +
    `backend ${JSON.stringify(c.backend)}\n` +
    `next: traffic_overview(capture_id="${c.capture_id}")`
  );
}

function renderOverview(o: OverviewResult): string {
  const proto = o.protocol_distribution.map((p) => `${"  ".repeat(p.depth)}${p.name}: ${p.frames} frames`).join("\n");
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

function renderQuery(r: { items: Array<Record<string, unknown>> } & Parameters<typeof renderEnvelope>[0]): string {
  return applyRenderBudget(renderEnvelope(r), renderRows(r.items).split("\n"), "").text;
}

function renderInspect(i: InspectResult): string {
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

function renderEvidence(e: EvidenceResult): string {
  const head =
    `frames ${e.returned} of ${e.requested} requested${e.truncated ? " [TRUNCATED at 200]" : ""}` +
    `${e.missing_frames.length ? ` missing: ${e.missing_frames.join(",")}` : ""}`;
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

function renderHttpTimeline(t: HttpTimelineResult): string {
  const head =
    `http transactions: ${t.transactions.length}${t.unmatched_requests > 0 ? ` (${t.unmatched_requests} unmatched request(s))` : ""}${t.conversation_id ? ` in ${t.conversation_id}` : ""}`;
  if (t.transactions.length === 0)
    return `${head}\n(no http transactions observed — plaintext HTTP only; HTTPS content is encrypted)`;
  const tEnd = Math.max(...t.transactions.map((x) => x.response_time_ms ?? x.request_time_ms), 1);
  const W = 40;
  const rows = t.transactions.map((x) => {
    const s = Math.round((x.request_time_ms / tEnd) * W);
    const e = Math.round(((x.response_time_ms ?? x.request_time_ms) / tEnd) * W);
    const bar = " ".repeat(Math.max(0, s)) + "█".repeat(Math.max(1, e - s));
    const dur = x.resp_time_ms !== null ? `${x.resp_time_ms}ms` : "…";
    return `${String(x.request_time_ms).padStart(8)}ms [${bar.padEnd(W)}] ${x.method ?? "?"} ${(x.uri ?? "").slice(0, 40)} → ${x.status_code ?? "?"} (${dur}) f${x.request_frame}${x.response_frame !== null ? `→${x.response_frame}` : ""}`;
  });
  return applyRenderBudget(head, rows, "").text;
}

function renderRaw(r: RawQueryResult): string {
  const head = `raw tshark fields${r.filter ? ` filter='${r.filter}'` : ""}: ${r.returned} rows${r.truncated ? " [TRUNCATED]" : ""}`;
  const rows = r.rows.map((cells) => cells.join("\t"));
  return applyRenderBudget(head, rows, `columns: ${r.fields.join(", ")}`).text;
}

function renderTimeseries(t: TimeseriesResult): string {
  const head =
    `${t.conversation_id} metric=${t.metric} bin_ms=${t.bin_ms}${t.sampled ? ` (auto-widened from ${t.requested_bin_ms})` : ""} bins=${t.bins_count}\n` +
    `t_start_ms  forward  reverse`;
  const rows = t.bins.map((b) => `${b.t_start_ms}  ${b.forward ?? "-"}  ${b.reverse ?? "-"}`);
  return applyRenderBudget(head, rows, "").text;
}

// ---------- 八工具定义 ----------

/* eslint-disable @typescript-eslint/no-explicit-any */

export class AstArm implements Arm {
  readonly name = "ast-v0.5";

  constructor(private readonly captureAbsPath: string) {}

  get systemPrompt(): string {
    return buildSystemPrompt("ast", this.captureAbsPath);
  }

  buildTools(records: ToolCallRecord[]): Array<Tool<any, any>> {
    // v0.2：必要参数前置守卫（四段式回显；空到达显式标注，F7 可观测信号）
    const requireParams = (
      tool: string,
      params: Record<string, unknown> | undefined,
      required: string[],
      expectedShape: string,
    ): ToolResult | null => {
      const empties: string[] = [];
      for (const key of required) {
        const v = params?.[key];
        if (v === undefined || v === null || (typeof v === "string" && v.trim() === "") || (Array.isArray(v) && v.length === 0)) {
          empties.push(key);
        }
      }
      if (empties.length === 0) return null;
      return fail(
        paramValidationError({
          tool,
          problem: `必要参数到达为空/缺失：${empties.join("、")}`,
          received: params,
          emptyArrivals: empties,
          expectedShape,
        }),
      );
    };

    const openTool: Tool<any, any> = {
      name: "traffic_open",
      description:
        "Open a pcap/pcapng capture and establish its identity (fingerprint, duration, packet count). " +
        "Returns capture_id used by all other traffic_* tools. Does NOT parse packets yet.",
      parameters: z.object({
        path: z.string().describe("Absolute path to the .pcap/.pcapng file"),
      }),
      executor: async (params: { path?: string }): Promise<ToolResult> => {
        const p = validCapturePath(params?.path);
        if (!p) {
          const pathEmpty = params?.path === undefined || params.path.trim() === "";
          return fail(
            paramValidationError({
              tool: "traffic_open",
              problem: "path 须为绝对路径且以 .pcap/.pcapng 结尾",
              received: params,
              emptyArrivals: pathEmpty ? ["path"] : [],
              expectedShape: "path(字符串: .pcap/.pcapng 绝对路径)",
            }),
          );
        }
        try {
          const session = await TrafficSession.open(p, {
            cacheDir: path.join(os.tmpdir(), "bench-ast-arm-cache"),
            autoDownload: false,
          });
          if (sessions.size >= MAX_SESSIONS) {
            const oldest = sessions.keys().next().value;
            if (oldest !== undefined) sessions.delete(oldest);
          }
          sessions.set(session.capture.capture_id, session);
          return ok(renderCapture(session.capture));
        } catch (err) {
          return fail(`ERROR: ${(err as Error).message}`);
        }
      },
    };

    const overviewTool: Tool<any, any> = {
      name: "traffic_overview",
      description:
        "Get capture overview from the lightweight index: protocol distribution, endpoint/conversation counts, top conversations by bytes.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
      }),
      executor: async (params: { capture_id?: string }): Promise<ToolResult> => {
        const guard = requireParams("traffic_overview", params, ["capture_id"], "capture_id(字符串: 来自 traffic_open)");
        if (guard) return guard;
        return errText(async () => renderOverview(await getSession(params?.capture_id ?? "").overview()));
      },
    };

    const QUERY_SCOPES = new Set(["conversation", "event", "frame", "stream"]);
    function asTrafficQuery(raw: unknown): TrafficQuery | null {
      if (typeof raw !== "object" || raw === null) return null;
      const q = raw as Record<string, unknown>;
      if (typeof q.scope !== "string" || !QUERY_SCOPES.has(q.scope)) return null;
      if (q.where !== undefined && !Array.isArray(q.where)) return null;
      if (q.select !== undefined && !Array.isArray(q.select)) return null;
      if (q.order_by !== undefined && !Array.isArray(q.order_by)) return null;
      if (q.limit !== undefined && typeof q.limit !== "number") return null;
      if (q.offset !== undefined && typeof q.offset !== "number") return null;
      return raw as TrafficQuery;
    }

    const queryTool: Tool<any, any> = {
      name: "traffic_query",
      description:
        'Run a bounded query over the Traffic Observation IR. scope: "conversation" | "event". ' +
        "where: conditions ({field,op,value}) combined with AND; ops: eq/ne/gt/gte/lt/lte/in/contains. " +
        "Conversation metrics include retransmission_count, rtt_median_ms, throughput_bps, missing_segment_count, http_txn_count, duration_ms, bytes_total... " +
        "Event fields: type, conversation_id, time_ms, direction, frame_number, plus typed attributes like attr.qname/attr.rcode_num/attr.status_code (require a matching type condition). " +
        "select/order_by/limit/offset supported; default projection is compact.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        query: z
          .object({})
          .passthrough()
          .describe(
            'Query AST, e.g. {"scope":"conversation","where":[{"field":"retransmission_count","op":"gt","value":0}],"order_by":[{"field":"retransmission_count","direction":"desc"}],"limit":20}',
          ),
      }),
      executor: async (params: { capture_id?: string; query?: unknown }): Promise<ToolResult> => {
        if (params?.capture_id === undefined || params.capture_id.trim() === "") {
          return fail(
            paramValidationError({
              tool: "traffic_query",
              problem: "capture_id 缺失，无法定位会话",
              received: params,
              emptyArrivals: ["capture_id"],
              expectedShape: "capture_id(字符串), query(对象: scope/where/select/order_by/limit)",
            }),
          );
        }
        const ast = asTrafficQuery(params?.query);
        if (!ast) {
          const q = params?.query;
          const queryEmpty =
            q === undefined || q === null || (typeof q === "object" && !Array.isArray(q) && Object.keys(q as object).length === 0);
          return fail(
            paramValidationError({
              tool: "traffic_query",
              problem: 'query 必须为非空 AST 对象（如 {"scope":"conversation","where":[...],"limit":20}）',
              received: params,
              emptyArrivals: queryEmpty ? ["query"] : [],
              expectedShape: "query(对象: scope/conversation|event, where(数组: {field,op,value}), order_by, limit), capture_id(字符串)",
            }),
          );
        }
        try {
          const runTrafficQuery = getSession(params?.capture_id ?? "").query.bind(getSession(params?.capture_id ?? ""));
          const { result } = await runTrafficQuery(ast);
          return ok(renderQuery(result as never));
        } catch (err) {
          return fail(
            `ERROR: ${(err as Error).message}\n` +
              "Fix the query: conditions are AND-only, fields are whitelisted per scope, attr.* fields need a type condition.",
          );
        }
      },
    };

    const inspectTool: Tool<any, any> = {
      name: "traffic_inspect",
      description:
        "Inspect one conversation in depth: endpoints, direction-split counters, derived metrics (handshake/rtt/throughput, retransmission count with frame evidence) and its event timeline.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        conversation_id: z.string().describe('e.g. "conv:tcp:0" (from traffic_query)'),
        timeline_limit: z.number().optional().describe("max timeline events returned (default 200, cap 500)"),
      }),
      executor: async (params: { capture_id?: string; conversation_id?: string; timeline_limit?: number }): Promise<ToolResult> => {
        const guard = requireParams("traffic_inspect", params, ["capture_id", "conversation_id"], "capture_id(字符串), conversation_id(字符串: 如 conv:tcp:0), timeline_limit(数字, 可选)");
        if (guard) return guard;
        return errText(async () =>
          renderInspect(await getSession(params?.capture_id ?? "").inspect(params?.conversation_id ?? "", { limit: params?.timeline_limit })),
        );
      },
    };

    const evidenceTool: Tool<any, any> = {
      name: "traffic_evidence",
      description:
        "Fetch raw per-frame records (fixed field set: seq/ack/len/flags/window/ack_rtt/analysis flags/dns/http/tls) for given frame numbers or event_ids. " +
        "Use this to VERIFY claims against packet-level facts instead of dumping the whole capture. Bounded at 200 frames per call; missing frame numbers are reported.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        frames: z.array(z.number()).optional().describe("frame numbers, e.g. [8,11,14]"),
        event_ids: z.array(z.string()).optional().describe('event ids, e.g. ["evt:000007"]'),
      }),
      executor: async (params: { capture_id?: string; frames?: number[]; event_ids?: string[] }): Promise<ToolResult> => {
        const guard = requireParams("traffic_evidence", params, ["capture_id"], "capture_id(字符串), frames(数字数组) 或 event_ids(字符串数组)——二选一");
        if (guard) return guard;
        return errText(async () =>
          renderEvidence(
            await getSession(params?.capture_id ?? "").evidence({ frames: params?.frames, event_ids: params?.event_ids }),
          ),
        );
      },
    };

    const timeseriesTool: Tool<any, any> = {
      name: "traffic_timeseries",
      description:
        "Server-side per-bin aggregation of one conversation: metric ∈ bytes|packets|window|rtt|tls_bytes, direction-split (forward=initiator→responder). " +
        "bin_ms in [10,5000] (default 100); auto-widens beyond 500 bins (sampled=true). Use for throughput shape, burst patterns, window starvation and RTT evolution.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        conversation_id: z.string().describe('e.g. "conv:tcp:0"'),
        metric: z.string().describe("bytes | packets | window | rtt | tls_bytes"),
        bin_ms: z.number().optional().describe("bin width in milliseconds [10,5000], default 100"),
      }),
      executor: async (params: { capture_id?: string; conversation_id?: string; metric?: string; bin_ms?: number }): Promise<ToolResult> => {
        const guard = requireParams("traffic_timeseries", params, ["capture_id", "conversation_id", "metric"], "capture_id(字符串), conversation_id(字符串), metric(bytes|packets|window|rtt), bin_ms(数字, 可选)");
        if (guard) return guard;
        return errText(async () =>
          renderTimeseries(
            await getSession(params?.capture_id ?? "").timeseries(
              params?.conversation_id ?? "",
              (params?.metric ?? "bytes") as "bytes",
              params?.bin_ms ?? 100,
            ),
          ),
        );
      },
    };

    const httpTimelineTool: Tool<any, any> = {
      name: "traffic_http_timeline",
      description:
        "HTTP transaction waterfall: pairs http_request/http_response events per conversation (FIFO by time) into transactions with method/uri/status/resp_time and frame evidence, rendered as an ASCII timeline. Plaintext HTTP only.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        conversation_id: z.string().optional().describe("optional: restrict to one conversation"),
      }),
      executor: async (params: { capture_id?: string; conversation_id?: string }): Promise<ToolResult> => {
        const guard = requireParams("traffic_http_timeline", params, ["capture_id"], "capture_id(字符串), conversation_id(字符串, 可选)");
        if (guard) return guard;
        return errText(async () => renderHttpTimeline(await getSession(params?.capture_id ?? "").httpTimeline(params?.conversation_id)));
      },
    };

    const rawQueryTool: Tool<any, any> = {
      name: "traffic_raw_query",
      description:
        "Bounded escape hatch for long-tail queries the IR does not cover: run tshark with a display filter and field list. " +
        "Field names are validated against the tshark vocabulary (unknown fields error out with hints). Structured argv (no shell); bounded rows (<=500) and cell sizes. Prefer traffic_query/traffic_evidence — use only when whitelists lack what you need.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        fields: z.array(z.string()).describe("tshark field names, e.g. ['dns.resp.ttl']"),
        display_filter: z.string().optional().describe('tshark display filter, e.g. "dns.flags.response==1"'),
        limit: z.number().optional().describe("max rows [1,500], default 100"),
      }),
      executor: async (params: { capture_id?: string; fields?: string[]; display_filter?: string; limit?: number }): Promise<ToolResult> => {
        const guard = requireParams("traffic_raw_query", params, ["capture_id", "fields"], "capture_id(字符串), fields(字符串数组: tshark 字段名), display_filter(字符串, 可选), limit(数字, 可选)");
        if (guard) return guard;
        return errText(async () =>
          renderRaw(
            await getSession(params?.capture_id ?? "").rawQuery({
              fields: params?.fields ?? [],
              display_filter: params?.display_filter,
              limit: params?.limit,
            }),
          ),
        );
      },
    };

    return [openTool, overviewTool, queryTool, inspectTool, evidenceTool, timeseriesTool, httpTimelineTool, rawQueryTool].map((t) =>
      withTiming(t, records),
    );
  }
}
