import type { Conversation, TrafficEvent } from "../types.js";
import type { FrameRecord } from "../frames.js";
import { EVENT_ATTR_FIELDS, EVENT_REGISTRY } from "../events/registry.js";

/** 合法操作符（v0.3.1：未知 op 一律报错，杜绝静默空集） */
const VALID_OPS = new Set(["eq", "ne", "gt", "gte", "lt", "lte", "in", "contains"]);

/** v0.1 查询 DSL：Filter + Projection + Ordering + Limit，条件之间只支持 AND。 */

export type QueryScope = "conversation" | "event" | "frame";

export type CompareOp = "eq" | "ne" | "gt" | "gte" | "lt" | "lte" | "in" | "contains";

export interface Condition {
  field: string;
  op: CompareOp;
  value: string | number | boolean | Array<string | number>;
}

export interface OrderBy {
  field: string;
  direction: "asc" | "desc";
}

export interface TrafficQuery {
  scope: QueryScope;
  where?: Condition[];
  select?: string[];
  order_by?: OrderBy[];
  limit?: number;
  offset?: number;
}

export class QueryValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QueryValidationError";
  }
}

export interface FieldSpec {
  /** 值类型 */
  type: "number" | "string" | "string[]";
  /** 从查询行（conversation / event / frame）取值的投影函数 */
  project: (obj: QueryRow) => unknown;
}

export type QueryRow = Conversation | TrafficEvent | FrameRecord;

const conv = (f: (c: Conversation) => unknown): FieldSpec["project"] => (o) =>
  f(o as unknown as Conversation);
const evt = (f: (e: TrafficEvent) => unknown): FieldSpec["project"] => (o) =>
  f(o as unknown as TrafficEvent);
const frm = (f: (r: FrameRecord) => unknown): FieldSpec["project"] => (o) =>
  f(o as unknown as FrameRecord);

export const CONVERSATION_FIELDS: Record<string, FieldSpec> = {
  conversation_id: { type: "string", project: conv((c) => c.conversation_id) },
  transport: { type: "string", project: conv((c) => c.transport) },
  initiator_ip: { type: "string", project: conv((c) => c.initiator.ip) },
  initiator_port: { type: "number", project: conv((c) => c.initiator.port) },
  responder_ip: { type: "string", project: conv((c) => c.responder.ip) },
  responder_port: { type: "number", project: conv((c) => c.responder.port) },
  start_ms: { type: "number", project: conv((c) => c.start_ms) },
  duration_ms: { type: "number", project: conv((c) => c.duration_ms) },
  packets_forward: { type: "number", project: conv((c) => c.packets.forward) },
  packets_reverse: { type: "number", project: conv((c) => c.packets.reverse) },
  packets_total: { type: "number", project: conv((c) => c.packets.forward + c.packets.reverse) },
  bytes_forward: { type: "number", project: conv((c) => c.bytes.forward) },
  bytes_reverse: { type: "number", project: conv((c) => c.bytes.reverse) },
  bytes_total: { type: "number", project: conv((c) => c.bytes.forward + c.bytes.reverse) },
  retransmission_count: { type: "number", project: conv((c) => c.metrics.retransmission_count) },
  dns_query_count: { type: "number", project: conv((c) => c.metrics.dns_query_count) },
  tls_handshake_count: { type: "number", project: conv((c) => c.metrics.tls_handshake_count) },
  tcp_handshake_ms: { type: "number", project: conv((c) => c.metrics.tcp_handshake_ms) },
  tls_handshake_ms: { type: "number", project: conv((c) => c.metrics.tls_handshake_ms) },
  rtt_median_ms: { type: "number", project: conv((c) => c.metrics.rtt_median_ms) },
  rtt_max_ms: { type: "number", project: conv((c) => c.metrics.rtt_max_ms) },
  throughput_bps: { type: "number", project: conv((c) => c.metrics.throughput_bps) },
  missing_segment_count: { type: "number", project: conv((c) => c.metrics.missing_segment_count) },
  http_txn_count: { type: "number", project: conv((c) => c.metrics.http_txn_count) },
  direction_basis: { type: "string", project: conv((c) => c.direction_basis) },
  protocol_tags: { type: "string[]", project: conv((c) => c.protocol_tags) },
};

export const EVENT_FIELDS: Record<string, FieldSpec> = {
  event_id: { type: "string", project: evt((e) => e.event_id) },
  conversation_id: { type: "string", project: evt((e) => e.conversation_id) },
  type: { type: "string", project: evt((e) => e.type) },
  time_ms: { type: "number", project: evt((e) => e.time_ms) },
  direction: { type: "string", project: evt((e) => e.direction) },
  frame_number: { type: "number", project: evt((e) => e.evidence.kind === "frame" ? e.evidence.frame_number : null) },
  ...Object.fromEntries(
    Object.entries(EVENT_ATTR_FIELDS).map(([name, spec]) => [
      `attr.${name}`,
      {
        type: spec.type,
        // 从事件 attributes 投影；缺失（null）按 null 语义参与比较
        project: evt((e) => e.attributes[name] ?? null),
      } satisfies FieldSpec,
    ]),
  ),
};

/**
 * 紧凑默认投影（Context Shaper v2）：不指定 select 时的输出列，
 * 主动收敛模型可见宽度；显式 select 不受影响。
 */
/** v0.3：frame scope —— 按白名单字段过滤/排序帧（来自缓存的帧表，不扫 pcap） */
export const FRAME_FIELDS: Record<string, FieldSpec> = {
  frame_number: { type: "number", project: frm((r) => r.frame_number) },
  time_ms: { type: "number", project: frm((r) => r.time_ms) },
  transport: { type: "string", project: frm((r) => r.transport) },
  ip_src: { type: "string", project: frm((r) => r.ip_src) },
  ip_dst: { type: "string", project: frm((r) => r.ip_dst) },
  src_port: { type: "number", project: frm((r) => r.src_port) },
  dst_port: { type: "number", project: frm((r) => r.dst_port) },
  /** 派生：conv:{transport}:{stream}（无流标识为 null） */
  conversation_id: {
    type: "string",
    project: frm((r) => (r.transport && r.stream_id !== null ? `conv:${r.transport}:${r.stream_id}` : null)),
  },
  tcp_seq_raw: { type: "number", project: frm((r) => r.tcp_seq_raw) },
  tcp_ack_raw: { type: "number", project: frm((r) => r.tcp_ack_raw) },
  tcp_len: { type: "number", project: frm((r) => r.tcp_len) },
  tcp_flags: { type: "string", project: frm((r) => r.tcp_flags) },
  tcp_window: { type: "number", project: frm((r) => r.tcp_window) },
  ack_rtt_ms: { type: "number", project: frm((r) => r.ack_rtt_ms) },
  tls_record_bytes: { type: "number", project: frm((r) => r.tls_record_bytes) },
  /** 命中的 tcp.analysis 标志（contains 查询） */
  analysis: { type: "string", project: frm((r) => (r.analysis.length ? r.analysis.join("|") : null)) },
};

export const DEFAULT_SELECT: Record<QueryScope, string[]> = {
  frame: ["frame_number", "time_ms", "ip_src", "ip_dst", "tcp_len", "tcp_flags", "analysis"],
  conversation: [
    "conversation_id",
    "transport",
    "initiator_ip",
    "initiator_port",
    "responder_ip",
    "responder_port",
    "duration_ms",
    "bytes_total",
    "retransmission_count",
    "direction_basis",
  ],
  event: ["event_id", "conversation_id", "type", "time_ms", "frame_number"],
};

export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 200;

/** 校验查询；不合法时抛 QueryValidationError，错误信息包含允许的字段/操作列表 */
export function validateQuery(q: TrafficQuery): void {
  const table =
    q.scope === "conversation" ? CONVERSATION_FIELDS : q.scope === "event" ? EVENT_FIELDS : FRAME_FIELDS;
  const scopeName = q.scope;
  const allowed = Object.keys(table).join(", ");

  if (q.scope !== "conversation" && q.scope !== "event" && q.scope !== "frame") {
    throw new QueryValidationError(`scope must be "conversation", "event" or "frame"`);
  }

  const seen = new Set<string>();
  const typeValues = new Set<string>();
  for (const cond of q.where ?? []) {
    if (cond.field === "type" && (cond.op === "eq" || cond.op === "in")) {
      for (const v of Array.isArray(cond.value) ? cond.value : [cond.value]) {
        typeValues.add(String(v));
      }
    }
    if (!VALID_OPS.has(cond.op)) {
      throw new QueryValidationError(
        `unknown op '${cond.op}'. Allowed: eq, ne, gt, gte, lt, lte, in, contains (no LIKE/regex)`,
      );
    }
    const spec = table[cond.field];
    if (!spec) {
      throw new QueryValidationError(
        `unknown field '${cond.field}' for scope '${scopeName}'. Allowed: ${allowed}`,
      );
    }
    if (seen.has(cond.field + cond.op)) {
      throw new QueryValidationError(`duplicate condition on '${cond.field}' (${cond.op})`);
    }
    seen.add(cond.field + cond.op);

    const numericOps: CompareOp[] = ["gt", "gte", "lt", "lte"];
    if (numericOps.includes(cond.op) && spec.type !== "number") {
      throw new QueryValidationError(`op '${cond.op}' requires a numeric field, '${cond.field}' is ${spec.type}`);
    }
    if (cond.op === "in") {
      if (!Array.isArray(cond.value)) {
        throw new QueryValidationError(`op 'in' requires an array value for '${cond.field}'`);
      }
    } else if (Array.isArray(cond.value)) {
      throw new QueryValidationError(`array value only allowed with op 'in' ('${cond.field}')`);
    }
    if (cond.op === "contains") {
      if (spec.type !== "string[]" && spec.type !== "string") {
        throw new QueryValidationError(`op 'contains' requires string or string[] field ('${cond.field}')`);
      }
    }
    if (spec.type === "number" && typeof cond.value === "string" && cond.op !== "contains") {
      throw new QueryValidationError(`field '${cond.field}' is numeric; value must be a number`);
    }
  }

  // 枚举值校验（v0.3.1）：拼错的 type/transport 立即报错而非静默空集
  if (q.scope === "event" && typeValues.size > 0) {
    const validTypes = Object.keys(EVENT_REGISTRY);
    const bogus = [...typeValues].filter((t) => !validTypes.includes(t));
    if (bogus.length > 0) {
      throw new QueryValidationError(
        `unknown event type(s): ${bogus.join(", ")}. Valid types: ${validTypes.join(", ")}`,
      );
    }
  }
  for (const cond of q.where ?? []) {
    if (cond.field === "transport" && cond.op === "eq") {
      const v = String(cond.value);
      if (v !== "tcp" && v !== "udp") {
        throw new QueryValidationError(`transport must be "tcp" or "udp", got '${v}'`);
      }
    }
  }

  // attr.* 字段要求 where 中给出兼容的 type 条件（事件 attributes 按类型校验）
  if (q.scope === "event") {
    const attrUses = [
      ...(q.where ?? []).map((c) => c.field),
      ...(q.select ?? []),
      ...(q.order_by ?? []).map((o) => o.field),
    ].filter((f) => f.startsWith("attr."));
    for (const f of attrUses) {
      const name = f.slice(5);
      const spec = EVENT_ATTR_FIELDS[name];
      if (!spec) {
        throw new QueryValidationError(`unknown attribute field '${f}'`);
      }
      if (typeValues.size === 0) {
        throw new QueryValidationError(
          `'${f}' requires a type condition, e.g. where: [{field:"type",op:"eq",value:"dns_response"}]`,
        );
      }
      const incompatible = [...typeValues].filter((t) => !spec.compatibleTypes.includes(t as never));
      if (incompatible.length > 0) {
        throw new QueryValidationError(
          `'${f}' is not an attribute of type ${incompatible.join(", ")}; it applies to: ${spec.compatibleTypes.join(", ")}`,
        );
      }
    }
  }

  for (const sel of q.select ?? []) {
    if (!table[sel]) {
      throw new QueryValidationError(
        `unknown select field '${sel}' for scope '${scopeName}'. Allowed: ${allowed}`,
      );
    }
  }

  for (const ob of q.order_by ?? []) {
    if (!table[ob.field]) {
      throw new QueryValidationError(
        `unknown order_by field '${ob.field}' for scope '${scopeName}'. Allowed: ${allowed}`,
      );
    }
    if (ob.direction !== "asc" && ob.direction !== "desc") {
      throw new QueryValidationError(`order_by.direction must be "asc" or "desc"`);
    }
  }

  if (q.limit !== undefined && (!Number.isInteger(q.limit) || q.limit < 1 || q.limit > MAX_LIMIT)) {
    throw new QueryValidationError(`limit must be an integer in [1, ${MAX_LIMIT}]`);
  }
  if (q.offset !== undefined && (!Number.isInteger(q.offset) || q.offset < 0)) {
    throw new QueryValidationError(`offset must be a non-negative integer`);
  }
}
