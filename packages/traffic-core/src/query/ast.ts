import type { Conversation, TrafficEvent } from "../types.js";
import { EVENT_ATTR_FIELDS } from "../events/registry.js";

/** v0.1 查询 DSL：Filter + Projection + Ordering + Limit，条件之间只支持 AND。 */

export type QueryScope = "conversation" | "event";

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
  /** 从 IR 对象取值的投影函数 */
  project: (obj: Conversation | TrafficEvent) => unknown;
}

const conv = (f: (c: Conversation) => unknown): FieldSpec["project"] => (o) =>
  f(o as Conversation);
const evt = (f: (e: TrafficEvent) => unknown): FieldSpec["project"] => (o) =>
  f(o as TrafficEvent);

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
export const DEFAULT_SELECT: Record<QueryScope, string[]> = {
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
  const table = q.scope === "conversation" ? CONVERSATION_FIELDS : EVENT_FIELDS;
  const scopeName = q.scope === "conversation" ? "conversation" : "event";
  const allowed = Object.keys(table).join(", ");

  if (q.scope !== "conversation" && q.scope !== "event") {
    throw new QueryValidationError(`scope must be "conversation" or "event"`);
  }

  const seen = new Set<string>();
  const typeValues = new Set<string>();
  for (const cond of q.where ?? []) {
    if (cond.field === "type" && (cond.op === "eq" || cond.op === "in")) {
      for (const v of Array.isArray(cond.value) ? cond.value : [cond.value]) {
        typeValues.add(String(v));
      }
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
