import type { BoundedResult, Conversation, TrafficEvent } from "../types.js";
import {
  CONVERSATION_FIELDS,
  DEFAULT_LIMIT,
  DEFAULT_SELECT,
  EVENT_FIELDS,
  FRAME_FIELDS,
  STREAM_FIELDS,
  validateQuery,
  type Condition,
  type FieldSpec,
  type QueryRow,
  type TrafficQuery,
} from "./ast.js";
import type { FrameRecord } from "../frames.js";
import type { QuicStreamSummary } from "../types.js";

/** 执行查询：内存过滤（AND）→ 稳定排序 → 分页 → 投影，输出有界信封 */
export function executeQuery(
  query: TrafficQuery,
  conversations: Conversation[],
  events: TrafficEvent[],
  frames?: FrameRecord[],
): BoundedResult<Record<string, unknown>> {
  validateQuery(query);
  const table =
    query.scope === "conversation"
      ? CONVERSATION_FIELDS
      : query.scope === "event"
        ? EVENT_FIELDS
        : query.scope === "frame"
          ? FRAME_FIELDS
          : STREAM_FIELDS;
  if (query.scope === "frame" && !frames) {
    throw new Error("frame scope requires the frames table");
  }
  const streamRows: QuicStreamSummary[] = conversations.flatMap((c) => c.streams ?? []);
  const source: QueryRow[] =
    query.scope === "conversation"
      ? conversations
      : query.scope === "event"
        ? events
        : query.scope === "stream"
          ? streamRows
          : frames!;

  const filtered = source.filter((obj) => (query.where ?? []).every((c) => match(obj, c, table)));

  const orderings = query.order_by ?? [];
  const sorted = [...filtered].sort((a, b) => {
    for (const ob of orderings) {
      const va = table[ob.field]!.project(a);
      const vb = table[ob.field]!.project(b);
      const cmp = compareValues(va, vb);
      if (cmp !== 0) return ob.direction === "desc" ? -cmp : cmp;
    }
    return 0; // Array.prototype.sort 稳定，保留原始时间序
  });

  const total = sorted.length;
  const offset = query.offset ?? 0;
  const limit = query.limit ?? DEFAULT_LIMIT;
  const page = sorted.slice(offset, offset + limit);

  // 紧凑默认投影（Context Shaper v2）：未显式 select 时输出收敛的列集
  const select =
    query.select && query.select.length > 0 ? query.select : DEFAULT_SELECT[query.scope];
  const items = page.map((obj) => {
    const row: Record<string, unknown> = {};
    for (const f of select) row[f] = table[f]!.project(obj);
    return row;
  });

  return {
    returned: items.length,
    total,
    offset,
    truncated: offset + items.length < total,
    items,
  };
}

function match(
  obj: QueryRow,
  cond: Condition,
  table: Record<string, FieldSpec>,
): boolean {
  const spec = table[cond.field]!;
  const actual = spec.project(obj);
  const value = cond.value;

  if (cond.op === "contains") {
    if (Array.isArray(actual)) return actual.some((v) => String(v) === String(value));
    return String(actual ?? "").includes(String(value));
  }
  if (actual === null || actual === undefined) {
    // null 只与 ne / in（不含该值）匹配，数值比较一律为假
    return cond.op === "ne" || (cond.op === "in" && Array.isArray(value) && !value.includes(actual as never));
  }
  if (cond.op === "in") {
    if (!Array.isArray(value)) return false;
    return value.some((v) => looselyEquals(actual, v));
  }
  switch (cond.op) {
    case "eq":
      return looselyEquals(actual, value);
    case "ne":
      return !looselyEquals(actual, value);
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const a = Number(actual);
      const b = Number(value);
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      if (cond.op === "gt") return a > b;
      if (cond.op === "gte") return a >= b;
      if (cond.op === "lt") return a < b;
      return a <= b;
    }
  }
  void spec;
  return false;
}

function looselyEquals(actual: unknown, value: unknown): boolean {
  if (typeof actual === "number" || typeof value === "number") {
    return Number(actual) === Number(value);
  }
  return String(actual) === String(value);
}

/** null 排在最后；数字与字符串分别比较 */
function compareValues(a: unknown, b: unknown): number {
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1;
  if (b === null || b === undefined) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
}
