/**
 * 集合元素的规范化键（RFC-002 §3 x-element-key）。
 * 会话五元组 → "{proto}|{src}:{sport}>{dst}:{dport}"（与题库 gold_evidence 键一致，
 * 臂间公平、不依赖 tshark stream 号）；其余值退化为键序稳定的 JSON 串。
 */

export interface SessionTuple {
  proto: string;
  src: string;
  sport: number;
  dst: string;
  dport: number;
}

export function isSessionTuple(v: unknown): v is SessionTuple {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const t = v as Record<string, unknown>;
  return (
    typeof t.proto === "string" &&
    typeof t.src === "string" &&
    typeof t.sport === "number" &&
    typeof t.dst === "string" &&
    typeof t.dport === "number"
  );
}

export function canonicalTupleKey(t: SessionTuple): string {
  return `${t.proto}|${t.src}:${t.sport}>${t.dst}:${t.dport}`;
}

/** 键序稳定的 JSON 序列化（对象键排序后拼接，保证同构对象同键） */
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? String(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

export function canonicalElementKey(v: unknown): string {
  if (isSessionTuple(v)) return canonicalTupleKey(v);
  return stableStringify(v);
}
