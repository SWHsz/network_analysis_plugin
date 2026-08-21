/**
 * M1 正确率判分（RFC-002 §6.1，确定性）。
 *
 * 口径：
 *   scalar_number : |ans - gold| <= max(tolerance_abs ?? 0, |tolerance_rel * gold|)
 *                   （abs/rel 同时声明时取更宽者；都未声明 = 零容差，切片边界判断 #7）
 *   scalar_enum   : 规范化（trim + 小写）后精确比对
 *   scalar_string : 同上
 *   set(unordered): 规范化元素键集合相等
 *   set(ordered)  : 键序列完全一致
 *   set(top_k_prefix): pass = 前缀与 gold 集合完全重合；partial = |prefix∩gold|/k
 *                   落盘供部分分分析，名次错误单独记录不计入 M1
 *   record        : 逐字段递归按上述规则
 *   题目正确      = 全字段对（主指标，备忘录 §7-M1）
 *
 * 字段 kind 的判定：优先 answer_schema 的 x-kind；缺省时从 gold 值类型推断
 * （number→数值容差、boolean/string→规范化精确、array→set）。
 */
import { canonicalElementKey } from "./elements.js";
import type { JsonSchema } from "./schema.js";
import type { Question } from "./question.js";

export interface FieldScore {
  path: string;
  kind: string;
  pass: boolean;
  /** 仅 set(top_k_prefix)：|prefix∩gold|/k */
  partial?: number;
  /** 仅 set(top_k_prefix)：与 gold 名次不一致的前缀位置数 */
  rankErrors?: number;
  detail?: string;
}

export interface CorrectnessResult {
  fields: FieldScore[];
  /** 主指标：全字段对 */
  correct: boolean;
}

function normalizeScalar(v: unknown): unknown {
  return typeof v === "string" ? v.trim().toLowerCase() : v;
}

interface Leaf {
  path: string;
  kind: string;
  setMode: string;
}

/**
 * 收集待判分的事实字段。约定（与现有题库一致）：
 * - 顶层属性即事实字段，其 subschema 是 {value, evidence} 包装节点；
 * - 仅当属性显式标 x-kind:"record" 时才递归（点路径对应 gold 键）；
 * - 属性未标 x-kind 时：set 题取根 schema 的 x-match；其余按题目 type，
 *   record 题的标量口径由 gold 值类型推断（number→容差比对，否则规范化精确）。
 */
function collectLeaves(q: Question): Leaf[] {
  const props = q.answer_schema.properties ?? {};
  const rootSetMode = String(q.answer_schema["x-match"] ?? "unordered");
  const leaves: Leaf[] = [];
  const pushScalarInferred = (path: string): void => {
    const gv = q.gold[path]?.value;
    leaves.push({ path, kind: typeof gv === "number" ? "scalar_number" : "scalar_enum", setMode: "unordered" });
  };
  const walk = (props: Record<string, JsonSchema>, prefix: string, defaultKind: string): void => {
    for (const [name, sub] of Object.entries(props)) {
      const path = prefix === "" ? name : `${prefix}.${name}`;
      const kind = sub?.["x-kind"];
      if (kind === "record") {
        walk(sub?.properties ?? {}, path, "scalar_number");
        continue;
      }
      if (kind === "set") {
        leaves.push({ path, kind: "set", setMode: String(sub?.["x-match"] ?? rootSetMode) });
        continue;
      }
      if (kind) {
        leaves.push({ path, kind, setMode: "unordered" });
        continue;
      }
      if (defaultKind === "set") {
        leaves.push({ path, kind: "set", setMode: rootSetMode });
      } else if (defaultKind === "record") {
        pushScalarInferred(path);
      } else {
        leaves.push({ path, kind: defaultKind, setMode: "unordered" });
      }
    }
  };
  walk(props, "", q.type);
  return leaves;
}

function scoreScalar(path: string, kind: string, goldValue: unknown, goldNode: { tolerance_abs?: number; tolerance_rel?: number }, ansNode: unknown, out: FieldScore): void {
  const node = ansNode as { value?: unknown } | null | undefined;
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    out.pass = false;
    out.detail = "答案节点不是 {value, evidence} 对象";
    return;
  }
  const a = node.value;
  if (kind === "scalar_number" && typeof goldValue === "number") {
    if (typeof a !== "number") {
      out.pass = false;
      out.detail = `value 应为 number，实际 ${typeof a}`;
      return;
    }
    const tolAbs = typeof goldNode.tolerance_abs === "number" ? goldNode.tolerance_abs : 0;
    const tolRel = typeof goldNode.tolerance_rel === "number" ? Math.abs(goldNode.tolerance_rel * goldValue) : 0;
    const tol = Math.max(tolAbs, tolRel);
    out.pass = Math.abs(a - goldValue) <= tol;
    if (!out.pass) out.detail = `|${a} - ${goldValue}| > tol ${tol}`;
    return;
  }
  // scalar_enum / scalar_string：规范化后精确
  out.pass = normalizeScalar(a) === normalizeScalar(goldValue);
  if (!out.pass) out.detail = `${JSON.stringify(a)} != gold ${JSON.stringify(goldValue)}`;
}

export function scoreCorrectness(q: Question, answer: Record<string, unknown>): CorrectnessResult {
  const fields: FieldScore[] = [];
  for (const leaf of collectLeaves(q)) {
    const goldNode = q.gold[leaf.path];
    const out: FieldScore = { path: leaf.path, kind: leaf.kind, pass: false };
    if (!goldNode) {
      out.detail = "gold 缺该字段（题目缺陷）";
      fields.push(out);
      continue;
    }
    if (leaf.kind === "set") {
      scoreSetField(leaf, goldNode.value, answer[leaf.path], out);
    } else {
      scoreScalar(leaf.path, leaf.kind, goldNode.value, goldNode, answer[leaf.path], out);
    }
    fields.push(out);
  }
  return { fields, correct: fields.length > 0 && fields.every((f) => f.pass) };
}

function scoreSetField(leaf: Leaf, goldValue: unknown, ansValue: unknown, out: FieldScore): void {
  if (!Array.isArray(goldValue)) {
    out.detail = "gold 值应为数组（题目缺陷）";
    return;
  }
  if (!Array.isArray(ansValue)) {
    out.detail = "答案应为数组";
    return;
  }
  const goldKeys = goldValue.map(canonicalElementKey);
  const ansKeys = ansValue.map((el) => canonicalElementKey((el as { value?: unknown })?.value));
  switch (leaf.setMode) {
    case "ordered": {
      out.pass = JSON.stringify(ansKeys) === JSON.stringify(goldKeys);
      if (!out.pass) out.detail = `有序序列不一致：[${ansKeys}] != [${goldKeys}]`;
      return;
    }
    case "top_k_prefix": {
      const k = goldKeys.length;
      const prefix = ansKeys.slice(0, k);
      const goldSet = new Set(goldKeys);
      let overlap = 0;
      for (const key of new Set(prefix)) if (goldSet.has(key)) overlap++;
      out.partial = overlap / k;
      out.rankErrors = prefix.filter((key, i) => key !== goldKeys[i]).length;
      out.pass = overlap === k && ansKeys.length === k;
      if (!out.pass) {
        out.detail = `前缀重合 ${overlap}/${k}${ansKeys.length !== k ? `（元素数 ${ansKeys.length} != k=${k}）` : ""}，名次错位 ${out.rankErrors}`;
      }
      return;
    }
    case "unordered":
    default: {
      const a = [...ansKeys].sort();
      const g = [...goldKeys].sort();
      out.pass = JSON.stringify(a) === JSON.stringify(g);
      if (!out.pass) out.detail = `集合不一致：[${a}] != [${g}]`;
      return;
    }
  }
}
