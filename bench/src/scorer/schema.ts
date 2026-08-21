/**
 * answer_schema 校验（RFC-002 §2.1 类型系统的 JSON Schema 子集）。
 *
 * 语义与 bench/src/schema/question-schema.mjs（Prompt 2 验收版）保持一致：
 * 该 .mjs 是题目信封校验的冻结产物；本文件是判分侧的正典实现，
 * 新增 tolerance_rel / set(ordered) / top_k_prefix 等 §6.1 完整口径。
 * 支持关键字：type/properties/required/additionalProperties/items/minItems/
 * maxItems/uniqueItems/enum/minimum/maximum/$ref(仅 #/$defs/...)；x-* 携带判分语义。
 */

export type JsonSchema = {
  $schema?: string;
  $defs?: Record<string, JsonSchema>;
  $ref?: string;
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean;
  items?: JsonSchema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  "x-kind"?: string;
  "x-match"?: string;
  "x-element-key"?: string;
};

const REF_PREFIX = "#/$defs/";

/** 仅支持局部引用 #/$defs/<name>；返回目标子 schema 或 undefined */
export function refTarget(root: JsonSchema, ref: unknown): JsonSchema | undefined {
  if (typeof ref !== "string" || !ref.startsWith(REF_PREFIX)) return undefined;
  const name = ref.slice(REF_PREFIX.length);
  if (name.includes("/")) return undefined;
  return root.$defs?.[name];
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return (
      deepEqual(ka, kb) &&
      ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
    );
  }
  return false;
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function typeMatches(expected: string, v: unknown): boolean {
  switch (expected) {
    case "object": return v !== null && typeof v === "object" && !Array.isArray(v);
    case "array": return Array.isArray(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "number": return typeof v === "number";
    case "string": return typeof v === "string";
    case "boolean": return typeof v === "boolean";
    case "null": return v === null;
    default: return false;
  }
}

const KEYWORDS = new Set([
  "$schema", "$defs", "$ref", "type", "properties", "required", "additionalProperties",
  "items", "minItems", "maxItems", "uniqueItems", "enum", "minimum", "maximum",
  "x-kind", "x-match", "x-element-key",
]);

/** 校验 schema 本身只使用本子集认识的关键字（防 answer_schema 出现校验器不认的写法被静默跳过） */
export function validateSchemaStructure(schema: unknown, where = "answer_schema"): string[] {
  const errs: string[] = [];
  walk(schema, where);
  return errs;

  function walk(node: unknown, p: string): void {
    if (typeof node !== "object" || node === null) return;
    for (const k of Object.keys(node)) {
      if (!KEYWORDS.has(k)) errs.push(`${p}: 不支持的关键字 "${k}"`);
    }
    const s = node as JsonSchema;
    if (s.$ref !== undefined && refTarget(schema as JsonSchema, s.$ref) === undefined && typeof s.$ref === "string") {
      errs.push(`${p}.$ref: 仅支持局部引用 #/$defs/<name>`);
      return;
    }
    if (s.properties) for (const [name, sub] of Object.entries(s.properties)) walk(sub, `${p}.properties.${name}`);
    if (s.items) walk(s.items, `${p}.items`);
    if (s.$defs) for (const [name, sub] of Object.entries(s.$defs)) walk(sub, `${p}.$defs.${name}`);
  }
}

/** 用 answer_schema 校验一个值（终答/gold 合成/canary 答案），返回错误信息数组 */
export function validateSchema(schema: JsonSchema, value: unknown, pathStr = "$"): string[] {
  const errs: string[] = [];
  visit(schema, value, pathStr);
  return errs;

  function visit(s: JsonSchema | undefined, v: unknown, p: string): void {
    if (s === undefined) return;
    if (s.$ref !== undefined) {
      const target = refTarget(schema, s.$ref);
      if (!target) {
        errs.push(`${p}: $ref 目标不存在（${s.$ref}）`);
        return;
      }
      visit(target, v, p);
      return;
    }
    if (s.enum !== undefined) {
      if (!s.enum.some((e) => deepEqual(e, v))) {
        errs.push(`${p}: 值 ${JSON.stringify(v)} 不在 enum ${JSON.stringify(s.enum)} 内`);
      }
      return;
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some((t) => typeMatches(t, v))) {
        errs.push(`${p}: 期望类型 ${types.join("|")}，实际 ${typeName(v)}`);
        return;
      }
    }
    if (typeMatches("object", v) && (s.properties || s.required)) {
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj);
      for (const r of s.required ?? []) {
        if (!keys.includes(r)) errs.push(`${p}: 缺必填属性 "${r}"`);
      }
      for (const [name, sub] of Object.entries(s.properties ?? {})) {
        if (keys.includes(name)) visit(sub, obj[name], `${p}.${name}`);
      }
      if (s.additionalProperties === false) {
        const allowed = new Set(Object.keys(s.properties ?? {}));
        for (const k of keys) {
          if (!allowed.has(k)) errs.push(`${p}: 多余属性 "${k}"（additionalProperties:false）`);
        }
      }
    }
    if (Array.isArray(v) && s.items !== undefined) {
      if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${p}: 元素数 ${v.length} < minItems ${s.minItems}`);
      if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(`${p}: 元素数 ${v.length} > maxItems ${s.maxItems}`);
      if (s.uniqueItems === true) {
        const seen = new Set<string>();
        for (const item of v) {
          const key = JSON.stringify(item);
          if (seen.has(key)) errs.push(`${p}: 元素重复 ${key}`);
          seen.add(key);
        }
      }
      v.forEach((item, i) => visit(s.items, item, `${p}[${i}]`));
    }
    if (typeof v === "number") {
      if (s.minimum !== undefined && v < s.minimum) errs.push(`${p}: ${v} < minimum ${s.minimum}`);
      if (s.maximum !== undefined && v > s.maximum) errs.push(`${p}: ${v} > maximum ${s.maximum}`);
    }
  }
}
