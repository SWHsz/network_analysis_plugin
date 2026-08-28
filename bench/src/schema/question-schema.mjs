// RFC-002 §3 题库 schema：信封校验 + JSON Schema 子集校验器 + 确定性 mini 判分器。
// 用途：垂直切片期的题目/金丝雀自校验（canary 元评测，RFC-002 §6.3）。
// 零依赖：仅 node:* 内置模块。
//
// 注：Prompt 3 之后判分正典实现移至 bench/src/scorer/（TS，含 set(ordered)/
// top_k_prefix/tolerance_rel/等价帧细分/M4 支持）；本文件的信封校验仍是出题期入口。
//
// 判分口径（与 RFC-002 §6.1/§6.2、备忘录 §7 对齐）：
//   scalar_number : |ans - gold| <= tolerance_abs ?? 0
//   scalar_enum   : 精确比对（字符串大小写规范化）
//   set(unordered): 规范化元素键集合相等
//   record        : 逐字段按上述规则
//   证据有效支撑  : precision === 1 且 recall > 0（对 gold_evidence 帧集）

import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export const ANSWER_FORMS = ["scalar_number", "scalar_enum", "scalar_string", "set", "record"];
export const IR_COVERAGE = ["covered", "raw_query_only", "uncovered"];
export const PROVENANCE_SOURCES = ["generator", "llm_draft+human_review", "human"];
export const ERROR_FORMS = ["wrong_value", "wrong_evidence_frame", "format_error"];
export const SKILL_AXES = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"];
export const SET_MATCH_MODES = ["unordered", "ordered", "top_k_prefix"];
export const CORPUS_LAYERS = ["L1", "L2", "L3"];
export const ANSWER_TOOLS = new Set([
  "traffic_open", "traffic_overview", "traffic_query", "traffic_inspect",
  "traffic_evidence", "traffic_timeseries", "traffic_raw_query", "traffic_http_timeline",
  "traffic_sql", "traffic_schema", "（组答）",
]);

// ---------- JSON Schema 子集 ----------
// 支持：type/properties/required/additionalProperties/items/minItems/maxItems/
//       uniqueItems/enum/minimum/maximum/$ref(仅 #/$defs/...)；x-* 为携带判分语义的扩展关键字。
const VALUE_KEYWORDS = new Set([
  "$schema", "$defs", "$ref", "type", "properties", "required", "additionalProperties",
  "items", "minItems", "maxItems", "uniqueItems", "enum", "minimum", "maximum",
  "x-kind", "x-match", "x-element-key",
]);

function typeName(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function typeMatches(expected, v) {
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

function deepEqual(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return deepEqual(ka, kb) && ka.every(k => deepEqual(a[k], b[k]));
  }
  return false;
}

/** 校验 schema 本身只使用本子集认识的关键字（防 answer_schema 里出现校验器不认的写法被静默跳过） */
export function validateSchemaStructure(schema, where = "answer_schema") {
  const errs = [];
  walk(schema);
  return errs;

  function walk(node, p) {
    if (typeof node !== "object" || node === null) return;
    for (const k of Object.keys(node)) {
      if (!VALUE_KEYWORDS.has(k)) errs.push(`${p}: 不支持的关键字 "${k}"`);
    }
    if (node.$ref !== undefined) {
      if (typeof node.$ref !== "string" || !/^#\/\$defs\/[^/]+$/.test(node.$ref)) {
        errs.push(`${p}.$ref: 仅支持局部引用 #/$defs/<name>`);
      }
      return;
    }
    if (node.properties) {
      for (const [name, sub] of Object.entries(node.properties)) walk(sub, `${p}.properties.${name}`);
    }
    if (node.items) walk(node.items, `${p}.items`);
    if (node.$defs) {
      for (const [name, sub] of Object.entries(node.$defs)) walk(sub, `${p}.$defs.${name}`);
    }
  }
}

/** 用 answer_schema 校验一个值（如终答/gold 合成/金丝雀答案），返回错误信息数组 */
export function validateSchema(schema, value, pathStr = "$", root = null) {
  const errs = [];
  if (root === null) root = schema;
  visit(schema, value, pathStr);
  return errs;

  function visit(s, v, p) {
    if (s === undefined || s === false) {
      if (s === false) errs.push(`${p}: schema 为 false，任何值都不匹配`);
      return;
    }
    if (typeof s === "boolean") return;
    if (s.$ref !== undefined) {
      const m = /^#\/\$defs\/(.+)$/.exec(s.$ref);
      const target = m && root.$defs ? root.$defs[m[1]] : undefined;
      if (!target) {
        errs.push(`${p}: $ref 目标不存在（${s.$ref}）`);
        return;
      }
      visit(target, v, p);
      return;
    }
    if (s.enum !== undefined) {
      if (!s.enum.some(e => deepEqual(e, v))) {
        errs.push(`${p}: 值 ${JSON.stringify(v)} 不在 enum ${JSON.stringify(s.enum)} 内`);
      }
      return;
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some(t => typeMatches(t, v))) {
        errs.push(`${p}: 期望类型 ${types.join("|")}，实际 ${typeName(v)}`);
        return;
      }
    }
    if (typeMatches("object", v) && (s.properties || s.required)) {
      const keys = Object.keys(v);
      for (const r of s.required || []) {
        if (!keys.includes(r)) errs.push(`${p}: 缺必填属性 "${r}"`);
      }
      for (const [name, sub] of Object.entries(s.properties || {})) {
        if (keys.includes(name)) visit(sub, v[name], `${p}.${name}`);
      }
      if (s.additionalProperties === false) {
        const allowed = new Set(Object.keys(s.properties || {}));
        for (const k of keys) {
          if (!allowed.has(k)) errs.push(`${p}: 多余属性 "${k}"（additionalProperties:false）`);
        }
      }
    }
    if (Array.isArray(v) && s.items !== undefined) {
      if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${p}: 元素数 ${v.length} < minItems ${s.minItems}`);
      if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(`${p}: 元素数 ${v.length} > maxItems ${s.maxItems}`);
      if (s.uniqueItems === true) {
        const seen = new Set();
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

// ---------- 判分 ----------

/** 规范化五元组键：{proto}|{src}:{sport}>{dst}:{dport}（与 set 题 x-element-key 一致） */
export function canonicalTupleKey(t) {
  return `${t.proto}|${t.src}:${t.sport}>${t.dst}:${t.dport}`;
}

function normalizeScalar(v) {
  return typeof v === "string" ? v.toLowerCase() : v;
}

function evidencePR(cited, gold) {
  // 空集/不可知 gold（备忘录 §7-M3 注册定义，2026-08-21 锁定）：诚实空引用=有效支撑
  if (gold.length === 0) {
    return { precision: cited.length === 0 ? 1 : 0, recall: 1, pass: cited.length === 0 };
  }
  const c = new Set(cited);
  const g = new Set(gold);
  let inter = 0;
  for (const f of c) if (g.has(f)) inter++;
  const precision = c.size === 0 ? 0 : inter / c.size;
  const recall = inter / g.size;
  return { precision, recall, pass: precision === 1 && recall > 0 };
}

function setFieldOf(question) {
  const fields = Object.keys(question.answer_schema.properties);
  if (fields.length !== 1) {
    throw new Error(`${question.question_id}: set 题应有且只有一个答案字段，实际 ${fields.length}`);
  }
  return fields[0];
}

export function scoreCorrectness(question, answer) {
  const results = {};
  if (question.type === "set") {
    const f = setFieldOf(question);
    const mode = (question.answer_schema && question.answer_schema["x-match"]) || "unordered";
    const goldKeys = question.gold[f].value.map(canonicalTupleKey);
    const ansNodes = answer ? answer[f] : undefined;
    if (!Array.isArray(ansNodes)) { results[f] = false; return results; }
    const ansKeys = ansNodes.map(n => canonicalTupleKey(n ? n.value : null));
    if (mode === "ordered") {
      // 有序：序列完全一致（工程化期补齐，原切片版仅实现 unordered）
      results[f] = JSON.stringify(ansKeys) === JSON.stringify(goldKeys);
      return results;
    }
    if (mode === "top_k_prefix") {
      // 前缀重合：全中且数量恰为 k 才算对（部分分由证据层落盘供分析）
      const k = goldKeys.length;
      const prefix = ansKeys.slice(0, k);
      const goldSet = new Set(goldKeys);
      let overlap = 0;
      for (const key of new Set(prefix)) if (goldSet.has(key)) overlap++;
      results[f] = overlap === k && ansKeys.length === k;
      return results;
    }
    // unordered（默认）：集合相等
    results[f] = JSON.stringify([...ansKeys].sort()) === JSON.stringify([...goldKeys].sort());
    return results;
  }
  for (const [field, g] of Object.entries(question.gold)) {
    const a = answer[field];
    if (a === null || typeof a !== "object" || Array.isArray(a)) { results[field] = false; continue; }
    if (typeof g.value === "number") {
      const tolAbs = typeof g.tolerance_abs === "number" ? g.tolerance_abs : 0;
      const tolRel = typeof g.tolerance_rel === "number" ? Math.abs(g.tolerance_rel * g.value) : 0;
      const tol = Math.max(tolAbs, tolRel);
      results[field] = typeof a.value === "number" && Math.abs(a.value - g.value) <= tol;
    } else {
      // 对象值（如五元组）走 deepEqual；字符串规范化后精确
      results[field] = deepEqual(normalizeScalar(a.value), normalizeScalar(g.value));
    }
  }
  return results;
}

export function scoreEvidence(question, answer) {
  const out = {};
  if (question.type === "set") {
    const f = setFieldOf(question);
    const perElement = {};
    for (const node of answer[f]) {
      const key = canonicalTupleKey(node.value);
      const goldFrames = question.gold_evidence[f][key];
      perElement[key] = goldFrames ? evidencePR(node.evidence, goldFrames) : { precision: 0, recall: 0, pass: false, in_gold: false };
    }
    out[f] = { per_element: perElement, pass: Object.values(perElement).every(e => e.pass) };
    return out;
  }
  for (const [field, goldFrames] of Object.entries(question.gold_evidence)) {
    const a = answer[field];
    out[field] = a && Array.isArray(a.evidence) ? evidencePR(a.evidence, goldFrames) : { precision: 0, recall: 0, pass: false };
  }
  return out;
}

/** 完整判分一个答案（schema → 正确率 → 证据），返回与 canary.expect 同形的裁决 */
export function scoreAnswer(question, answer) {
  const schemaErrors = validateSchema(question.answer_schema, answer);
  if (schemaErrors.length > 0) {
    return { schema_valid: false, schema_errors: schemaErrors, correctness: false, evidence_pass: false };
  }
  const correctnessFields = scoreCorrectness(question, answer);
  const evidence = scoreEvidence(question, answer);
  return {
    schema_valid: true,
    schema_errors: [],
    correctness: Object.values(correctnessFields).every(Boolean),
    correctness_fields: correctnessFields,
    evidence,
    evidence_pass: Object.values(evidence).map(f => f.pass).every(Boolean),
  };
}

/** 把 gold + gold_evidence 合成为形如终答的对象，用于 schema 校验 gold 结构 */
/** 键序稳定的 JSON 序列化（与 bench/src/scorer/elements.ts 的 stableStringify 同构） */
function stableStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? String(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(",")}}`;
}

export function canonicalElementKey(v) {
  if (typeof v === "object" && v !== null && !Array.isArray(v) &&
      typeof v.proto === "string" && typeof v.src === "string" && typeof v.sport === "number" &&
      typeof v.dst === "string" && typeof v.dport === "number") {
    return canonicalTupleKey(v);
  }
  return stableStringify(v);
}

export function buildGoldAsAnswer(question) {
  if (question.type === "set") {
    const f = setFieldOf(question);
    const evMap = question.gold_evidence[f];
    return { [f]: question.gold[f].value.map(v => ({ value: v, evidence: evMap[canonicalTupleKey(v)] })) };
  }
  const out = {};
  for (const [field, node] of Object.entries(question.gold)) {
    const ev = question.gold_evidence[field];
    // 实例题扩展（S3 桥接）：元素粒度证据表 → 按元素键组配 {value, evidence} 元组链
    if (ev !== null && typeof ev === "object" && !Array.isArray(ev) && Array.isArray(node.value)) {
      out[field] = node.value.map(v => ({ value: v, evidence: ev[canonicalElementKey(v)] ?? [] }));
    } else {
      out[field] = { value: node.value, evidence: ev };
    }
  }
  return out;
}

// ---------- 题目信封校验 ----------

function checkExpectShape(expect, where, add, { requireAllTrue }) {
  const keys = ["schema_valid", "correctness", "evidence_pass"];
  for (const k of keys) {
    if (typeof expect[k] !== "boolean") add(`${where}.expect.${k}: 应为 boolean`);
  }
  const extra = Object.keys(expect).filter(k => !keys.includes(k));
  if (extra.length > 0) add(`${where}.expect: 多余键 ${extra.join(",")}`);
  if (requireAllTrue && keys.every(k => expect[k] === true) === false) {
    add(`${where}.expect: known_good 必须全为 true`);
  }
}

export function validateEnvelope(q, gt) {
  const errs = [];
  const id = q.question_id ?? "<无 question_id>";
  const push = (msg) => errs.push(`[${id}] ${msg}`);

  for (const k of ["question_id", "version", "capture", "type", "question", "answer_schema", "gold", "gold_evidence", "gold_derivation", "reference_solution", "tags", "provenance", "canary"]) {
    if (!(k in q)) push(`缺顶层字段 "${k}"`);
  }
  if (errs.length > 0) return errs; // 连 question_id 都可能没有，后续检查无意义

  if (typeof q.question_id !== "string" ||
      !(/^q-[a-z0-9]+-\d+$/.test(q.question_id) || /^q-[a-z0-9]+-i\d+-r\d+$/.test(q.question_id))) {
    push("question_id 命名应为 q-<fixture>-<序号> 或实例命名 q-<card>-i<seed>-r<tier>");
  }
  if (!Number.isInteger(q.version) || q.version < 1) push("version 应为 >=1 的整数");
  if (typeof q.question !== "string" || q.question.length < 10) push("question 题面过短");

  // capture
  const cap = q.capture;
  if (typeof cap.fixture !== "string") push("capture.fixture 应为字符串");
  if (typeof cap.gt !== "string") push("capture.gt 应为字符串");
  if (typeof cap.path !== "string") push("capture.path 应为字符串");
  if (gt) {
    if (gt.capture !== cap.fixture) push(`capture.fixture(${cap.fixture}) 与 gt.capture(${gt.capture}) 不一致`);
    if (gt.detection_basis !== "generator_intent") push(`gt.detection_basis 应为 generator_intent，实际 ${gt.detection_basis}`);
  }

  // type / answer_schema
  if (!ANSWER_FORMS.includes(q.type)) push(`type "${q.type}" 不在五种形态内`);
  const schema = q.answer_schema;
  errs.push(...validateSchemaStructure(schema).map(e => `[${id}] ${e}`));
  if (schema && schema["x-kind"] !== q.type) push(`answer_schema.x-kind(${schema["x-kind"]}) 与 type(${q.type}) 不一致`);
  if (q.type === "set") {
    if (!SET_MATCH_MODES.includes(schema["x-match"])) push(`set 题缺少合法 x-match（${schema["x-match"]}）`);
    if (typeof schema["x-element-key"] !== "string") push("set 题缺少 x-element-key（规范化元素键格式说明）");
  }

  // gold / gold_evidence 结构
  const goldFields = Object.keys(q.gold ?? {});
  const schemaFields = schema && schema.properties ? Object.keys(schema.properties) : [];
  if (JSON.stringify(goldFields.slice().sort()) !== JSON.stringify(schemaFields.slice().sort())) {
    push(`gold 字段 [${goldFields}] 与 answer_schema 字段 [${schemaFields}] 不一致`);
  }
  if (JSON.stringify(Object.keys(q.gold_evidence ?? {})) !== JSON.stringify(goldFields)) {
    push(`gold_evidence 字段与 gold 字段不一致`);
  }
  for (const [f, node] of Object.entries(q.gold ?? {})) {
    if (node === null || typeof node !== "object" || !("value" in node)) push(`gold.${f} 应为 {value[, tolerance_abs]} 节点`);
    if (node && "tolerance_abs" in node) {
      if (typeof node.value !== "number") push(`gold.${f}: tolerance_abs 只能声明在数值字段上`);
      else if (typeof node.tolerance_abs !== "number" || node.tolerance_abs < 0) push(`gold.${f}.tolerance_abs 应为 >=0 的数`);
    }
  }
  if (q.type === "set") {
    const f = goldFields[0];
    const evMap = q.gold_evidence?.[f];
    const goldKeys = Array.isArray(q.gold?.[f]?.value) ? q.gold[f].value.map(canonicalTupleKey).sort() : null;
    const evKeys = evMap && typeof evMap === "object" && !Array.isArray(evMap) ? Object.keys(evMap).sort() : null;
    if (goldKeys === null) push("set 题 gold 值应为数组");
    else if (JSON.stringify(goldKeys) !== JSON.stringify(evKeys)) {
      push(`set 题 gold_evidence 键集与 gold 元素规范化键集不一致：${JSON.stringify(evKeys)} vs ${JSON.stringify(goldKeys)}`);
    }
  }

  // 证据帧范围（对 gold_evidence；gt 已加载时才检查）
  if (gt) {
    const n = gt.packet_count;
    // 否定性/空 gold（空集、unknowable、布尔 false=「未发生」）豁免非空帧集要求
    const assertsNothing = (f) => {
      const node = q.gold?.[f];
      return !!node && (
        (Array.isArray(node.value) && node.value.length === 0) ||
        node.value === "unknowable" ||
        node.value === false ||
        node.unknowable === true
      );
    };
    const checkFrames = (frames, where, allowEmpty = false) => {
      if (!Array.isArray(frames) || (!allowEmpty && frames.length === 0)) { push(`${where}: 帧集应为非空数组`); return; }
      for (const fr of frames) {
        if (!Number.isInteger(fr) || fr < 1 || fr > n) push(`${where}: 帧号 ${fr} 越界（应 ∈ [1,${n}]）`);
      }
    };
    for (const [f, val] of Object.entries(q.gold_evidence ?? {})) {
      if (q.type === "set") {
        for (const [k, frames] of Object.entries(val)) checkFrames(frames, `gold_evidence.${f}[${k}]`);
      } else if (val !== null && typeof val === "object" && !Array.isArray(val)) {
        // 实例题扩展（S3 桥接）：record 题的元素粒度证据表（如 attack_chain 每阶段帧集），
        // 键 = canonicalElementKey(元素值)，逐键检查帧号范围（语义与 set 题同构）
        for (const [k, frames] of Object.entries(val)) checkFrames(frames, `gold_evidence.${f}[${k}]`);
      } else {
        checkFrames(val, `gold_evidence.${f}`, assertsNothing(f));
      }
    }
  }

  // gold 合成答案须通过 answer_schema（结构性自洽）
  const goldAsAnswer = buildGoldAsAnswer(q);
  const goldSchemaErrs = validateSchema(schema, goldAsAnswer);
  for (const e of goldSchemaErrs) push(`gold 结构不合 answer_schema: ${e}`);

  // gold_derivation / reference_solution
  const gd = q.gold_derivation;
  if (!gd || !Array.isArray(gd.gt_pointers) || gd.gt_pointers.length === 0) push("gold_derivation.gt_pointers 应为非空数组");
  if (!gd || typeof gd.derivation !== "string" || gd.derivation.length < 20) push("gold_derivation.derivation 推导说明过短");
  if (!gd || typeof gd.tolerance_note !== "string") push("gold_derivation.tolerance_note 应说明容差口径");

  const rs = q.reference_solution;
  if (!rs || !Array.isArray(rs.steps) || rs.steps.length === 0) push("reference_solution.steps 应为非空数组（备忘录 §6：无参考解法链不予入库）");
  else {
    rs.steps.forEach((s, i) => {
      if (!Number.isInteger(s.n)) push(`reference_solution.steps[${i}].n 应为整数`);
      if (typeof s.tool !== "string" || !ANSWER_TOOLS.has(s.tool)) push(`reference_solution.steps[${i}].tool "${s.tool}" 不在工具面词表内`);
      if (typeof s.expect !== "string") push(`reference_solution.steps[${i}].expect 应为字符串`);
    });
    const ns = rs.steps.map(s => s.n);
    if (ns.some((v, i) => i > 0 && v !== ns[i - 1] + 1)) push("reference_solution.steps[].n 应从 1 连续递增");
  }
  if (!rs || !rs.factors || !("H" in rs.factors) || !("C" in rs.factors)) push("reference_solution.factors 须含 H 与 C（备忘录 §2 五因子）");
  if (!rs || typeof rs.difficulty_derivation !== "string" || rs.difficulty_derivation.length < 5) push("reference_solution.difficulty_derivation 应说明难度推导");
  if (!rs || typeof rs.bash_equivalent !== "string") push("reference_solution.bash_equivalent 应为 bash 臂等价命令");
  if (q.tags?.ir_coverage === "raw_query_only" && (!rs || typeof rs.ir_rationale !== "string")) {
    push("raw_query_only 题必须在 reference_solution.ir_rationale 给出白名单外依据");
  }

  // tags / provenance
  const t = q.tags;
  if (!Array.isArray(t.protocols) || t.protocols.length === 0) push("tags.protocols 应为非空数组");
  if (!Array.isArray(t.skill) || t.skill.length === 0 || !t.skill.every(s => SKILL_AXES.includes(s))) push(`tags.skill 应为能力轴子集（${SKILL_AXES.join("/")}）`);
  if (![1, 2, 3].includes(t.difficulty)) push("tags.difficulty 应为 1|2|3");
  if (t.difficulty_label !== `D${t.difficulty}`) push(`tags.difficulty_label(${t.difficulty_label}) 与 difficulty(${t.difficulty}) 不一致`);
  if (!IR_COVERAGE.includes(t.ir_coverage)) push(`tags.ir_coverage "${t.ir_coverage}" 不在枚举内`);
  if (!CORPUS_LAYERS.includes(t.corpus_layer)) push("tags.corpus_layer 应为 L1|L2|L3");
  if (typeof t.scenario_pack !== "string" || !/^P\d$/.test(t.scenario_pack)) push("tags.scenario_pack 应形如 P<n>");
  if (!PROVENANCE_SOURCES.includes(q.provenance?.source)) push(`provenance.source "${q.provenance?.source}" 不在枚举内`);

  // canary
  const canary = q.canary;
  if (!canary || !canary.known_good || !canary.known_bad) { push("canary 须含 known_good 与 known_bad"); return errs; }
  if (typeof canary.known_good.answer !== "object") push("canary.known_good.answer 缺失");
  checkExpectShape(canary.known_good.expect ?? {}, "canary.known_good", push, { requireAllTrue: true });
  const kb = canary.known_bad;
  if (typeof kb.answer !== "object") push("canary.known_bad.answer 缺失");
  if (!ERROR_FORMS.includes(kb.error_form)) push(`canary.known_bad.error_form "${kb.error_form}" 不在三分类内`);
  if (typeof kb.emulates !== "string" || kb.emulates.length < 10) push("canary.known_bad.emulates 应说明模拟的失误形态");
  checkExpectShape(kb.expect ?? {}, "canary.known_bad", m => errs.push(m), { requireAllTrue: false });
  if (kb.error_form === "format_error" && kb.expect?.schema_valid !== false) push("error_form=format_error 时 expect.schema_valid 必须为 false");
  if (kb.error_form === "wrong_value" && kb.expect?.correctness !== false) push("error_form=wrong_value 时 expect.correctness 必须为 false");
  if (kb.error_form === "wrong_evidence_frame" && kb.expect?.evidence_pass !== false) push("error_form=wrong_evidence_frame 时 expect.evidence_pass 必须为 false");

  return errs;
}

/** canary 元评测：实际判分结果必须与题目声明的 expect 完全一致（RFC-002 §6.3，两者都须 100%） */
export function metaEvalCanary(q) {
  const problems = [];
  const good = scoreAnswer(q, q.canary.known_good.answer);
  const expectGood = q.canary.known_good.expect;
  const goodVerdict = { schema_valid: good.schema_valid, correctness: good.correctness, evidence_pass: good.evidence_pass };
  if (JSON.stringify(goodVerdict) !== JSON.stringify(expectGood)) {
    problems.push(`known_good 判分 ${JSON.stringify(goodVerdict)} != 声明 ${JSON.stringify(expectGood)}`);
  }
  const bad = scoreAnswer(q, q.canary.known_bad.answer);
  const expectBad = q.canary.known_bad.expect;
  const badVerdict = { schema_valid: bad.schema_valid, correctness: bad.correctness, evidence_pass: bad.evidence_pass };
  if (JSON.stringify(badVerdict) !== JSON.stringify(expectBad)) {
    problems.push(`known_bad 判分 ${JSON.stringify(badVerdict)} != 声明 ${JSON.stringify(expectBad)}（error_form=${q.canary.known_bad.error_form}）`);
  }
  return problems;
}
