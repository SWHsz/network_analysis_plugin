/**
 * M3 证据判分（RFC-002 §6.2，确定性）。
 *
 * 口径：
 * - 结构覆盖率 coverage = 有非空且有效证据的字段数 / 事实字段总数；
 *   有效 = 帧号 ∈ [1, gt.packet_count]。set 题按 gold 元素粒度计。
 * - 字段级 precision/recall 对 gold_evidence 帧集；汇总落宏平均。
 * - "有效支撑" = precision === 1 且 recall > 0（备忘录 §7-M3，预注册口径）。
 * - precision < 1 时细分引用了什么：同会话同类型的「疑似等价帧」（单列，
 *   供人工裁定等价帧容差表）、同会话不同类型的「相关帧」、其余「无关帧」、
 *   越界「无效帧」。仅当失分完全来自等价/相关帧时标 needs_human_review——
 *   判分本身仍按预注册口径执行，不引入隐式容差。
 */
import { canonicalElementKey } from "./elements.js";
import type { GroundTruth, Question } from "./question.js";

export interface EvidenceBreakdown {
  equivalent: number[];
  related: number[];
  irrelevant: number[];
  invalid: number[];
}

export interface EvidenceFieldScore {
  path: string;
  /** set 题的元素规范化键；非 set 题为 null */
  elementKey: string | null;
  citedCount: number;
  precision: number;
  recall: number;
  structurallyValid: boolean;
  breakdown: EvidenceBreakdown;
  pass: boolean;
  needsHumanReview: boolean;
  /** set 题：答案混入的非 gold 元素（对空 gold 集判分，必不 pass） */
  notInGold?: boolean;
}

export interface EvidenceResult {
  fields: EvidenceFieldScore[];
  coverage: number;
  macroPrecision: number;
  macroRecall: number;
}

function pr(cited: Set<number>, gold: Set<number>): { precision: number; recall: number } {
  let inter = 0;
  for (const f of cited) if (gold.has(f)) inter++;
  return {
    precision: cited.size === 0 ? 0 : inter / cited.size,
    recall: gold.size === 0 ? 0 : inter / gold.size,
  };
}

class FrameIndex {
  private byFrame = new Map<number, { conv: string | null; kind: string | null }>();

  constructor(gt: GroundTruth) {
    for (const f of gt.frames ?? []) {
      if (typeof f?.frame === "number") {
        this.byFrame.set(f.frame, { conv: f.conv ?? null, kind: f.kind ?? null });
      }
    }
  }

  has(frame: number): boolean {
    return this.byFrame.has(frame);
  }

  profile(frame: number): { conv: string | null; kind: string | null } {
    return this.byFrame.get(frame) ?? { conv: null, kind: null };
  }
}

/** 引用帧分类：gold 帧集的 (conv, kind) 轮廓之外的引用落到哪个桶 */
function classifyCited(cited: number[], gold: number[], packetCount: number, index: FrameIndex): EvidenceBreakdown {
  const goldSet = new Set(gold);
  const goldProfiles = new Set(gold.map((f) => JSON.stringify(index.profile(f))));
  const goldConvs = new Set(gold.map((f) => index.profile(f).conv).filter((c): c is string => c !== null));
  const out: EvidenceBreakdown = { equivalent: [], related: [], irrelevant: [], invalid: [] };
  for (const f of cited) {
    if (goldSet.has(f)) continue;
    if (!Number.isInteger(f) || f < 1 || f > packetCount) {
      out.invalid.push(f);
      continue;
    }
    if (!index.has(f)) {
      out.irrelevant.push(f);
      continue;
    }
    const p = index.profile(f);
    if (p.conv !== null && goldConvs.has(p.conv)) {
      if (goldProfiles.has(JSON.stringify(p))) out.equivalent.push(f);
      else out.related.push(f);
    } else {
      out.irrelevant.push(f);
    }
  }
  return out;
}

function emptyScore(path: string, elementKey: string | null): EvidenceFieldScore {
  return {
    path,
    elementKey,
    citedCount: 0,
    precision: 0,
    recall: 0,
    structurallyValid: false,
    breakdown: { equivalent: [], related: [], irrelevant: [], invalid: [] },
    pass: false,
    needsHumanReview: false,
  };
}

function finalize(score: EvidenceFieldScore, cited: number[], gold: number[], packetCount: number, index: FrameIndex): void {
  // 空集/不可知 gold（S9，备忘录 §7 注册定义）：诚实空引用 = 有效支撑
  // （precision:=1、recall:=1）；引用了任何帧则 precision=0 判否。
  // 覆盖率口径不变：无非空有效证据不计入 coverage 分子。
  if (gold.length === 0) {
    score.citedCount = cited.length;
    score.precision = cited.length === 0 ? 1 : 0;
    score.recall = 1;
    score.structurallyValid = false;
    score.breakdown = classifyCited(cited, gold, packetCount, index);
    score.pass = cited.length === 0;
    score.needsHumanReview = false;
    return;
  }
  score.citedCount = cited.length;
  const validCited = cited.every((f) => Number.isInteger(f) && f >= 1 && f <= packetCount);
  score.structurallyValid = cited.length > 0 && validCited;
  const r = pr(new Set(cited), new Set(gold));
  score.precision = r.precision;
  score.recall = r.recall;
  score.breakdown = classifyCited(cited, gold, packetCount, index);
  score.pass = score.precision === 1 && score.recall > 0;
  score.needsHumanReview =
    !score.pass && score.breakdown.invalid.length === 0 && score.breakdown.irrelevant.length === 0;
}

function citedFramesOf(ansNode: unknown): number[] {
  if (!ansNode || typeof ansNode !== "object" || Array.isArray(ansNode)) return [];
  const ev = (ansNode as { evidence?: unknown }).evidence;
  return Array.isArray(ev) ? ev.filter((f): f is number => typeof f === "number") : [];
}

export function scoreEvidence(q: Question, gt: GroundTruth, answer: Record<string, unknown>): EvidenceResult {
  const index = new FrameIndex(gt);
  const n = gt.packet_count;
  const fields: EvidenceFieldScore[] = [];

  if (q.type === "set") {
    const fieldName = Object.keys(q.answer_schema.properties ?? {})[0] ?? "";
    const goldMap = q.gold_evidence[fieldName] as Record<string, number[]> | undefined;
    const goldValue = q.gold[fieldName]?.value;
    const goldKeys: string[] = Array.isArray(goldValue) ? goldValue.map(canonicalElementKey) : [];
    const ansList = Array.isArray(answer[fieldName]) ? (answer[fieldName] as unknown[]) : [];
    // 按 gold 元素粒度计覆盖率与字段级 P/R；答案混入的非 gold 元素单独成行（必不 pass）
    const ansByKey = new Map<string, number[]>();
    for (const el of ansList) {
      const node = el as { value?: unknown; evidence?: unknown } | null;
      const key = canonicalElementKey(node?.value);
      if (!ansByKey.has(key)) ansByKey.set(key, citedFramesOf(node));
    }
    for (const key of goldKeys) {
      const score = emptyScore(fieldName, key);
      const gold = goldMap?.[key] ?? [];
      const cited = ansByKey.get(key) ?? [];
      if (gold.length > 0) finalize(score, cited, gold, n, index);
      fields.push(score);
    }
    for (const [key, cited] of ansByKey) {
      if (goldKeys.includes(key)) continue;
      const score = emptyScore(fieldName, key);
      finalize(score, cited, [], n, index); // 对空 gold 集：precision 即判死
      score.notInGold = true;
      fields.push(score);
    }
  } else {
    for (const [fieldName, gold] of Object.entries(q.gold_evidence)) {
      const score = emptyScore(fieldName, null);
      if (Array.isArray(gold)) finalize(score, citedFramesOf(answer[fieldName]), gold, n, index);
      fields.push(score);
    }
  }

  const coverageBasis = fields.filter((f) => !f.notInGold);
  const coverage =
    coverageBasis.length === 0 ? 0 : coverageBasis.filter((f) => f.structurallyValid).length / coverageBasis.length;
  const macroPrecision = fields.length === 0 ? 0 : fields.reduce((a, b) => a + b.precision, 0) / fields.length;
  const macroRecall = fields.length === 0 ? 0 : fields.reduce((a, b) => a + b.recall, 0) / fields.length;
  return { fields, coverage, macroPrecision, macroRecall };
}
