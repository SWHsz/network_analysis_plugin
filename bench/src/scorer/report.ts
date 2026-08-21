/**
 * 指标报告（RFC-002 §6.5 v1.1 结构；口径锁定见备忘录 §7）。
 *
 * - M1 主指标 = 全字段对；分层视图：能力轴×难度 / 场景包 / ir_coverage / 语料层
 * - M2 token-per-correct：分母 = 全部运行的 token（含答错与预算耗尽，防 Goodhart）；
 *   切片期无定价 → usd_per_correct = null
 * - M3 = 覆盖率 + 对 gold 帧集的宏平均 precision/recall（仅 schema 有效的运行）
 * - M4 = 空集/不可知题上编造比例；切片题库暂无此类题 → null
 * - 缺数据的字段一律填 null，不造数
 */
import type { Question } from "./question.js";
import type { RunClassification } from "./pipeline.js";
import type { HallucinationVerdict } from "./hallucination.js";

/** runner 侧提供的单次运行遥测（RFC-002 §5.1 metrics 子集） */
export interface RunMetrics {
  llmCalls: number;
  inputTokens: number;
  outputTokens: number;
  toolRenderChars: number;
  interfaceTokens: number;
  wallMs: number;
  budgetExhausted: boolean;
}

export interface ReportRun {
  questionId: string;
  runIndex: number;
  question: Pick<Question, "tags">;
  classification: RunClassification;
  schemaValid: boolean;
  evidence?: {
    coverage: number;
    macroPrecision: number;
    macroRecall: number;
    allFieldsPass: boolean;
    needsHumanReviewFields: string[];
  };
  hallucination?: HallucinationVerdict;
  metrics?: RunMetrics;
}

export interface SliceReport {
  arm: string;
  model: string;
  date: string;
  runs_per_question: number;
  M1_correctness: {
    overall: number | null;
    by_axis_difficulty: Record<string, { total: number; correct: number }>;
    by_scenario_pack: Record<string, { total: number; correct: number }>;
    by_ir_coverage: Record<string, { total: number; correct: number }>;
    by_corpus_layer: Record<string, { total: number; correct: number }>;
  };
  M2_cost: {
    tokens_per_correct: number | null;
    usd_per_correct: number | null;
    wall_ms_per_correct: number | null;
  };
  M3_evidence: {
    coverage: number | null;
    precision: number | null;
    recall: number | null;
  };
  M4_hallucination_rate: number | null;
  diagnostics: {
    format_error_rate: number;
    error_mode_dist: Record<string, number>;
    turns_per_question: number | null;
    budget_exhausted_rate: number | null;
    interface_tokens: number | null;
  };
  diagnosis_subset: null;
  per_run: Array<{
    question_id: string;
    run_index: number;
    classification: RunClassification;
    schema_valid: boolean;
    evidence_pass: boolean | null;
    needs_human_review_fields: string[];
    hallucinated: boolean | null;
    budget_exhausted: boolean | null;
  }>;
}

function bucketBy(runs: ReportRun[], key: (r: ReportRun) => string): Record<string, { total: number; correct: number }> {
  const out: Record<string, { total: number; correct: number }> = {};
  for (const r of runs) {
    const k = key(r);
    out[k] ??= { total: 0, correct: 0 };
    out[k].total++;
    if (r.classification === "correct") out[k].correct++;
  }
  return out;
}

const mean = (xs: number[]): number | null => (xs.length === 0 ? null : xs.reduce((a, b) => a + b, 0) / xs.length);

export function assembleReport(input: {
  arm: string;
  model: string;
  date: string;
  runsPerQuestion: number;
  runs: ReportRun[];
}): SliceReport {
  const runs = input.runs;
  const correctCount = runs.filter((r) => r.classification === "correct").length;
  const scored = runs.filter((r) => r.schemaValid && r.evidence !== undefined);
  const m4Applicable = runs.filter((r) => r.hallucination?.applicable === true);
  const withMetrics = runs.filter((r) => r.metrics !== undefined);

  const totalTokens = withMetrics.reduce((a, r) => a + (r.metrics?.inputTokens ?? 0) + (r.metrics?.outputTokens ?? 0), 0);
  const totalWallMs = withMetrics.reduce((a, r) => a + (r.metrics?.wallMs ?? 0), 0);

  const errorModeDist: Record<string, number> = { correct: 0, wrong: 0, format_error: 0, budget_exhausted: 0 };
  const bump = (k: string) => {
    errorModeDist[k] = (errorModeDist[k] ?? 0) + 1;
  };
  for (const r of runs) {
    if (r.metrics?.budgetExhausted) bump("budget_exhausted");
    bump(r.classification);
  }

  return {
    arm: input.arm,
    model: input.model,
    date: input.date,
    runs_per_question: input.runsPerQuestion,
    M1_correctness: {
      overall: runs.length === 0 ? null : correctCount / runs.length,
      by_axis_difficulty: bucketBy(runs, (r) => `${r.question.tags.skill.join("+")}×${r.question.tags.difficulty_label}`),
      by_scenario_pack: bucketBy(runs, (r) => r.question.tags.scenario_pack),
      by_ir_coverage: bucketBy(runs, (r) => r.question.tags.ir_coverage),
      by_corpus_layer: bucketBy(runs, (r) => r.question.tags.corpus_layer),
    },
    M2_cost: {
      // 分母含答错/预算耗尽的全部消耗（备忘录 §7-M2 预注册口径）
      tokens_per_correct: correctCount === 0 || withMetrics.length === 0 ? null : totalTokens / correctCount,
      usd_per_correct: null,
      wall_ms_per_correct: correctCount === 0 || withMetrics.length === 0 ? null : totalWallMs / correctCount,
    },
    M3_evidence: {
      coverage: mean(scored.map((r) => r.evidence?.coverage ?? 0)),
      precision: mean(scored.map((r) => r.evidence?.macroPrecision ?? 0)),
      recall: mean(scored.map((r) => r.evidence?.macroRecall ?? 0)),
    },
    M4_hallucination_rate:
      m4Applicable.length === 0 ? null : m4Applicable.filter((r) => r.hallucination?.hallucinated === true).length / m4Applicable.length,
    diagnostics: {
      format_error_rate: runs.length === 0 ? 0 : runs.filter((r) => r.classification === "format_error").length / runs.length,
      error_mode_dist: errorModeDist,
      turns_per_question: mean(withMetrics.map((r) => r.metrics?.llmCalls ?? 0)),
      budget_exhausted_rate: withMetrics.length === 0 ? null : withMetrics.filter((r) => r.metrics?.budgetExhausted === true).length / withMetrics.length,
      interface_tokens: mean(withMetrics.map((r) => r.metrics?.interfaceTokens ?? 0)),
    },
    diagnosis_subset: null,
    per_run: runs.map((r) => ({
      question_id: r.questionId,
      run_index: r.runIndex,
      classification: r.classification,
      schema_valid: r.schemaValid,
      evidence_pass: r.evidence ? r.evidence.allFieldsPass : null,
      needs_human_review_fields: r.evidence?.needsHumanReviewFields ?? [],
      hallucinated: r.hallucination?.applicable ? r.hallucination.hallucinated : null,
      budget_exhausted: r.metrics ? r.metrics.budgetExhausted : null,
    })),
  };
}
