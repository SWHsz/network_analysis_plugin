/**
 * 判分管线：把「提取 → 契约校验 → M1 正确率 → M3 证据 → M4 支持」串成一个
 * 确定性裁决，供 canary 元评测与 runner 报告共用（RFC-002 §6.1/§6.2/§6.5）。
 *
 * 分类 classification：
 *   "correct"      — schema 过、全字段对
 *   "wrong"        — schema 过但有字段错
 *   "format_error" — 提取失败或 answer_schema 校验不过（单独分类，不计入对错）
 */
import { extractFinalAnswer, type Extraction, validateAgainstContract } from "./answer-contract.js";
import { scoreCorrectness, type CorrectnessResult } from "./correctness.js";
import { scoreEvidence, type EvidenceResult } from "./evidence.js";
import { scoreHallucinationSupport, type HallucinationVerdict } from "./hallucination.js";
import type { GroundTruth, Question } from "./question.js";

export type RunClassification = "correct" | "wrong" | "format_error";

export interface ScoredRun {
  questionId: string;
  /** canary 侧标注来源；runner 侧为臂名+运行序号 */
  source: string;
  answerRaw: string;
  extraction: Extraction;
  schemaValid: boolean;
  schemaErrors: string[];
  formatError: string | null;
  correctness: CorrectnessResult | null;
  evidence: EvidenceResult | null;
  hallucination: HallucinationVerdict;
  classification: RunClassification;
}

/** 对一段终答原文跑完整判分管线 */
export function scoreRun(q: Question, gt: GroundTruth, answerRaw: string, source = ""): ScoredRun {
  const extraction = extractFinalAnswer(answerRaw);
  const contract = validateAgainstContract(q.answer_schema, extraction);
  if ("formatError" in contract) {
    return {
      questionId: q.question_id,
      source,
      answerRaw,
      extraction,
      schemaValid: false,
      schemaErrors: [],
      formatError: contract.formatError,
      correctness: null,
      evidence: null,
      hallucination: scoreHallucinationSupport(q, null),
      classification: "format_error",
    };
  }
  const answer = contract.answer as Record<string, unknown>;
  const correctness = scoreCorrectness(q, answer);
  const evidence = scoreEvidence(q, gt, answer);
  return {
    questionId: q.question_id,
    source,
    answerRaw,
    extraction,
    schemaValid: true,
    schemaErrors: [],
    formatError: null,
    correctness,
    evidence,
    hallucination: scoreHallucinationSupport(q, answer),
    classification: correctness.correct ? "correct" : "wrong",
  };
}

/** canary 元评测的裁决三元组（与题目 expect 同形，RFC-002 §6.3） */
export interface CanaryVerdict {
  schema_valid: boolean;
  correctness: boolean;
  evidence_pass: boolean;
}

function verdictOf(run: {
  schemaValid: boolean;
  correctness: CorrectnessResult | null;
  evidence: EvidenceResult | null;
}): CanaryVerdict {
  return {
    schema_valid: run.schemaValid,
    correctness: run.correctness?.correct ?? false,
    evidence_pass: (run.evidence?.fields.length ?? 0) > 0 && (run.evidence?.fields.every((f) => f.pass) ?? false),
  };
}

/** 直接对结构化答案对象判分（canary 答案不走 fenced block 提取） */
export function scoreAnswerObject(q: Question, gt: GroundTruth, answer: Record<string, unknown>): {
  verdict: CanaryVerdict;
  detail: Omit<ScoredRun, "answerRaw" | "extraction"> & { answerRaw: string; extraction: { status: "ok"; value: unknown; nonUniqueBlock: false } };
} {
  const raw = JSON.stringify(answer, null, 2);
  // canary 答案绕过提取器直接进契约校验：known_bad 的 format_error 形态
  // 本就是「结构不合 schema」，从对象层校验等价复现
  const contract = validateAgainstContract(q.answer_schema, { status: "ok", value: answer, nonUniqueBlock: false });
  if ("formatError" in contract) {
    return {
      verdict: { schema_valid: false, correctness: false, evidence_pass: false },
      detail: {
        questionId: q.question_id,
        source: "",
        answerRaw: raw,
        extraction: { status: "ok", value: answer, nonUniqueBlock: false },
        schemaValid: false,
        schemaErrors: [],
        formatError: contract.formatError,
        correctness: null,
        evidence: null,
        hallucination: scoreHallucinationSupport(q, null),
        classification: "format_error",
      },
    };
  }
  const ans = contract.answer as Record<string, unknown>;
  const correctness = scoreCorrectness(q, ans);
  const evidence = scoreEvidence(q, gt, ans);
  return {
    verdict: {
      schema_valid: true,
      correctness: correctness.correct,
      evidence_pass: evidence.fields.length > 0 && evidence.fields.every((f) => f.pass),
    },
    detail: {
      questionId: q.question_id,
      source: "",
      answerRaw: raw,
      extraction: { status: "ok", value: answer, nonUniqueBlock: false },
      schemaValid: true,
      schemaErrors: [],
      formatError: null,
      correctness,
      evidence,
      hallucination: scoreHallucinationSupport(q, ans),
      classification: correctness.correct ? "correct" : "wrong",
    },
  };
}
