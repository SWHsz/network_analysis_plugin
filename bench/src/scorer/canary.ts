/**
 * canary 元评测（RFC-002 §6.3）：判分器先被 benchmark。
 *
 * 每题自带 canary 对（known_good / known_bad，含声明的期望裁决 expect）。
 * 判分器实跑后必须与声明完全一致：
 *   acc_correct = known_good 裁决一致率（须 = 1.0）
 *   acc_wrong   = known_bad  裁决一致率（须 = 1.0）
 * 任一 < 1.0 = 判分器 bug 或题目歧义 → 阻塞实验（CLI 以非零退出码失败）。
 */
import { loadGroundTruth, type CanaryExpect, type Question } from "./question.js";
import { scoreAnswerObject, type CanaryVerdict } from "./pipeline.js";

export interface CanaryCheck {
  questionId: string;
  side: "known_good" | "known_bad";
  errorForm?: string;
  expect: CanaryExpect;
  actual: CanaryVerdict;
  match: boolean;
}

export interface MetaEvalResult {
  checks: CanaryCheck[];
  totalGood: number;
  totalBad: number;
  accCorrect: number;
  accWrong: number;
  /** 两者都为 1.0 才放行实验 */
  pass: boolean;
}

function triplesEqual(a: CanaryVerdict, b: CanaryExpect): boolean {
  return a.schema_valid === b.schema_valid && a.correctness === b.correctness && a.evidence_pass === b.evidence_pass;
}

export function metaEvalQuestion(q: Question, gt = loadGroundTruth(q)): CanaryCheck[] {
  const good = scoreAnswerObject(q, gt, q.canary.known_good.answer);
  const bad = scoreAnswerObject(q, gt, q.canary.known_bad.answer);
  return [
    {
      questionId: q.question_id,
      side: "known_good",
      expect: q.canary.known_good.expect,
      actual: good.verdict,
      match: triplesEqual(good.verdict, q.canary.known_good.expect),
    },
    {
      questionId: q.question_id,
      side: "known_bad",
      errorForm: q.canary.known_bad.error_form,
      expect: q.canary.known_bad.expect,
      actual: bad.verdict,
      match: triplesEqual(bad.verdict, q.canary.known_bad.expect),
    },
  ];
}

export function metaEvalAll(questions: Question[]): MetaEvalResult {
  const checks = questions.flatMap((q) => metaEvalQuestion(q));
  const goods = checks.filter((c) => c.side === "known_good");
  const bads = checks.filter((c) => c.side === "known_bad");
  const accCorrect = goods.length === 0 ? 0 : goods.filter((c) => c.match).length / goods.length;
  const accWrong = bads.length === 0 ? 0 : bads.filter((c) => c.match).length / bads.length;
  return {
    checks,
    totalGood: goods.length,
    totalBad: bads.length,
    accCorrect,
    accWrong,
    pass: accCorrect === 1 && accWrong === 1 && checks.length > 0,
  };
}
