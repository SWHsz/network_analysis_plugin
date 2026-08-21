/**
 * 真实题库金标准（Prompt 3 验收 b）：加载 bench/questions/ 全部 5 题 × 2 canary，
 * 判分器实跑元评测必须 10/10；known_good 走完整管线（含 fenced 提取）必须判 correct。
 */
import { describe, expect, it } from "vitest";
import { loadGroundTruth, loadQuestionsDir } from "../src/scorer/question.js";
import { metaEvalAll } from "../src/scorer/canary.js";
import { scoreRun } from "../src/scorer/pipeline.js";
import { fenced } from "./helpers.js";

const questions = loadQuestionsDir();

describe("bench/questions 题库", () => {
  it("切片期恰为 5 题，覆盖五种答案形态与三种 canary 错误形态", () => {
    expect(questions.length).toBe(5);
    const forms = new Set(questions.map((q) => q.type));
    expect(forms.has("scalar_number")).toBe(true);
    expect(forms.has("scalar_enum")).toBe(true);
    expect(forms.has("set")).toBe(true);
    expect(forms.has("record")).toBe(true);
    const errorForms = new Set(questions.map((q) => q.canary.known_bad.error_form));
    expect(errorForms.size).toBeGreaterThanOrEqual(3); // 值错/证据帧错/格式错
  });

  it("canary 元评测 10/10（验收 b）", () => {
    const r = metaEvalAll(questions);
    const failed = r.checks.filter((c) => !c.match);
    expect(failed, JSON.stringify(failed.map((c) => [c.questionId, c.side, c.expect, c.actual]))).toEqual([]);
    expect(r.totalGood).toBe(5);
    expect(r.totalBad).toBe(5);
    expect(r.accCorrect).toBe(1);
    expect(r.accWrong).toBe(1);
  });

  it.each(questions.map((q) => [q.question_id, q] as const))(
    "%s：known_good 答案经 fenced 提取走完整管线 → correct",
    (_id, q) => {
      const gt = loadGroundTruth(q);
      const run = scoreRun(q, gt, fenced(q.canary.known_good.answer), "golden");
      expect(run.classification, JSON.stringify(run)).toBe("correct");
      expect(run.extraction.status === "ok" && run.extraction.nonUniqueBlock).toBe(false);
    },
  );

  it("gold 自身合成答案必过 answer_schema 且判 correct（题目自洽）", () => {
    for (const q of questions) {
      const gt = loadGroundTruth(q);
      // gold_evidence 直接作为证据帧集合成 gold 答案
      const goldAnswer: Record<string, unknown> = {};
      if (q.type === "set") {
        const field = Object.keys(q.gold)[0]!;
        const evMap = q.gold_evidence[field] as Record<string, number[]>;
        const tuples = q.gold[field]!.value as Array<Record<string, unknown>>;
        const keyOf = (t: Record<string, unknown>) =>
          `${t.proto}|${t.src}:${t.sport}>${t.dst}:${t.dport}`;
        goldAnswer[field] = tuples.map((t) => ({ value: t, evidence: evMap[keyOf(t)] }));
      } else {
        for (const [field, node] of Object.entries(q.gold)) {
          goldAnswer[field] = { value: node.value, evidence: q.gold_evidence[field] };
        }
      }
      const run = scoreRun(q, gt, fenced(goldAnswer), "gold-self");
      expect(run.classification, `${q.question_id}: ${JSON.stringify(run.formatError ?? run.correctness)}`).toBe("correct");
    }
  });
});
