/** M4 幻觉判定支持 + canary 元评测（含失败路径）+ §6.5 报告组装 */
import { describe, expect, it } from "vitest";
import { scoreHallucinationSupport } from "../src/scorer/hallucination.js";
import { metaEvalAll, metaEvalQuestion } from "../src/scorer/canary.js";
import { assembleReport, type ReportRun } from "../src/scorer/report.js";
import { makeQuestion } from "./helpers.js";

describe("scoreHallucinationSupport（M4 判分侧支持）", () => {
  it("空集 gold：答非空 = hallucination，答空集 = 诚实", () => {
    const q = makeQuestion({ gold: { arp_replies: { value: [] } }, gold_evidence: { arp_replies: [] } });
    expect(scoreHallucinationSupport(q, { arp_replies: { value: [{ proto: "arp" }], evidence: [1] } }).hallucinated).toBe(true);
    expect(scoreHallucinationSupport(q, { arp_replies: { value: [], evidence: [] } }).hallucinated).toBe(false);
  });

  it("unknowable gold：哨兵值不算幻觉", () => {
    const q = makeQuestion({ gold: { initiator: { value: "unknowable" } }, gold_evidence: { initiator: [] } });
    expect(scoreHallucinationSupport(q, { initiator: { value: "192.168.1.4", evidence: [1] } }).hallucinated).toBe(true);
    expect(scoreHallucinationSupport(q, { initiator: { value: "unknowable", evidence: [] } }).hallucinated).toBe(false);
  });

  it("普通题不适用；format_error 答案不参与判定", () => {
    const q = makeQuestion();
    expect(scoreHallucinationSupport(q, { value: { value: 3, evidence: [1] } }).applicable).toBe(false);
    expect(scoreHallucinationSupport(q, null).hallucinated).toBe(false);
  });
});

describe("canary 元评测（RFC-002 §6.3）", () => {
  it("一致时 acc 双 1.0 且 pass", () => {
    const q = makeQuestion();
    const r = metaEvalAll([q]);
    expect(r.pass).toBe(true);
    expect(r.accCorrect).toBe(1);
    expect(r.accWrong).toBe(1);
  });

  it("失败路径：题目声明与判分器裁决不一致 → 检出且 pass=false（阻塞实验）", () => {
    // 题目错误声明 known_bad 应当 correctness=true —— 元评测必须抓住
    const q = makeQuestion();
    q.canary.known_bad.expect = { schema_valid: true, correctness: true, evidence_pass: true };
    const checks = metaEvalQuestion(q);
    expect(checks.find((c) => c.side === "known_bad")?.match).toBe(false);
    const all = metaEvalAll([q]);
    expect(all.pass).toBe(false);
    expect(all.accWrong).toBe(0);
  });

  it("known_bad 的 format_error 形态：schema_valid=false 三元组全 false", () => {
    const q = makeQuestion();
    q.canary.known_bad = {
      answer: { value: 3 }, // 裸整数，非 {value,evidence} 节点
      error_form: "format_error",
      emulates: "违反答案契约节点结构",
      expect: { schema_valid: false, correctness: false, evidence_pass: false },
    };
    const r = metaEvalAll([q]);
    expect(r.pass).toBe(true);
  });
});

describe("assembleReport（§6.5 结构）", () => {
  const q = makeQuestion();
  const tags = q.tags;
  const run = (over: Partial<ReportRun>): ReportRun => ({
    questionId: "q-test-001",
    runIndex: 1,
    question: { tags },
    classification: "correct",
    schemaValid: true,
    ...over,
  });

  it("M1/M2/M3 汇总与分层视图", () => {
    const runs: ReportRun[] = [
      run({
        runIndex: 1,
        classification: "correct",
        evidence: { coverage: 1, macroPrecision: 1, macroRecall: 1, allFieldsPass: true, needsHumanReviewFields: [] },
        metrics: { llmCalls: 3, inputTokens: 100, outputTokens: 50, toolRenderChars: 200, interfaceTokens: 555, wallMs: 1000, budgetExhausted: false },
      }),
      run({
        runIndex: 2,
        classification: "wrong_answer",
        evidence: { coverage: 0.5, macroPrecision: 0.5, macroRecall: 0.5, allFieldsPass: false, needsHumanReviewFields: ["retr"] },
        metrics: { llmCalls: 5, inputTokens: 200, outputTokens: 100, toolRenderChars: 400, interfaceTokens: 555, wallMs: 2000, budgetExhausted: false },
      }),
      run({ runIndex: 3, classification: "format_error", schemaValid: false }),
    ];
    const rep = assembleReport({ arm: "test-arm", model: "m", date: "2026-08-21", runsPerQuestion: 3, runs });
    expect(rep.M1_correctness.overall).toBeCloseTo(1 / 3);
    expect(rep.M1_correctness.by_axis_difficulty["S2×D1"]).toEqual({ total: 3, correct: 1 });
    // token-per-correct 分母 = 全部运行 token
    expect(rep.M2_cost.tokens_per_correct).toBeCloseTo((150 + 300) / 1);
    expect(rep.M2_cost.usd_per_correct).toBeNull(); // 切片期无定价
    expect(rep.M3_evidence.coverage).toBeCloseTo(0.75); // 仅 schema 有效运行参与
    expect(rep.diagnostics.format_error_rate).toBeCloseTo(1 / 3);
    expect(rep.diagnostics.interface_tokens).toBeCloseTo(555);
    expect(rep.diagnosis_subset).toBeNull();
  });

  it("缺数据字段填 null：无正确运行 → M2 null；无 S9 题 → M4 null", () => {
    const rep = assembleReport({
      arm: "a",
      model: "m",
      date: "d",
      runsPerQuestion: 1,
      runs: [run({ classification: "wrong_answer", evidence: { coverage: 1, macroPrecision: 1, macroRecall: 0.5, allFieldsPass: false, needsHumanReviewFields: [] } })],
    });
    expect(rep.M2_cost.tokens_per_correct).toBeNull();
    expect(rep.M4_hallucination_rate).toBeNull();
    expect(rep.diagnostics.budget_exhausted_rate).toBeNull();
  });
});
