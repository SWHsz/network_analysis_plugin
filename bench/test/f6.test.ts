/** F6 协议不合规分类（scorer/f6.ts）：子类判定、四分桶、双口径完成率 */
import { describe, expect, it } from "vitest";
import { classifyF6, completionRates, emptyBreakdown, outcomeBucket } from "../src/scorer/f6.js";

describe("classifyF6", () => {
  it("a) 空 answerRaw + format_error → no_finish_call", () => {
    const f6 = classifyF6({ classification: "format_error", answerRaw: "", toolCallCount: 3, llmCalls: 4, maxTurns: 8 });
    expect(f6.no_finish_call).toBe(true);
    expect(f6.finish_payload_invalid).toBe(false);
    expect(f6.no_tool_exploration).toBe(false);
    expect(f6.max_turns_exhausted).toBe(false);
  });

  it("b) 非空 answerRaw + format_error → finish_payload_invalid", () => {
    const f6 = classifyF6({ classification: "format_error", answerRaw: "答案：三次", toolCallCount: 3, llmCalls: 4, maxTurns: 8 });
    expect(f6.finish_payload_invalid).toBe(true);
    expect(f6.no_finish_call).toBe(false);
  });

  it("c) 零工具调用 → no_tool_exploration（独立于其它标志）", () => {
    const f6 = classifyF6({ classification: "wrong_answer", answerRaw: "```json\n{}\n```", toolCallCount: 0, llmCalls: 2, maxTurns: 8 });
    expect(f6.no_tool_exploration).toBe(true);
    expect(f6.no_finish_call).toBe(false);
  });

  it("maxTurns 打满附注（不改变其它子类判定）", () => {
    const f6 = classifyF6({ classification: "format_error", answerRaw: "", toolCallCount: 5, llmCalls: 8, maxTurns: 8 });
    expect(f6.max_turns_exhausted).toBe(true);
    expect(f6.no_finish_call).toBe(true);
  });

  it("correct 运行无任何 F6 标志", () => {
    const f6 = classifyF6({ classification: "correct", answerRaw: "```json\n{x:1}\n```", toolCallCount: 4, llmCalls: 5, maxTurns: 8 });
    expect(Object.values(f6).every((v) => v === false)).toBe(true);
  });
});

describe("outcomeBucket / completionRates", () => {
  it("E1 两例：打满轮次→budget_exhausted；未打满格式失败→protocol_noncompliance", () => {
    const exhausted = classifyF6({ classification: "format_error", answerRaw: "", toolCallCount: 5, llmCalls: 8, maxTurns: 8 });
    expect(outcomeBucket("format_error", exhausted)).toBe("budget_exhausted");
    const plain = classifyF6({ classification: "format_error", answerRaw: "", toolCallCount: 4, llmCalls: 4, maxTurns: 8 });
    expect(outcomeBucket("format_error", plain)).toBe("protocol_noncompliance");
  });

  it("correct/wrong_answer → forensic_*", () => {
    const clean = classifyF6({ classification: "correct", answerRaw: "x", toolCallCount: 2, llmCalls: 3, maxTurns: 8 });
    expect(outcomeBucket("correct", clean)).toBe("forensic_correct");
    expect(outcomeBucket("wrong_answer", clean)).toBe("forensic_wrong");
  });

  it("双口径完成率：excluding_F6 剔除 protocol/bucket 失败", () => {
    const b = emptyBreakdown();
    b.forensic_correct = 2;
    b.forensic_wrong = 1;
    b.protocol_noncompliance = 1;
    b.budget_exhausted = 1;
    const r = completionRates(b);
    expect(r.completion_rate_excluding_F6).toBe("2/3");
    expect(r.completion_rate_raw).toBe("2/5");
  });
});
