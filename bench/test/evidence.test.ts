/** M3 证据判分（RFC-002 §6.2）：结构覆盖率、字段级 P/R、等价帧细分 */
import { describe, expect, it } from "vitest";
import { scoreEvidence } from "../src/scorer/evidence.js";
import { makeGt, makeQuestion } from "./helpers.js";

const node = (value: unknown, evidence: number[]) => ({ value, evidence });

const gt = makeGt({
  frames: [
    { frame: 1, conv: "A", kind: "syn" },
    { frame: 2, conv: "A", kind: "synack" },
    { frame: 3, conv: "A", kind: "ack" },
    { frame: 8, conv: "A", kind: "retransmission" },
    { frame: 11, conv: "A", kind: "retransmission" },
    { frame: 14, conv: "A", kind: "retransmission" },
    { frame: 22, conv: "X2", kind: "zero_window" },
    { frame: 23, conv: "X2", kind: "window_update" },
    { frame: 31, conv: null, kind: "noise" },
  ],
});

const q = makeQuestion({
  gold: { retr: { value: 3 }, hs_ms: { value: 70.0, tolerance_abs: 2.0 } },
  gold_evidence: { retr: [8, 11, 14], hs_ms: [1, 2, 3] },
  answer_schema: {
    "x-kind": "record",
    type: "object",
    properties: { retr: { type: "object" }, hs_ms: { type: "object" } },
    required: ["retr", "hs_ms"],
  },
});

describe("scoreEvidence", () => {
  it("精确引用 gold：precision=1、recall=1、pass", () => {
    const r = scoreEvidence(q, gt, { retr: node(3, [8, 11, 14]), hs_ms: node(70, [1, 2, 3]) });
    expect(r.fields.every((f) => f.pass)).toBe(true);
    expect(r.coverage).toBe(1);
    expect(r.macroPrecision).toBe(1);
    expect(r.macroRecall).toBe(1);
  });

  it("部分引用也是有效支撑（precision=1、recall<1）", () => {
    const r = scoreEvidence(q, gt, { retr: node(3, [8]), hs_ms: node(70, [1]) });
    expect(r.fields.every((f) => f.pass)).toBe(true);
    // 每字段 recall = 1/3（gold 各 3 帧，各引 1 帧）
    expect(r.macroRecall).toBeCloseTo(1 / 3);
  });

  it("无关帧拉低 precision；越界帧记 invalid 且结构无效", () => {
    const r = scoreEvidence(q, gt, { retr: node(3, [8, 31]), hs_ms: node(70, [1, 99]) });
    const retr = r.fields.find((f) => f.path === "retr")!;
    expect(retr.pass).toBe(false);
    expect(retr.breakdown.irrelevant).toEqual([31]);
    const hs = r.fields.find((f) => f.path === "hs_ms")!;
    expect(hs.breakdown.invalid).toEqual([99]);
    expect(hs.structurallyValid).toBe(false);
  });

  it("同会话同类型 → 疑似等价帧单列并标 needs_human_review；同会话异类型 → related", () => {
    // 用 X2 的 zero_window 帧 22 对 gold=[22] 的题验证等价/相关路径
    const qz = makeQuestion({
      gold: { zw: { value: true } },
      gold_evidence: { zw: [22] },
      answer_schema: { type: "object", properties: { zw: { type: "object" } }, required: ["zw"] },
    });
    // 引用同会话不同类型的帧 23（window_update）：related 桶 + needs_human_review
    const r = scoreEvidence(qz, gt, { zw: node(true, [22, 23]) });
    const f = r.fields[0]!;
    expect(f.breakdown.related).toEqual([23]);
    expect(f.precision).toBeCloseTo(0.5);
    expect(f.needsHumanReview).toBe(true);

    // 引用无会话噪声帧 31：irrelevant 桶，不标 needs_human_review
    const r2 = scoreEvidence(qz, gt, { zw: node(true, [22, 31]) });
    const f2 = r2.fields[0]!;
    expect(f2.breakdown.irrelevant).toEqual([31]);
    expect(f2.needsHumanReview).toBe(false);
  });

  it("覆盖率按非空且有效证据的字段数计", () => {
    const r = scoreEvidence(q, gt, { retr: node(3, [8]), hs_ms: node(70, []) });
    expect(r.coverage).toBeCloseTo(0.5);
  });

  it("空集 gold（S9 注册定义）：诚实空引用=有效支撑，引用任何帧判否", () => {
    const qz = makeQuestion({
      gold: { arp: { value: [] } },
      gold_evidence: { arp: [] },
      answer_schema: { type: "object", properties: { arp: { type: "object" } }, required: ["arp"] },
    });
    const honest = scoreEvidence(qz, gt, { arp: node([], []) });
    expect(honest.fields[0]!.pass).toBe(true);
    expect(honest.fields[0]!.precision).toBe(1);
    expect(honest.fields[0]!.recall).toBe(1);
    // 覆盖率口径不变：无非空有效证据不计入分子
    expect(honest.coverage).toBe(0);

    const asserted = scoreEvidence(qz, gt, { arp: node([{ proto: "arp" }], [1]) });
    expect(asserted.fields[0]!.pass).toBe(false);
    expect(asserted.fields[0]!.precision).toBe(0);
  });
});
