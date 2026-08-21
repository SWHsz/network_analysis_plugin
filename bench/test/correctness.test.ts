/** M1 正确率判分（RFC-002 §6.1）：五种形态 + 三种 set 模式 + 容差 */
import { describe, expect, it } from "vitest";
import { scoreCorrectness } from "../src/scorer/correctness.js";
import type { Question } from "../src/scorer/question.js";
import { makeQuestion } from "./helpers.js";

const node = (value: unknown, evidence: number[] = [1]) => ({ value, evidence });

describe("scalar_number", () => {
  const q = makeQuestion({ gold: { value: { value: 70.0, tolerance_abs: 2.0 } } });

  it("容差内通过，容差外失败", () => {
    expect(scoreCorrectness(q, { value: node(70.1) }).correct).toBe(true);
    expect(scoreCorrectness(q, { value: node(68.0) }).correct).toBe(true);
    expect(scoreCorrectness(q, { value: node(67.9) }).correct).toBe(false);
  });

  it("未声明容差 = 零容差（切片边界判断 #7）", () => {
    const q0 = makeQuestion({ gold: { value: { value: 3 } } });
    expect(scoreCorrectness(q0, { value: node(3) }).correct).toBe(true);
    expect(scoreCorrectness(q0, { value: node(3.5) }).correct).toBe(false);
  });

  it("tolerance_rel：相对容差取 |rel*gold|", () => {
    const qr = makeQuestion({ gold: { value: { value: 100, tolerance_rel: 0.05 } } });
    expect(scoreCorrectness(qr, { value: node(104) }).correct).toBe(true);
    expect(scoreCorrectness(qr, { value: node(106) }).correct).toBe(false);
  });

  it("abs/rel 同时声明取更宽者", () => {
    const qb = makeQuestion({ gold: { value: { value: 100, tolerance_abs: 1, tolerance_rel: 0.05 } } });
    expect(scoreCorrectness(qb, { value: node(104) }).correct).toBe(true);
    expect(scoreCorrectness(qb, { value: node(101) }).correct).toBe(true);
  });
});

describe("scalar_enum / scalar_string", () => {
  it("规范化（trim+小写）后精确比对", () => {
    const q = makeQuestion({
      type: "scalar_enum",
      answer_schema: { "x-kind": "scalar_enum", type: "object", properties: { verdict: { type: "object" } }, required: ["verdict"] },
      gold: { verdict: { value: true } },
      gold_evidence: { verdict: [22] },
    });
    expect(scoreCorrectness(q, { verdict: node(true) }).correct).toBe(true);
    expect(scoreCorrectness(q, { verdict: node(false) }).correct).toBe(false);

    const qs = makeQuestion({
      answer_schema: { type: "object", properties: { qname: { type: "object" } }, required: ["qname"] },
      gold: { qname: { value: "Youtube.COM" } },
      gold_evidence: { qname: [19] },
    });
    expect(scoreCorrectness(qs, { qname: node("  youtube.com ") }).correct).toBe(true);
  });

  it("对象值标量（如五元组）走 deepEqual 比对（q-web-005 路径）", () => {
    const tuple = { proto: "tcp", src: "192.168.1.4", sport: 53124, dst: "142.250.74.14", dport: 443 };
    const q = makeQuestion({
      answer_schema: { type: "object", properties: { sess: { type: "object" } }, required: ["sess"] },
      gold: { sess: { value: tuple } },
      gold_evidence: { sess: [1] },
    });
    // 键序不同仍相等
    const reordered = { dport: 443, dst: tuple.dst, sport: tuple.sport, src: tuple.src, proto: "tcp" };
    expect(scoreCorrectness(q, { sess: node(reordered) }).correct).toBe(true);
    expect(scoreCorrectness(q, { sess: node({ ...tuple, dport: 444 }) }).correct).toBe(false);
  });
});

const TUPLE = (sport: number, proto = "tcp") => ({ proto, src: "192.168.1.4", sport, dst: "10.0.0.1", dport: 443 });

function setQuestion(mode: string): Question {
  return makeQuestion({
    type: "set",
    answer_schema: {
      "x-kind": "set",
      "x-match": mode,
      "x-element-key": "{proto}|{src}:{sport}>{dst}:{dport}",
      type: "object",
      properties: { top: { type: "array", items: { type: "object" } } },
      required: ["top"],
    },
    gold: { top: { value: [TUPLE(1), TUPLE(2), TUPLE(3)] } },
    gold_evidence: { top: {} },
  });
}

describe("set 三种模式", () => {
  it("unordered：顺序无关集合相等", () => {
    const q = setQuestion("unordered");
    expect(scoreCorrectness(q, { top: [node(TUPLE(3)), node(TUPLE(1)), node(TUPLE(2))] }).correct).toBe(true);
    expect(scoreCorrectness(q, { top: [node(TUPLE(1)), node(TUPLE(2))] }).correct).toBe(false);
    expect(scoreCorrectness(q, { top: [node(TUPLE(1)), node(TUPLE(2)), node(TUPLE(9))] }).correct).toBe(false);
  });

  it("ordered：序列完全一致才算对", () => {
    const q = setQuestion("ordered");
    expect(scoreCorrectness(q, { top: [node(TUPLE(1)), node(TUPLE(2)), node(TUPLE(3))] }).correct).toBe(true);
    expect(scoreCorrectness(q, { top: [node(TUPLE(3)), node(TUPLE(2)), node(TUPLE(1))] }).correct).toBe(false);
  });

  it("top_k_prefix：重合度部分分 + 名次错误单独记录", () => {
    const q = setQuestion("top_k_prefix");
    const full = scoreCorrectness(q, { top: [node(TUPLE(1)), node(TUPLE(2)), node(TUPLE(3))] });
    expect(full.correct).toBe(true);

    // 全中但名次错位：M1 仍算对（名次错误单列）
    const reordered = scoreCorrectness(q, { top: [node(TUPLE(2)), node(TUPLE(1)), node(TUPLE(3))] });
    expect(reordered.correct).toBe(true);
    expect(reordered.fields[0]?.rankErrors).toBe(2);

    // 部分重合：partial 落盘
    const partial = scoreCorrectness(q, { top: [node(TUPLE(1)), node(TUPLE(9)), node(TUPLE(3))] });
    expect(partial.correct).toBe(false);
    expect(partial.fields[0]?.partial).toBeCloseTo(2 / 3);
    expect(partial.fields[0]?.rankErrors).toBe(1);
  });
});

describe("record", () => {
  it("逐字段判定；主指标=全字段对", () => {
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
    const good = scoreCorrectness(q, { retr: node(3), hs_ms: node(71.5) });
    expect(good.correct).toBe(true);
    const half = scoreCorrectness(q, { retr: node(4), hs_ms: node(70) });
    expect(half.correct).toBe(false);
    expect(half.fields.map((f) => f.pass)).toEqual([false, true]);
  });
});
