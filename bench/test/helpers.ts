/** 测试辅助：构造最小合法 Question（字段按 RFC-002 §3） */
import type { JsonSchema } from "../src/scorer/schema.js";
import type { GroundTruth, Question } from "../src/scorer/question.js";

export function makeQuestion(overrides: Partial<Question> & { question_id?: string } = {}): Question {
  const answer_schema: JsonSchema = overrides.answer_schema ?? {
    "x-kind": "scalar_number",
    type: "object",
    properties: {
      value: {
        type: "object",
        properties: {
          value: { type: "number", minimum: 0 },
          evidence: { type: "array", items: { type: "integer", minimum: 1 }, minItems: 1, uniqueItems: true },
        },
        required: ["value", "evidence"],
        additionalProperties: false,
      },
    },
    required: ["value"],
    additionalProperties: false,
  };
  return {
    question_id: "q-test-001",
    version: 1,
    capture: { fixture: "web-session", path: "fixtures/web-session.pcap", gt: "ground_truth/web-session.gt.json" },
    type: "record",
    question: "测试题面：这是一个用于单元测试的最小题目对象。",
    answer_schema,
    gold: { value: { value: 3 } },
    gold_evidence: { value: [8, 11, 14] },
    gold_derivation: {},
    reference_solution: {},
    tags: {
      protocols: ["tcp"],
      skill: ["S2"],
      difficulty: 1,
      difficulty_label: "D1",
      ir_coverage: "covered",
      corpus_layer: "L1",
      scenario_pack: "P1",
    },
    provenance: { source: "generator" },
    canary: {
      known_good: {
        answer: { value: { value: 3, evidence: [8] } },
        expect: { schema_valid: true, correctness: true, evidence_pass: true },
      },
      known_bad: {
        answer: { value: { value: 4, evidence: [8] } },
        error_form: "wrong_value",
        emulates: "测试用：值错形态",
        expect: { schema_valid: true, correctness: false, evidence_pass: true },
      },
    },
    ...overrides,
  } as Question;
}

export function makeGt(overrides: Partial<GroundTruth> = {}): GroundTruth {
  return {
    capture: "web-session",
    detection_basis: "generator_intent",
    packet_count: 32,
    duration_ms: 1600,
    facts: {},
    frames: [],
    ...overrides,
  };
}

export function fenced(obj: unknown): string {
  return "```json\n" + JSON.stringify(obj, null, 2) + "\n```";
}
