/**
 * T1 桥接转换器 round-trip 测试（S3 批）——桥接测试要有牙齿：
 *
 *   known-good（gold 合成答案，走 fenced 提取全管线）必须 correct；
 *   known-bad（错阶段序 / 错帧 / 伪造帧 / 错枚举值 / 非法枚举值）必须各按
 *   注册口径判负；canary 双侧一致；信封校验零错。
 *
 * hermetic 组不依赖任何真实构建产物；real-instances 组只在 T2 构建的实例
 * 存在时运行（对真实 bench-question/bench-gt/pcap 元数据做全链路回归）。
 */
import { describe, expect, it } from "vitest";
import {
  buildBenchGt,
  buildQuestionEnvelope,
  selfCheck,
  type BuildGt,
  type BuildGold,
  type BuildQuestion,
} from "../src/bridge/from-card.js";
import { isInstanceFixture, listInstanceFixtures } from "../src/bridge/instances.js";
import { loadGroundTruth, loadInstanceQuestion, type GroundTruth, type Question } from "../src/scorer/question.js";
import { scoreRun } from "../src/scorer/pipeline.js";

// ---- 合成 build 产物（逐字段对齐 pcap_builder build_from_card 的输出形态） ----

const ENUM = [
  "path_traversal", "c2_beacon", "volumetric_ddos", "file_upload_rce", "config_injection",
  "auth_bypass", "dns_cache_poisoning", "dns_tunneling_exfil", "smtp_relay_abuse",
  "port_scan", "rce", "data_exfil", "brute_force",
];

function synthBuild(): {
  bq: BuildQuestion;
  gold: BuildGold;
  bgt: BuildGt;
  distractorTypes: string[];
} {
  const bq = {
    question_id: "Q-S01-i1",
    card_id: "Q-S01",
    instance_seed: 1,
    symptom_text: "Ticket #1: the file portal intermittently returns HTTP 500 and once rendered garbled configuration text.",
    environment_card: "LAN 10.20.5.0/24; file portal 10.20.5.30; 3 intranet servers + employee endpoints; UTC.",
    attack_type_enum: ENUM,
    stage_definitions: ["recon", "successful_read"],
    answer_contract: { attack_type: ENUM, evidence_frames: "list<int>", attack_chain: "list<{stage: str, frames: list<int>}>" },
    pcap_file: "benchmark.pcap",
    pcap_sha256: "fake",
  };
  const gold = {
    question_id: "Q-S01-i1",
    card_id: "Q-S01",
    instance_seed: 1,
    attack_type: "path_traversal",
    evidence_frames: [101, 102, 103, 210, 211, 212],
    attack_chain: [
      { stage: "recon", frames: [101, 102, 103] },
      { stage: "successful_read", frames: [210, 211, 212] },
    ],
    distractor_frame_set: [301, 302],
    detection_basis: "traversal probes then successful arbitrary-file reads against a static file portal",
    generator_intent: "traversal probes (../ URL forms) then successful reads (/etc/passwd style bodies)",
    sampling_rule: { per_stage_cap: 10, per_source_cap: 3, global_cap: 60, rfc: "RFC-002" },
    replay_of: "CVE-2025-24513",
    pcap_file: "benchmark.pcap",
    pcap_sha256: "fake",
    total_frames: 100_000,
  };
  const bgt = {
    pcap_sha256: "fake",
    total_frames: 100_000,
    time_window: { start: 1_787_115_600.2, end: 1_787_116_000.8 },
    L2_injected_attacks: [
      {
        event_id: "E001",
        source: "card Q-S01 (synth)",
        attack_type: "path_traversal",
        key_frames: { recon: [101, 102, 103], successful_read: [210, 211, 212] },
        original_frame_mapping: Object.fromEntries(
          [101, 102, 103, 104, 210, 211, 212, 213].map((o, i) => [String(o), o + i]),
        ),
      },
      {
        event_id: "D001",
        source: "[distractor] rce",
        attack_type: "rce",
        key_frames: {} as Record<string, number[]>,
        original_frame_mapping: { "300": 301, "303": 302 },
      },
    ],
  };
  return { bq, gold, bgt, distractorTypes: ["rce"] };
}

function bridged(): { q: Question; gt: GroundTruth } {
  const { bq, gold, bgt, distractorTypes } = synthBuild();
  const q = buildQuestionEnvelope({ bq, gold, fixture: "s01-i1-r1", distractorTypes });
  const gt = buildBenchGt({ gold, bgt, fixture: "s01-i1-r1" });
  return { q, gt };
}

function fenced(obj: unknown): string {
  return "```json\n" + JSON.stringify(obj, null, 2) + "\n```";
}

function goldAnswerOf(q: Question): Record<string, unknown> {
  const chainGold = q.gold.attack_chain!.value as Array<{ stage: string }>;
  const evMap = q.gold_evidence.attack_chain as Record<string, number[]>;
  const keyOf = (s: { stage: string }) => JSON.stringify({ stage: s.stage });
  return {
    attack_type: { value: (q.gold.attack_type!.value as string), evidence: q.gold_evidence.attack_type as number[] },
    attack_chain: chainGold.map((s) => ({ value: { stage: s.stage }, evidence: evMap[keyOf(s)] })),
  };
}

describe("from-card 桥接（hermetic）", () => {
  it("信封校验零错 + gold 合成答案走完整管线必 correct", async () => {
    const { q, gt } = bridged();
    const mjs = await import("../src/schema/question-schema.mjs");
    expect(mjs.validateEnvelope(q, gt)).toEqual([]);
    const run = scoreRun(q, gt, fenced(goldAnswerOf(q)), "t");
    expect(run.classification, JSON.stringify(run.correctness ?? run.formatError)).toBe("correct");
    expect(run.evidence?.fields.every((f) => f.pass)).toBe(true);
  });

  it("known-bad：错阶段序必判 wrong_answer（M1 有序口径）", () => {
    const { q, gt } = bridged();
    const bad = goldAnswerOf(q);
    (bad.attack_chain as unknown[]).reverse();
    expect(scoreRun(q, gt, fenced(bad), "t").classification).toBe("wrong_answer");
  });

  it("known-bad：阶段帧集张冠李戴必挂 M3（correctness 过但 evidence_pass 挂）", () => {
    const { q, gt } = bridged();
    const bad = goldAnswerOf(q);
    const chain = bad.attack_chain as Array<{ value: { stage: string }; evidence: number[] }>;
    chain[0]!.evidence = [210, 211, 212]; // recon 引用 successful_read 的帧
    const run = scoreRun(q, gt, fenced(bad), "t");
    expect(run.classification).toBe("correct"); // 序列全等（值=阶段名）未被破坏
    const reconRow = run.evidence!.fields.find((f) => f.elementKey === JSON.stringify({ stage: "recon" }))!;
    expect(reconRow.pass).toBe(false);
    expect(reconRow.precision).toBe(0);
  });

  it("known-bad：混入无关/伪造帧必挂 M3（precision < 1）", () => {
    const { q, gt } = bridged();
    const bad = goldAnswerOf(q);
    (bad.attack_type as { evidence: number[] }).evidence = [101, 102, 103, 999_999];
    const run = scoreRun(q, gt, fenced(bad), "t");
    expect(run.evidence!.fields.find((f) => f.path === "attack_type")!.pass).toBe(false);
    expect(run.evidence!.fields.find((f) => f.path === "attack_type")!.breakdown.invalid).toEqual([999_999]);
  });

  it("known-bad：合法枚举内的错值判 wrong_answer；非法枚举值判 format_error", () => {
    const { q, gt } = bridged();
    const badEnum = goldAnswerOf(q);
    (badEnum.attack_type as { value: string }).value = "c2_beacon";
    expect(scoreRun(q, gt, fenced(badEnum), "t").classification).toBe("wrong_answer");
    const badFormat = goldAnswerOf(q);
    (badFormat.attack_type as { value: string }).value = "not_a_type";
    expect(scoreRun(q, gt, fenced(badFormat), "t").classification).toBe("format_error");
  });

  it("canary 双侧一致 + 自检（含错序判负）全绿", async () => {
    const { q, gt } = bridged();
    const result = await selfCheck(q, gt);
    expect(result.envelope_errors).toBe(0);
    expect(result.gold_answer_classification).toBe("correct");
    expect(result.reversed_chain_classification).toBe("wrong_answer");
    expect(result.canary_all_match).toBe(true);
  });

  it("bridge 不落盘即可全程函数级验证；instance fixture 命名解析一致", () => {
    expect(isInstanceFixture("s01-i1-r1")).toBe(true);
    expect(isInstanceFixture("s04-i12-r3")).toBe(true);
    expect(isInstanceFixture("q-web-001")).toBe(false);
    expect(isInstanceFixture("s01-r1")).toBe(false);
  });
});

describe("from-card 桥接（真实 T2 实例）", () => {
  const fixtures = listInstanceFixtures();
  it.skipIf(fixtures.length === 0)("实例注册表非空且命名合法", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(1);
    for (const f of fixtures) expect(isInstanceFixture(f)).toBe(true);
  });

  for (const fixture of fixtures) {
    it(`${fixture}: 信封/gt 自洽 + gold 必 correct + evidence 帧落在 pcap 元数据帧数内`, async () => {
      const q = loadInstanceQuestion(fixture);
      expect(q, "bench-question.json 存在").not.toBeNull();
      if (!q) return;
      const gt = loadGroundTruth(q);
      const mjs = await import("../src/schema/question-schema.mjs");
      expect(mjs.validateEnvelope(q, gt)).toEqual([]);
      const run = scoreRun(q, gt, fenced(goldAnswerOf(q)), "t");
      expect(run.classification, JSON.stringify(run.correctness ?? run.formatError)).toBe("correct");
      // evidence 帧 ⊆ [1, packet_count]（packet_count 来自 build_gt total_frames）
      for (const f of q.gold_evidence.attack_type as number[]) {
        expect(f).toBeLessThanOrEqual(gt.packet_count);
        expect(f).toBeGreaterThanOrEqual(1);
      }
    });
  }
});
