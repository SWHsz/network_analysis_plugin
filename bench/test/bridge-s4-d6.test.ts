/**
 * S4 桥接冒烟（builder 侧 D6 树 → 真 from-card 函数 + 判分自检）。
 *
 * 与 bridge-from-card.test.ts 的 real-instances 组（bench 本地树）互补：本组直接
 * 读 pcap_builder 的 output/instances/ 全量语料树，抽样跑 buildQuestionEnvelope +
 * buildBenchGt + selfCheck（信封零错 / gold 必 correct / 错序必判负 / canary 双侧
 * 一致）+ SHA 三方对账。precheck_s4.py 以 S4_CELLS 环境变量指定抽样（"card/iN/tier"
 * 逗号分隔），不设则默认抽 3 类（batch1 synth / batch2 synth / real）。
 */
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildBenchGt, buildQuestionEnvelope, sha256File } from "../src/bridge/from-card.js";
import { INSTANCE_FIXTURE_RE } from "../src/bridge/instances.js";

const D6_ROOT = process.env.S4_D6_ROOT
  ?? "/Volumes/Data 1/pcap_benchmark/output/instances";

interface CellPick { card: string; inst: string; tier: string; cell: string }

function pickCells(): CellPick[] {
  const spec = process.env.S4_CELLS;
  if (spec) {
    return spec.split(",").map((s) => {
      const [card, inst, tier] = s.trim().split("/");
      return { card, inst, tier, cell: path.join(D6_ROOT, card, inst, tier, "synth-v1") };
    });
  }
  const picks: CellPick[] = [];
  const seen = new Set<string>();
  for (const cardDir of fs.readdirSync(D6_ROOT).sort()) {
    if (cardDir.startsWith("_")) continue;
    for (const inst of fs.readdirSync(path.join(D6_ROOT, cardDir)).sort()) {
      for (const tier of fs.readdirSync(path.join(D6_ROOT, cardDir, inst)).sort()) {
        const cell = path.join(D6_ROOT, cardDir, inst, tier, "synth-v1");
        if (!fs.existsSync(path.join(cell, "gold.json"))) continue;
        const num = Number(cardDir.replace(/\D/g, ""));
        const kind = fs.existsSync(path.join(cell, "resolved-card.json")) ? "real" : "synth";
        const batch = num <= 10 ? "batch1" : num <= 22 ? "batch2" : "batch3";
        const sig = `${kind}/${batch}`;
        if (seen.has(sig)) continue;
        seen.add(sig);
        picks.push({ card: cardDir, inst, tier, cell });
      }
    }
  }
  return picks.slice(0, 3);
}

describe("S4 D6 桥接冒烟", () => {
  const cells = pickCells();
  it("抽样非空（≥1 cell）", () => {
    expect(cells.length).toBeGreaterThanOrEqual(1);
  });
  for (const { card, inst, tier, cell } of cells) {
    const low = card.replace("Q-", "").toLowerCase();
    const fixture = `${low}-${inst}-${tier}`;
    it(`${card}/${inst}/${tier}: 桥接 + 判分自检全绿`, async () => {
      expect(INSTANCE_FIXTURE_RE.test(fixture)).toBe(true);
      const read = <T,>(p: string): T => JSON.parse(fs.readFileSync(p, "utf8")) as T;
      const bqEntry = read<Array<{ [k: string]: unknown }>>(path.join(cell, "questions.json"))[0]!;
      const gold = read<Parameters<typeof buildQuestionEnvelope>[0]["gold"]>(path.join(cell, "gold.json"));
      const bgt = read<Parameters<typeof buildBenchGt>[0]["bgt"]>(path.join(cell, "benchmark_gt.json"));
      const bq = bqEntry as unknown as Parameters<typeof buildQuestionEnvelope>[0]["bq"];

      const sha = sha256File(path.join(cell, "benchmark.pcap"));
      expect([bq.pcap_sha256, gold.pcap_sha256, bgt.pcap_sha256].every((x) => !x || x === sha)).toBe(true);

      const distractorTypes = (bgt.L2_injected_attacks ?? [])
        .filter((ev) => ev.source.startsWith("[distractor]"))
        .map((ev) => ev.attack_type);
      const q = buildQuestionEnvelope({ bq, gold, fixture, distractorTypes });
      const gt = buildBenchGt({ gold, bgt, fixture });
      const { selfCheck } = await import("../src/bridge/from-card.js");
      const result = await selfCheck(q, gt);
      expect(result.envelope_errors).toBe(0);
      expect(result.gold_answer_classification).toBe("correct");
      expect(result.reversed_chain_classification).toBe("wrong_answer");
      expect(result.canary_all_match).toBe(true);
    });
  }
});
