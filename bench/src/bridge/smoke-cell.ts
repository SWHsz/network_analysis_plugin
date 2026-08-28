/**
 * S4 预检的桥接冒烟 runner：对任意 build 产物目录跑真 from-card 转换函数 + 判分自检。
 *
 *   tsx src/bridge/smoke-cell.ts --from <cell 目录> --fixture <实例 fixture 名>
 *
 * 与 from-card.ts CLI 的差别：只读冒烟——不校验 bench 实例根路径、不落盘任何文件；
 * 复用同一套 buildQuestionEnvelope / buildBenchGt / selfCheck（含信封校验、gold 必
 * correct、错序必判负、canary 双侧一致）。输出一行 JSON verdict 供预检脚本消费。
 */
import fs from "node:fs";
import path from "node:path";
import { buildBenchGt, buildQuestionEnvelope, selfCheck, sha256File } from "./from-card.js";
import { INSTANCE_FIXTURE_RE } from "./instances.js";

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const from = flag("--from");
  const fixture = flag("--fixture");
  if (!from || !fixture || !INSTANCE_FIXTURE_RE.test(fixture)) {
    console.error("用法：tsx src/bridge/smoke-cell.ts --from <cell 目录> --fixture <card-i<N>-r<T>>");
    return 2;
  }
  const read = <T>(p: string, label: string): T =>
    JSON.parse(fs.readFileSync(p, "utf8")) as T;
  const bq = read<{ [k: string]: unknown } & { card_id: string; instance_seed: number }>(
    path.join(from, "questions.json"), "questions.json");
  const [bqEntry] = read<Array<{ [k: string]: unknown }>>(path.join(from, "questions.json"), "questions");
  void bq;
  const gold = read<Parameters<typeof buildQuestionEnvelope>[0]["gold"]>(
    path.join(from, "gold.json"), "gold.json");
  const bgt = read<Parameters<typeof buildBenchGt>[0]["bgt"]>(
    path.join(from, "benchmark_gt.json"), "benchmark_gt.json");
  const bqTyped = bqEntry as unknown as Parameters<typeof buildQuestionEnvelope>[0]["bq"];

  // SHA 对账（与 CLI 同口径）
  const sha = sha256File(path.join(from, "benchmark.pcap"));
  const shaOk = [bqTyped.pcap_sha256, gold.pcap_sha256, bgt.pcap_sha256].every(
    (s) => !s || s === sha);

  const distractorTypes = (bgt.L2_injected_attacks ?? [])
    .filter((ev) => ev.source.startsWith("[distractor]"))
    .map((ev) => ev.attack_type);
  const q = buildQuestionEnvelope({ bq: bqTyped, gold, fixture, distractorTypes });
  const gt = buildBenchGt({ gold, bgt, fixture });
  const selfCheckResult = await selfCheck(q, gt);

  const verdict = {
    fixture,
    sha_consistent: shaOk,
    gold_classification: selfCheckResult.gold_answer_classification,
    reversed_chain_classification: selfCheckResult.reversed_chain_classification,
    canary_all_match: selfCheckResult.canary_all_match,
    envelope_errors: selfCheckResult.envelope_errors,
    self_check: selfCheckResult,
  };
  console.log(JSON.stringify(verdict));
  return shaOk && verdict.gold_classification === "correct" &&
      verdict.reversed_chain_classification === "wrong_answer" &&
      verdict.canary_all_match === true
    ? 0
    : 1;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[smoke-cell] fatal:", err);
    process.exitCode = 1;
  },
);
