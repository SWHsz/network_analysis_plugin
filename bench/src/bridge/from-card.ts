/**
 * T1 桥接转换器：pcap_builder 题卡实例产物 → bench 判分格式（S3 批）。
 *
 *   tsx src/bridge/from-card.ts --from bench/fixtures/instances/s01/i1/r1 --tier r1 [--overwrite]
 *
 * 输入（--from 目录 = build_from_card 的 output_dir，即实例目录）：
 *   questions.json / gold.json / benchmark_gt.json / benchmark.pcap
 * 输出（同目录，gitignore 覆盖路径——gt/gold 不入公开仓库）：
 *   bench-question.json  bench 信封题目（type=record；attack_type=scalar_enum + attack_chain=set(ordered)）
 *   bench-gt.json        bench GroundTruth 切片（packet_count/duration/facts/frames 轮廓）
 *   meta.json            桥接元数据（SHA/帧数/share/自检结果）
 *
 * 桥接映射（T1 设计基准）：
 *   attack_type（枚举）   → scalar_enum 节点；evidence 帧集对 gold.evidence_frames 做 M3
 *   attack_chain（有序）  → set(ordered)，每元素 {value:{stage}, evidence:frames}；
 *                           阶段序列全等（M1）+ 每阶段帧集 M3（元素粒度证据表）
 *   题面                  = symptom_text + environment_card 原文（症状驱动，不泄答案）
 *
 * 写盘边界：实例目录一次性写入，bench-* 产物已存在即拒绝（--overwrite 显式覆盖，
 * 且永不触碰 pcap_builder 侧产物）。自带判分器自检（金标准答案必 correct、错阶段序
 * 必判负、canary 双侧一致、信封校验零错），自检不过不落盘——桥接测试要有牙齿。
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertSafeBasename } from "../paths.js";
import { INSTANCE_FIXTURE_RE, instancesRoot } from "./instances.js";
import { canonicalElementKey } from "../scorer/elements.js";
import type { GroundTruth, Question } from "../scorer/question.js";
import type { JsonSchema } from "../scorer/schema.js";

export const BRIDGE_VERSION = "from-card v1 (S3, 2026-08-28)";

// ---- pcap_builder 产物类型（只声明桥接消费的字段） ----

export interface BuildQuestion {
  question_id: string;
  card_id: string;
  instance_seed: number;
  symptom_text: string;
  environment_card: string;
  attack_type_enum: string[];
  stage_definitions: string[];
  answer_contract: Record<string, unknown>;
  pcap_file: string;
  pcap_sha256: string;
}

export interface BuildGold {
  question_id: string;
  card_id: string;
  instance_seed: number;
  attack_type: string;
  evidence_frames: number[];
  attack_chain: Array<{ stage: string; frames: number[] }>;
  distractor_frame_set: number[];
  detection_basis: string;
  generator_intent: string;
  sampling_rule?: Record<string, unknown>;
  replay_of?: string;
  pcap_file: string;
  pcap_sha256: string;
  total_frames: number;
}

export interface BuildGtAttack {
  event_id: string;
  source: string;
  attack_type: string;
  key_frames?: Record<string, number[]>;
  original_frame_mapping?: Record<string, number>;
}

export interface BuildGt {
  pcap_sha256: string;
  total_frames: number;
  time_window: { start: number; end: number };
  L2_injected_attacks: BuildGtAttack[];
  [k: string]: unknown;
}

export interface BridgeMeta {
  bridge_version: string;
  fixture: string;
  card_id: string;
  instance_seed: number;
  tier: string;
  question_id: string;
  build_products: string[];
  derived_files: string[];
  pcap: string;
  pcap_sha256: string;
  pcap_bytes: number;
  total_frames: number;
  attack_frames: number;
  attack_share: number;
  distractor_frames: number;
  time_window: { start: number; end: number };
  duration_s: number;
  bridged_at: string;
  self_check: Record<string, unknown>;
}

function die(msg: string): never {
  throw new Error(`[from-card] ${msg}`);
}

function readJson<T>(p: string, label: string): T {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8")) as T;
  } catch (e) {
    return die(`${label} 读取/解析失败（${p}）：${(e as Error).message}`);
  }
}

export function sha256File(p: string): string {
  return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function factEvidenceSchema(): JsonSchema {
  return { type: "array", items: { type: "integer", minimum: 1 }, minItems: 1, uniqueItems: true };
}

/** 选 known_bad 的错值：优先卡面混淆项（distractor）的攻击类型，否则取枚举中任一非 gold 值 */
function pickWrongEnum(enumValues: string[], gold: string, distractorTypes: string[]): string {
  const inEnum = distractorTypes.filter((t) => enumValues.includes(t) && t !== gold);
  const wrong = inEnum.length > 0 ? inEnum : enumValues.filter((v) => v !== gold);
  if (wrong.length === 0) return die("attack_type_enum 无非 gold 值，无法构造 known_bad");
  return wrong[0]!;
}

export function buildQuestionEnvelope(args: {
  bq: BuildQuestion;
  gold: BuildGold;
  fixture: string;
  distractorTypes: string[];
}): Question {
  const { bq, gold, fixture, distractorTypes } = args;
  const stages = bq.stage_definitions;
  if (stages.length === 0) return die("卡面 stage_definitions 为空，无法构造 attack_chain 契约");
  const m = INSTANCE_FIXTURE_RE.exec(fixture);
  if (!m) return die(`fixture 名非法：${fixture}`);
  const capturePrefix = `bench/fixtures/instances/${m[1]}/i${m[2]}/${m[3]}`;

  const answerSchema: JsonSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    "x-kind": "record",
    type: "object",
    $defs: {
      attack_type_enum: { type: "string", enum: [...bq.attack_type_enum] },
      fact_evidence: factEvidenceSchema(),
      stage_node: {
        type: "object",
        properties: {
          value: {
            type: "object",
            properties: { stage: { type: "string", enum: [...stages] } },
            required: ["stage"],
            additionalProperties: false,
          },
          evidence: factEvidenceSchema(),
        },
        required: ["value", "evidence"],
        additionalProperties: false,
      },
    },
    properties: {
      attack_type: {
        "x-kind": "scalar_enum",
        type: "object",
        properties: {
          value: { $ref: "#/$defs/attack_type_enum" },
          evidence: { $ref: "#/$defs/fact_evidence" },
        },
        required: ["value", "evidence"],
        additionalProperties: false,
      },
      attack_chain: {
        "x-kind": "set",
        "x-match": "ordered",
        "x-element-key": "canonicalElementKey({stage}) —— 键序稳定 JSON",
        type: "array",
        items: { $ref: "#/$defs/stage_node" },
        minItems: stages.length,
        maxItems: stages.length,
        uniqueItems: true,
      },
    },
    required: ["attack_type", "attack_chain"],
    additionalProperties: false,
  };

  const chainValues = gold.attack_chain.map((s) => ({ stage: s.stage }));
  const goldEvidenceChain: Record<string, number[]> = {};
  for (const s of gold.attack_chain) goldEvidenceChain[canonicalElementKey({ stage: s.stage })] = s.frames;

  const questionText = [
    bq.symptom_text,
    "",
    `Environment card: ${bq.environment_card}`,
    "",
    "Investigate the packet capture and answer with two facts:",
    "1. attack_type — the single attack type from the schema enum that best explains the observed symptom; its evidence is the frame numbers of the request-response pairs that constitute the attack.",
    `2. attack_chain — the attack's stages as an ordered list. The capture contains exactly the ${stages.length} stages listed in the schema, one node each, in the order they occurred; each node's evidence is that stage's supporting frame numbers.`,
    "",
    'Every factual node carries {"value", "evidence":[frame numbers]}; evidence frames must be real frames of this capture.',
  ].join("\n");

  const badType = pickWrongEnum(bq.attack_type_enum, gold.attack_type, distractorTypes);

  return {
    question_id: `q-${fixture}`,
    version: 1,
    capture: {
      fixture,
      path: `${capturePrefix}/benchmark.pcap`,
      gt: `${capturePrefix}/bench-gt.json`,
    },
    type: "record",
    question: questionText,
    answer_schema: answerSchema,
    gold: {
      attack_type: { value: gold.attack_type },
      attack_chain: { value: chainValues },
    },
    gold_evidence: {
      attack_type: gold.evidence_frames,
      attack_chain: goldEvidenceChain,
    },
    gold_derivation: {
      gt_pointers: [
        "gold.json:attack_type",
        "gold.json:attack_chain",
        "benchmark_gt.json:L2_injected_attacks[*].key_frames",
      ],
      derivation:
        `由 build gold 直接映射：attack_type=${gold.attack_type}；attack_chain 按 gold.attack_chain 顺序展开为 ` +
        `元素键 ${Object.keys(goldEvidenceChain).join(", ")}，每阶段帧集即 M3 判分参照（M3 口径：precision=1 且 recall>0）。` +
        `检测依据（卡面）：${gold.detection_basis}`,
      tolerance_note: "枚举/阶段序列/帧集均为精确判分（规范化后全等），无数值容差",
      sampling_rule: gold.sampling_rule ?? null,
    },
    reference_solution: {
      steps: [
        { n: 1, tool: "traffic_open", input: "benchmark.pcap（实例目录）", expect: "确立 capture_id 与总体规模（背景为主，攻击为稀疏注入）" },
        { n: 2, tool: "traffic_http_timeline", input: "定位环境卡资产（portal）的异常 HTTP 突发", expect: "读出攻击请求簇（traversal 探测/成功读取）与时间顺序" },
        { n: 3, tool: "traffic_evidence", input: "对候选帧逐帧核验请求-响应对", expect: "确认每阶段的支撑帧号（攻击帧，非混淆项）" },
        { n: 4, tool: "（组答）", input: "—", expect: "attack_type 枚举判定 + attack_chain 按时间序组链，每节点带帧级证据" },
      ],
      bash_equivalent:
        "tshark -r benchmark.pcap -Y 'http && ip.addr==<portal_ip>' -T fields -e frame.number -e http.request.uri -e http.response.code  # 探测/读取请求按帧序分阶段",
      factors: { H: 3, C: 2, G: "large", X: 1, N: "high" },
      difficulty_derivation:
        "大背景（≥1e5 帧）中的稀疏攻击注入：S6（异常发现，信噪比驱动）+ S7（长程导航，大捕获多跳下钻）；" +
        "两阶段链的时间序判定 + 帧级证据 → D3 关联链",
    },
    tags: {
      protocols: ["http"],
      skill: ["S6", "S7"],
      difficulty: 3,
      difficulty_label: "D3",
      ir_coverage: "covered",
      corpus_layer: "L2",
      scenario_pack: "P2",
    },
    provenance: {
      source: "generator",
      generator: "pcap_builder synthesis.build_from_card",
      bridge: BRIDGE_VERSION,
      card_id: bq.card_id,
      instance_seed: bq.instance_seed,
      build_question_id: bq.question_id,
      replay_of: gold.replay_of ?? null,
    },
    canary: {
      known_good: {
        answer: {
          attack_type: { value: gold.attack_type, evidence: gold.evidence_frames },
          attack_chain: gold.attack_chain.map((s) => ({ value: { stage: s.stage }, evidence: s.frames })),
        },
        expect: { schema_valid: true, correctness: true, evidence_pass: true },
        note: "gold 直接构造：验证桥接映射的全链路正通道",
      },
      known_bad: {
        answer: {
          attack_type: { value: badType, evidence: gold.evidence_frames },
          attack_chain: gold.attack_chain.map((s) => ({ value: { stage: s.stage }, evidence: s.frames })),
        },
        error_form: "wrong_value",
        emulates: `把近失混淆项的攻击类型（${badType}）当成主攻击类型作答（类型对不上 gold，帧证据不动）`,
        expect: { schema_valid: true, correctness: false, evidence_pass: true },
      },
    },
  };
}

export function buildBenchGt(args: { gold: BuildGold; bgt: BuildGt; fixture: string }): GroundTruth {
  const { gold, bgt, fixture } = args;
  const stageFrames = new Set(gold.attack_chain.flatMap((s) => s.frames));
  const evidenceSet = new Set(gold.evidence_frames);
  const distractorSet = new Set(gold.distractor_frame_set);
  const attackFrames = new Set<number>();
  for (const ev of bgt.L2_injected_attacks ?? []) {
    if (ev.source.startsWith("[distractor]")) continue;
    for (const g of Object.values(ev.original_frame_mapping ?? {})) attackFrames.add(g);
  }

  // 帧轮廓（M3 等价/相关细分的索引）：kind 优先级 gold_evidence > attack_chain > distractor > attack；
  // conv：主攻击="attack"、混淆项="distractor"——同 conv 的非 gold 攻击帧 → related，混淆项 → irrelevant
  const profile = new Map<number, { kind: string; conv: string }>();
  const put = (frames: Iterable<number>, kind: string, conv: string): void => {
    for (const f of frames) if (!profile.has(f)) profile.set(f, { kind, conv });
  };
  put(evidenceSet, "gold_evidence", "attack");
  put([...stageFrames].filter((f) => !evidenceSet.has(f)), "attack_chain", "attack");
  put(distractorSet, "distractor", "distractor");
  put(attackFrames, "attack", "attack");

  const frames = [...profile.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([frame, p]) => ({ frame, kind: p.kind, conv: p.conv }));

  return {
    capture: fixture,
    detection_basis: "generator_intent",
    packet_count: bgt.total_frames ?? gold.total_frames,
    duration_ms: Math.max(0, Math.round((bgt.time_window.end - bgt.time_window.start) * 1000)),
    facts: {
      attack_type: gold.attack_type,
      attack_chain: gold.attack_chain,
      evidence_frames: gold.evidence_frames,
      distractor_frame_set: gold.distractor_frame_set,
      detection_basis: gold.detection_basis,
      generator_intent: gold.generator_intent,
      attack_frames_total: attackFrames.size,
      note: "元素粒度证据表见题目 gold_evidence.attack_chain（键 = canonicalElementKey({stage})）",
    },
    frames,
  };
}

/** 桥接自检：信封校验零错 + gold 合成答案必 correct + 错阶段序必判负 + canary 双侧一致 */
export async function selfCheck(q: Question, gt: GroundTruth): Promise<Record<string, unknown>> {
  const { scoreRun } = await import("../scorer/pipeline.js");
  const { metaEvalQuestion } = await import("../scorer/canary.js");
  const mjs = await import("../schema/question-schema.mjs");

  const envErrs = mjs.validateEnvelope(q, gt) as string[];
  if (envErrs.length > 0) return die(`信封校验失败：\n  ${envErrs.join("\n  ")}`);

  const goldAnswer = mjs.buildGoldAsAnswer(q) as Record<string, unknown>;
  const run = scoreRun(q, gt, `\`\`\`json\n${JSON.stringify(goldAnswer, null, 2)}\n\`\`\``, "bridge-self-check");
  if (run.classification !== "correct") {
    return die(`gold 合成答案未判 correct：${JSON.stringify(run.correctness)} / ${JSON.stringify(run.evidence)}`);
  }

  const reversed = JSON.parse(JSON.stringify(goldAnswer)) as Record<string, unknown>;
  (reversed.attack_chain as unknown[]).reverse();
  const runReversed = scoreRun(q, gt, `\`\`\`json\n${JSON.stringify(reversed, null, 2)}\n\`\`\``, "bridge-reversed-chain");
  if (runReversed.classification !== "wrong_answer") {
    return die("错阶段序答案未被正确判负（M1 有序口径失效）");
  }

  const canary = metaEvalQuestion(q, gt);
  const failed = canary.filter((c) => !c.match);
  if (failed.length > 0) return die(`canary 元评测不一致：${JSON.stringify(failed)}`);

  return {
    envelope_errors: 0,
    gold_answer_classification: run.classification,
    reversed_chain_classification: runReversed.classification,
    canary_checks: canary.length,
    canary_all_match: true,
  };
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const fromDir = flag("--from");
  const tier = flag("--tier");
  const overwrite = argv.includes("--overwrite");
  if (!fromDir || !tier) {
    console.error("用法：tsx src/bridge/from-card.ts --from <实例目录> --tier r<N> [--overwrite]");
    console.error("  <实例目录> = bench/fixtures/instances/<card>/i<seed>/<tier>（build_from_card 的 --out）");
    return 2;
  }
  assertSafeBasename(tier, "--tier");
  if (!/^r\d+$/.test(tier)) die(`--tier 须形如 r1/r2，实际 ${tier}`);

  const bqPath = path.join(fromDir, "questions.json");
  const goldPath = path.join(fromDir, "gold.json");
  const gtPath = path.join(fromDir, "benchmark_gt.json");
  const pcapPath = path.join(fromDir, "benchmark.pcap");
  for (const p of [bqPath, goldPath, gtPath, pcapPath]) {
    if (!fs.existsSync(p)) die(`build 产物缺失：${p}（--from 须为 build_from_card 的 output_dir）`);
  }
  const [bq] = readJson<BuildQuestion[]>(bqPath, "questions.json") ?? [];
  if (!bq) return die("questions.json 为空");
  const gold = readJson<BuildGold>(goldPath, "gold.json");
  const bgt = readJson<BuildGt>(gtPath, "benchmark_gt.json");

  const card = bq.card_id.replace(/^Q-/, "").toLowerCase();
  const fixture = `${card}-i${bq.instance_seed}-${tier}`;
  if (!INSTANCE_FIXTURE_RE.test(fixture)) die(`fixture 名非法：${fixture}`);

  const expectedDir = path.join(instancesRoot(), card, `i${bq.instance_seed}`, tier);
  if (path.resolve(expectedDir) !== path.resolve(fromDir)) {
    die(`--from 目录与实例目录约定不符：期望 ${expectedDir}，实际 ${fromDir}`);
  }

  const derived = ["bench-question.json", "bench-gt.json", "meta.json"];
  for (const name of derived) {
    if (fs.existsSync(path.join(fromDir, name)) && !overwrite) {
      die(`${name} 已存在（一次性写入；显式 --overwrite 才可覆盖）`);
    }
  }

  // SHA 三方对账：pcap 实算 = questions.json = gold.json = benchmark_gt.json
  const pcapSha = sha256File(pcapPath);
  for (const [label, declared] of [
    ["questions.json", bq.pcap_sha256],
    ["gold.json", gold.pcap_sha256],
    ["benchmark_gt.json", bgt.pcap_sha256],
  ] as const) {
    if (declared && declared !== pcapSha) {
      die(`SHA 不一致：${label} 声明 ${declared.slice(0, 12)}…，实算 ${pcapSha.slice(0, 12)}…`);
    }
  }

  const distractorTypes = (bgt.L2_injected_attacks ?? [])
    .filter((ev) => ev.source.startsWith("[distractor]"))
    .map((ev) => ev.attack_type);
  const q = buildQuestionEnvelope({ bq, gold, fixture, distractorTypes });
  const gt = buildBenchGt({ gold, bgt, fixture });
  const selfCheckResult = await selfCheck(q, gt);

  fs.writeFileSync(path.join(fromDir, "bench-question.json"), JSON.stringify(q, null, 2) + "\n");
  fs.writeFileSync(path.join(fromDir, "bench-gt.json"), JSON.stringify(gt, null, 2) + "\n");
  const totalFrames = bgt.total_frames ?? gold.total_frames;
  const attackFrames = new Set<number>();
  for (const ev of bgt.L2_injected_attacks ?? []) {
    if (ev.source.startsWith("[distractor]")) continue;
    for (const g of Object.values(ev.original_frame_mapping ?? {})) attackFrames.add(g);
  }
  const meta: BridgeMeta = {
    bridge_version: BRIDGE_VERSION,
    fixture,
    card_id: bq.card_id,
    instance_seed: bq.instance_seed,
    tier,
    question_id: q.question_id,
    build_products: ["questions.json", "gold.json", "benchmark_gt.json", "benchmark.pcap"],
    derived_files: derived,
    pcap: pcapPath,
    pcap_sha256: pcapSha,
    pcap_bytes: fs.statSync(pcapPath).size,
    total_frames: totalFrames,
    attack_frames: attackFrames.size,
    attack_share: attackFrames.size / Math.max(1, totalFrames),
    distractor_frames: gold.distractor_frame_set.length,
    time_window: bgt.time_window,
    duration_s: Math.round((bgt.time_window.end - bgt.time_window.start) * 100) / 100,
    bridged_at: new Date().toISOString(),
    self_check: selfCheckResult,
  };
  fs.writeFileSync(path.join(fromDir, "meta.json"), JSON.stringify(meta, null, 2) + "\n");

  console.log(
    `[from-card] ${fixture}: ${totalFrames} 帧，攻击 ${attackFrames.size} 帧（share ${(meta.attack_share * 100).toFixed(4)}%），自检全绿`,
  );
  console.log(`[from-card] 落盘：${derived.join(", ")}`);
  return 0;
}

// 直接执行时启动 CLI（被 vitest import 时不启动）
const isMain = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      console.error("[from-card] fatal:", err);
      process.exitCode = 1;
    },
  );
}
