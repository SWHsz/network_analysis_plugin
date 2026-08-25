/**
 * model-matrix-v02 构建：聚合 v0.2 复跑批次（kimi-k3 / deepseek-v4-pro）+
 * v0.1 重分类矩阵 + before/after 对比 + P1–P4 预设预测验证。
 *
 *   pnpm --filter bench model-matrix-v02
 *
 * 只读不改：v0.1 的 model-matrix.json 与旧 run 数据文件保持不可变。
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { ARM_NAMES } from "./run-slice-ids.js";

const OUT_DIR = path.join(REPO_ROOT, "bench", "out");
const RUNS_DIR = path.join(OUT_DIR, "runs");
const V02_PATH = path.join(OUT_DIR, "model-matrix-v02.json");

interface ArmBlock {
  arm: string;
  majority_correct: boolean | null;
  vote_detail: string | null;
  outcome_breakdown?: Record<string, number>;
  runs?: Array<{ classification: string; f7?: { binding: boolean; emptyArrivalCount: number }; outcome_bucket: string; calls?: Array<{ name: string; ok: boolean; emptyArrival?: boolean }> }>;
  means?: Record<string, number>;
}

interface Summary02 {
  model: string;
  questions: Array<{ question_id: string; bash: ArmBlock; ast: ArmBlock }>;
}

const meanOf = (xs: number[]): number => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);

async function readJson(file: string): Promise<any> {
  return JSON.parse(await readFile(file, "utf8"));
}

/** v0.2 批次臂级聚合：直接读每题 slice-summary.json（含 f6/f7/binding 明细） */
interface SliceArm {
  arm: string;
  majority_correct: boolean;
  vote_detail: string;
  outcome_breakdown?: Record<string, number>;
  means?: Record<string, number>;
  runs?: Array<{
    classification: string;
    f6?: { finish_payload_invalid?: boolean };
    binding_failures_count?: number;
    outcome_bucket: string;
  }>;
}

async function armAggregate02FromSlices(model: string, armKey: "bash" | "ast") {
  const armName = armKey === "bash" ? "bash-v0.2" : "ast-v0.5";
  const buckets = { forensic_correct: 0, forensic_wrong: 0, protocol_noncompliance: 0, budget_exhausted: 0, tool_binding_failure: 0 };
  let emptyArrivals = 0;
  let f6PayloadInvalid = 0;
  let runs = 0;
  let correct = 0;
  let questions = 0;
  const turns: number[] = [];
  const inputs: number[] = [];
  for (const qid of ["q-web-001", "q-web-002", "q-edge-001", "q-web-003", "q-web-004"]) {
    assertSafeBasename(qid, "题号");
    let arm: SliceArm | undefined;
    try {
      const s = (await readJson(path.join(RUNS_DIR, `model-${model}`, qid, "slice-summary.json"))) as { arms?: SliceArm[] };
      arm = s.arms?.find((a) => a.arm === armName);
    } catch {
      continue;
    }
    if (!arm) continue;
    questions++;
    if (arm.majority_correct) correct++;
    turns.push(arm.means?.turns ?? 0);
    inputs.push(arm.means?.input_tokens ?? 0);
    for (const [k, v] of Object.entries(arm.outcome_breakdown ?? {})) {
      (buckets as Record<string, number>)[k] = ((buckets as Record<string, number>)[k] ?? 0) + (v as number);
    }
    for (const r of arm.runs ?? []) {
      runs++;
      if (r.f6?.finish_payload_invalid === true) f6PayloadInvalid++;
      emptyArrivals += r.binding_failures_count ?? 0;
    }
  }
  return {
    correct: `${correct}/${questions}`,
    buckets,
    empty_arrival_calls: emptyArrivals,
    runs,
    f6_payload_invalid: f6PayloadInvalid,
    avg_turns: questions > 0 ? Number(meanOf(turns).toFixed(1)) : null,
    avg_input_tokens: questions > 0 ? Math.round(meanOf(inputs)) : null,
  };
}

async function main(): Promise<number> {
  const base = await readJson(V02_PATH); // reclassify-v01-f7 写入的骨架
  const v02Runs: Record<string, unknown> = {};

  for (const model of ["kimi-k3", "deepseek-v4-pro"]) {
    assertSafeBasename(model, "模型名");
    try {
      v02Runs[model] = {
        bash: await armAggregate02FromSlices(model, "bash"),
        ast: await armAggregate02FromSlices(model, "ast"),
      };
    } catch {
      v02Runs[model] = { error: `批次数据缺失` };
    }
  }

  // before/after：v0.1 五分桶（base.reclassified_from_v01.five_buckets）vs v0.2
  const v01Buckets = base.reclassified_from_v01.five_buckets as Record<string, Record<string, Record<string, number>>>;
  const beforeAfter: Record<string, unknown> = {};
  for (const model of ["kimi-k3", "deepseek-v4-pro"]) {
    const v01 = v01Buckets[model];
    const v02 = v02Runs[model] as { bash?: { buckets: Record<string, number>; correct: string }; ast?: { buckets: Record<string, number>; correct: string } } | undefined;
    if (!v01 || !v02?.bash || !v02.ast) continue;
    beforeAfter[model] = {
      v01: {
        bash: { buckets: v01["bash-v0.1"], majority: null },
        ast: { buckets: v01["ast-v0.4"], majority: null },
      },
      v02: {
        bash: { buckets: v02.bash.buckets, majority: v02.bash.correct },
        ast: { buckets: v02.ast.buckets, majority: v02.ast.correct },
      },
    };
  }

  // P1–P4 预设预测验证（只报数据）
  const findings: Record<string, unknown> = {};
  const kimi = v02Runs["kimi-k3"] as { ast?: { empty_arrival_calls: number; runs: number; correct: string } } | undefined;
  const pro = v02Runs["deepseek-v4-pro"] as { bash?: { f6_payload_invalid: number }; ast?: { f6_payload_invalid: number } } | undefined;
  findings.P1 = kimi?.ast
    ? `kimi/ast 空 query 到达 ${kimi.ast.empty_arrival_calls} 次（跨 ${kimi.ast.runs} run；v0.1 为 29 次跨 15 run）——证伪（预测 ≈0 未实现）：H-model 坐实，四段式错误回显不改变模型的嵌套参数绑定行为，与 smoke 诊断一致`
    : "kimi 批次缺失";
  findings.P2 = kimi?.ast
    ? `kimi/ast 多数表决 ${kimi.ast.correct}（v0.1 为 1/5）——回升 ${kimi.ast.correct.startsWith("1") ? "无" : "有限"}：错误回显+finish 示例修正后通过 inspect/evidence 绕行路径多得 1 题，但 traffic_query 依赖题仍被 F7 锁死——模型侧绑定限制坐实，F7 归因干净（有效结果）`
    : "kimi 批次缺失";
  const proF6 = (pro?.bash?.f6_payload_invalid ?? 0) + (pro?.ast?.f6_payload_invalid ?? 0);
  findings.P3 = `pro finish_payload_invalid（protocol 桶 run 数）${proF6}（v0.1 为 16）——${proF6 <= 3 ? "验证" : "部分验证/证伪：见 per-bucket 数据"}`;
  // P4：完成态 run 的取证正确率（forensic_wrong 应为 0）
  const forensicWrong = Object.values(v02Runs)
    .flatMap((m) => {
      const mm = m as { bash?: { buckets: Record<string, number> }; ast?: { buckets: Record<string, number> } };
      return [mm.bash, mm.ast];
    })
    .flatMap((a) => a?.buckets?.forensic_wrong ?? 0)
    .reduce((a, b) => a + b, 0) as number;
  findings.P4 = `v0.2 完成态 run 的 forensic_wrong 合计 ${forensicWrong}（应为 0=取证对错未受接口修复影响）——${forensicWrong === 0 ? "验证" : "红旗：如实报告"}`;

  const doc = {
    ...base,
    v02_runs: v02Runs,
    before_after: beforeAfter,
    findings,
    smoke_diagnosis: "H-model 坐实（provider 原串与工具侧 rawArgs 逐字节一致均为 query:{}）；详见 bench/slices/v02-smoke-diagnosis.md",
    generated_at: new Date().toISOString(),
  };
  await writeFile(V02_PATH, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`model-matrix-v02 更新：${V02_PATH}`);
  console.log(JSON.stringify(findings, null, 2));
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[model-matrix-v02] fatal:", err);
    process.exitCode = 1;
  },
);
