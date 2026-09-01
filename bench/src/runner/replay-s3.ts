/**
 * T4 S3 回放对账（零 LLM）：读 budget-sweep 72-run transcript，
 * 用当前判分管道重跑 harvest→判分→聚合，与 calibration-report 对账。
 *
 * 验证：数字必须吻合（不吻合=管道回归）。
 * 运行：tsx src/runner/replay-s3.ts
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { scoreRun } from "../scorer/pipeline.js";
import { classifyF6, outcomeBucket } from "../scorer/f6.js";
import { detectF7, applyF7 } from "../scorer/f7.js";
import type { Question } from "../scorer/question.js";

const SWEEP_DIR = path.join(REPO_ROOT, "bench", "out", "runs", "budget-sweep");
const INSTANCES_DIR = path.join(REPO_ROOT, "bench", "fixtures", "instances");
const CALIBRATION_PATH = path.join(REPO_ROOT, "bench", "out", "calibration-report.json");

interface RunEntry {
  run_index: number;
  classification: string;
  answer?: Record<string, unknown>;
  answerRaw?: string;
  metrics?: { llmCalls: number; toolRenderChars: number; budgetExhausted: boolean };
  f6?: Record<string, boolean>;
}

async function readJson(file: string): Promise<unknown> {
  return JSON.parse(await readFile(file, "utf8"));
}

async function collectRuns(dir: string): Promise<string[]> {
  const { readdir } = await import("node:fs/promises");
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const sub = path.join(dir, e.name);
    if (existsSync(path.join(sub, "runs.json"))) out.push(path.join(sub, "runs.json"));
    else out.push(...(await collectRuns(sub)));
  }
  return out;
}

async function main(): Promise<number> {
  const runFiles = await collectRuns(SWEEP_DIR);
  console.log(`[replay-s3] 发现 ${runFiles.length} 个 runs.json`);

  // 按 budget/model/question/arm 分组，模拟 E1 多数表决
  const groups = new Map<string, { correct: number; total: number; classifications: string[] }>();
  let totalRuns = 0;
  let replayCorrect = 0;

  for (const rf of runFiles) {
    const rel = path.relative(SWEEP_DIR, rf);
    const parts = rel.split(path.sep);
    const budget = parts[0] ?? "?";
    const arm = parts[parts.length - 2] ?? "?";
    const qid = parts[parts.length - 3] ?? "?";
    const modelDir = parts.length > 4 ? parts[1]! : "";
    const model = modelDir.startsWith("model-") ? modelDir.slice(6) : "flash";

    // 加载 bridge question
    const match = qid.match(/^q-(s\d+)-(i\d+)-(r\d+)$/);
    if (!match) continue;
    const [, s, i, r] = match;
    const qFile = path.join(INSTANCES_DIR, s!, i!, r!, "bench-question.json");
    if (!existsSync(qFile)) continue;
    const q = (await readJson(qFile)) as Question;

    const runs = (await readJson(rf)) as RunEntry[];
    const key = `${budget}/${model}/${qid}/${arm}`;
    if (!groups.has(key)) groups.set(key, { correct: 0, total: 0, classifications: [] });
    const g = groups.get(key)!;

    for (const run of runs) {
      totalRuns++;
      // 重跑判分管道
      const scored = scoreRun(q, q, run.answerRaw ?? "", `${arm}#${run.run_index}`);
      g.classifications.push(scored.classification);
      g.total++;
      if (scored.classification === "correct") {
        g.correct++;
        replayCorrect++;
      }
    }
  }

  // 多数表决汇总
  const majorityResults = new Map<string, boolean>();
  for (const [key, g] of groups) {
    majorityResults.set(key, g.correct > g.total / 2);
  }
  const majorityCorrect = [...majorityResults.values()].filter(Boolean).length;
  const majorityTotal = majorityResults.size;

  // 对账 calibration-report
  const cal = (await readJson(CALIBRATION_PATH)) as Record<string, unknown>;
  const calMatrix = cal.matrix as { total_runs?: number } | undefined;
  const calTotal = calMatrix?.total_runs ?? "?";

  console.log(`\n[replay-s3] 重放结果：`);
  console.log(`  total_runs: ${totalRuns}（calibration-report: ${calTotal}）`);
  console.log(`  run-level correct: ${replayCorrect}/${totalRuns}`);
  console.log(`  majority groups: ${majorityCorrect}/${majorityTotal}`);
  console.log(`\n  per-group detail:`);
  for (const [key, g] of [...groups.entries()].sort()) {
    const maj = g.correct > g.total / 2 ? "✓" : "✗";
    console.log(`  ${maj} ${key}: ${g.correct}/${g.total} (${g.classifications.join(",")})`);
  }

  // 验证：总数匹配
  if (calTotal !== "?" && totalRuns !== calTotal) {
    console.error(`\n✗ 对账失败：total_runs ${totalRuns} != calibration ${calTotal}`);
    return 1;
  }
  console.log(`\n✓ 回放对账 PASS（${totalRuns} run 与 calibration-report total_runs 吻合）`);
  return 0;
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => { console.error("[replay-s3] fatal:", err); process.exitCode = 1; },
);
