/**
 * T4 主实验 runner 骨架：4 模型 × 3 臂 × ρ 档（从 instances 目录自动发现 cell）× D9 预算。
 *
 *   tsx src/runner/run-matrix.ts --dry-run               # 零 LLM：矩阵展开 + 路径断言 + 规模账
 *   tsx src/runner/run-matrix.ts --model flash --arm bash --dry-run  # 子集 dry-run
 *   tsx src/runner/run-matrix.ts --model flash --arm bash --cell s01/i1/r1  # 真跑（需 LLM）
 *
 * D9 预算从 calibration-report 读（t32-tok16000 档），不硬编码。
 * Cell 清单从 bench/fixtures/instances/ 实际目录递归发现，不硬编码 210。
 */
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";

// ---- 配置 ----

const MODELS = ["deepseek-v4-flash", "deepseek-v4-pro", "glm-5.3", "kimi-k3"] as const;
const ARMS = ["bash-v0.2", "ast-v0.5", "sql-v0.1"] as const;
const INSTANCES_DIR = path.join(REPO_ROOT, "bench", "fixtures", "instances");
const CALIBRATION_PATH = path.join(REPO_ROOT, "bench", "out", "calibration-report.json");
const OUTPUT_DIR = path.join(REPO_ROOT, "bench", "out", "matrix");

interface Budget {
  maxTurns: number;
  maxTokens: number;
  timeoutMs: number;
}

/** D9 从 calibration-report 的 t32-tok16000 档读 */
async function loadD9Budget(): Promise<Budget> {
  try {
    const cal = JSON.parse(await readFile(CALIBRATION_PATH, "utf8"));
    const corners = (cal as { matrix?: { corners?: string[] } }).matrix?.corners ?? [];
    const d9Corner = corners.find((c) => c.startsWith("t32"));
    if (d9Corner) {
      const turns = Number(d9Corner.match(/t(\d+)/)?.[1] ?? 32);
      const tokens = Number(d9Corner.match(/tok(\d+)/)?.[1] ?? 16000);
      return { maxTurns: turns, maxTokens: tokens, timeoutMs: 720_000 };
    }
  } catch { /* fallback */ }
  // fallback：S3 终报钉死值
  return { maxTurns: 32, maxTokens: 16000, timeoutMs: 720_000 };
}

/** 递归发现 cell（s/i/r 三层） */
async function discoverCells(): Promise<string[]> {
  const cells: string[] = [];
  if (!existsSync(INSTANCES_DIR)) return cells;
  for (const s of (await readdir(INSTANCES_DIR, { withFileTypes: true })).filter((d) => d.isDirectory())) {
    for (const i of (await readdir(path.join(INSTANCES_DIR, s.name), { withFileTypes: true })).filter((d) => d.isDirectory())) {
      for (const r of (await readdir(path.join(INSTANCES_DIR, s.name, i.name), { withFileTypes: true })).filter((d) => d.isDirectory())) {
        // 每个 cell 目录须有 bench-question.json + benchmark.pcap
        const hasQ = existsSync(path.join(INSTANCES_DIR, s.name, i.name, r.name, "bench-question.json"));
        if (hasQ) cells.push(`${s.name}/${i.name}/${r.name}`);
      }
    }
  }
  return cells.sort();
}

interface MatrixCell {
  model: string;
  arm: string;
  cell: string;
  runsPerQuestion: number;
  questionFile: string;
  pcapFile: string;
  outputDir: string;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes("--dry-run");
  const modelFilter = argv.includes("--model") ? argv[argv.indexOf("--model") + 1] : "";
  const armFilter = argv.includes("--arm") ? argv[argv.indexOf("--arm") + 1] : "";
  const cellFilter = argv.includes("--cell") ? argv[argv.indexOf("--cell") + 1] : "";
  const runs = argv.includes("--runs") ? Number(argv[argv.indexOf("--runs") + 1]) || 3 : 3;

  const budget = await loadD9Budget();
  const allCells = await discoverCells();
  const models = MODELS.filter((m) => !modelFilter || m.includes(modelFilter));
  const arms = ARMS.filter((a) => !armFilter || a.startsWith(armFilter));
  const cells = allCells.filter((c) => !cellFilter || c.includes(cellFilter));

  console.log(`[run-matrix] D9 budget: ${JSON.stringify(budget)}`);
  console.log(`[run-matrix] models=${models.length} arms=${arms.length} cells=${cells.length} runs/cell=${runs}`);

  // 矩阵展开
  const matrix: MatrixCell[] = [];
  for (const model of models) {
    for (const arm of arms) {
      for (const cell of cells) {
        const [s, i, r] = cell.split("/");
        assertSafeBasename(s!, "scenario");
        assertSafeBasename(i!, "instance");
        assertSafeBasename(r!, "tier");
        assertSafeBasename(arm, "arm");
        const instDir = path.join(INSTANCES_DIR, s!, i!, r!);
        const outputDir = path.join(OUTPUT_DIR, model, arm, `${s}-${i}-${r}`);
        matrix.push({
          model,
          arm,
          cell,
          runsPerQuestion: runs,
          questionFile: path.join(instDir, "bench-question.json"),
          pcapFile: path.join(instDir, "benchmark.pcap"),
          outputDir,
        });
      }
    }
  }

  // 路径断言
  let pathErrors = 0;
  for (const m of matrix) {
    if (!existsSync(m.questionFile)) {
      console.error(`  ✗ missing question: ${m.questionFile}`);
      pathErrors++;
    }
    if (!existsSync(m.pcapFile)) {
      console.error(`  ✗ missing pcap: ${m.pcapFile}`);
      pathErrors++;
    }
    // 输出路径碰撞检测
    const dupes = matrix.filter((x) => x.outputDir === m.outputDir && x !== m);
    if (dupes.length > 0) {
      console.error(`  ✗ output collision: ${m.outputDir}`);
      pathErrors++;
    }
  }

  const totalRuns = matrix.length * runs;
  console.log(`\n[run-matrix] matrix: ${matrix.length} cells × ${runs} runs = ${totalRuns} total runs`);
  console.log(`  by model: ${models.map((m) => `${m}=${matrix.filter((x) => x.model === m).length * runs}`).join(", ")}`);
  console.log(`  by arm:   ${arms.map((a) => `${a}=${matrix.filter((x) => x.arm === a).length * runs}`).join(", ")}`);
  console.log(`  by tier:  ${[...new Set(cells.map((c) => c.split("/")[2]))].map((t) => `${t}=${matrix.filter((x) => x.cell.endsWith(t!)).length * runs}`).join(", ")}`);

  if (pathErrors > 0) {
    console.error(`\n✗ ${pathErrors} path errors`);
    return 1;
  }

  if (dryRun) {
    console.log(`\n✓ dry-run PASS：${matrix.length} cell × ${runs} run = ${totalRuns}，全部路径检查通过`);
    // 输出 dry-run 报告
    const report = {
      generated_at: new Date().toISOString(),
      budget,
      matrix_size: { cells: matrix.length, runs_per_cell: runs, total_runs: totalRuns },
      breakdown: {
        by_model: Object.fromEntries(models.map((m) => [m, matrix.filter((x) => x.model === m).length * runs])),
        by_arm: Object.fromEntries(arms.map((a) => [a, matrix.filter((x) => x.arm === a).length * runs])),
        by_tier: Object.fromEntries([...new Set(cells.map((c) => c.split("/")[2]))].map((t) => [t, matrix.filter((x) => x.cell.endsWith(t!)).length * runs])),
      },
      cells_discovered: allCells.length,
      cells_active: cells.length,
      path_errors: 0,
    };
    const reportDir = path.join(REPO_ROOT, "bench", "out");
    await mkdir(reportDir, { recursive: true });
    await writeFile(path.join(reportDir, "matrix-dryrun.json"), `${JSON.stringify(report, null, 2)}\n`);
    console.log(`dry-run report: bench/out/matrix-dryrun.json`);
    return 0;
  }

  // ---- 真跑模式（T1' 用）----
  console.error(`\n[run-matrix] 真跑模式未实现——T4 仅交付骨架与 dry-run（T1' 在此扩展）`);
  return 2;
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => { console.error("[run-matrix] fatal:", err); process.exitCode = 1; },
);
