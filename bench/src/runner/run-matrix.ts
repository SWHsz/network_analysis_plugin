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
import { existsSync, readFileSync } from "node:fs";
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

/**
 * Envelope 预算（C 方案 2026-09-01）：默认宽 ceiling = D9 × 2 = 64 turns / 32k tokens / 1440s。
 * 优先从 calibration-report 的 D9 档推导 ×2；fallback 硬编码。
 * 支持逐档覆盖（r3 单点上调用）。
 */
export function loadEnvelopeBudget(): Budget & { envelope_source: string; overrides: Record<string, Partial<Budget>> } {
  const base: Budget = { maxTurns: 64, maxTokens: 32_000, timeoutMs: 1_440_000 };
  try {
    const cal = JSON.parse(readFileSync(CALIBRATION_PATH, "utf8"));
    const corners = (cal as { matrix?: { corners?: string[] } }).matrix?.corners ?? [];
    const d9 = corners.find((c) => c.startsWith("t32"));
    if (d9) {
      const t = Number(d9.match(/t(\d+)/)?.[1] ?? 32);
      const tok = Number(d9.match(/tok(\d+)/)?.[1] ?? 16000);
      return {
        maxTurns: t * 2, maxTokens: tok * 2, timeoutMs: 720_000 * 2,
        envelope_source: `calibration ${d9} × 2 (C 方案)`,
        overrides: { r3: { maxTurns: 128, maxTokens: 64_000, timeoutMs: 2_880_000 } },
      };
    }
  } catch { /* fallback below */ }
  return {
    ...base,
    envelope_source: "fallback (C 方案硬编码)",
    overrides: { r3: { maxTurns: 128, maxTokens: 64_000, timeoutMs: 2_880_000 } },
  };
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

  const budget = loadEnvelopeBudget();
  const allCells = await discoverCells();
  const models = MODELS.filter((m) => !modelFilter || m.includes(modelFilter));
  const arms = ARMS.filter((a) => !armFilter || a.startsWith(armFilter));
  const cells = allCells.filter((c) => !cellFilter || c.includes(cellFilter));

  console.log(`[run-matrix] envelope: ${JSON.stringify({ maxTurns: budget.maxTurns, maxTokens: budget.maxTokens, timeoutMs: budget.timeoutMs })} (${budget.envelope_source})`);
  console.log(`[run-matrix] models=${models.length} arms=${arms.length} cells=${cells.length} (discovered=${allCells.length}) runs/cell=${runs}`);

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
    // Envelope 2× 断言：新预算必须 ≥ 旧 D9 × 2
    const expectedMin = { turns: 64, tokens: 32_000, timeoutMs: 1_440_000 };
    if (budget.maxTurns < expectedMin.turns || budget.maxTokens < expectedMin.tokens || budget.timeoutMs < expectedMin.timeoutMs) {
      console.error(`✗ envelope 断言失败：budget ${JSON.stringify(budget)} < C 方案最低 ${JSON.stringify(expectedMin)}`);
      return 1;
    }
    console.log(`  envelope 2× 断言: PASS (≥${expectedMin.turns}t/${expectedMin.tokens}tok/${expectedMin.timeoutMs / 1000}s)`);

    console.log(`\n✓ dry-run PASS：${matrix.length} cell × ${runs} run = ${totalRuns}，全部路径检查通过`);
    const report = {
      generated_at: new Date().toISOString(),
      envelope: {
        maxTurns: budget.maxTurns, maxTokens: budget.maxTokens, timeoutMs: budget.timeoutMs,
        source: budget.envelope_source, overrides: budget.overrides,
      },
      matrix_size: { cells: matrix.length, runs_per_cell: runs, total_runs: totalRuns },
      breakdown: {
        by_model: Object.fromEntries(models.map((m) => [m, matrix.filter((x) => x.model === m).length * runs])),
        by_arm: Object.fromEntries(arms.map((a) => [a, matrix.filter((x) => x.arm === a).length * runs])),
        by_tier: Object.fromEntries([...new Set(cells.map((c) => c.split("/")[2]))].map((t) => [t, matrix.filter((x) => x.cell.endsWith(t!)).length * runs])),
      },
      cells_discovered: allCells.length,
      cells_active: cells.length,
      path_errors: 0,
      breaker: { k: 3, n: 5, source: "breaker-replay.json 定档（26de970），锁定不可调" },
    };
    const reportDir = path.join(REPO_ROOT, "bench", "out");
    await mkdir(reportDir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    await writeFile(path.join(reportDir, `matrix-dryrun-${stamp}.json`), `${JSON.stringify(report, null, 2)}\n`);
    // 也写 latest（供 CI 消费），但旧报告不覆盖
    await writeFile(path.join(reportDir, `matrix-dryrun-latest.json`), `${JSON.stringify(report, null, 2)}\n`);
    console.log(`dry-run report: bench/out/matrix-dryrun-${stamp}.json`);
    return 0;
  }

  // ---- 真跑模式（Lane A vLLM / Lane B zen）----
  // 熔断参数锁定（K=3/N=5，breaker-replay.json 定档 26de970，不可调）
  const BREAKER_PARAMS = { k: 3, n: 5 } as const;

  // Provider 路由：--provider vllm（Lane A）或 --provider opengo2（Lane B）
  const providerFlag = argv.includes("--provider") ? argv[argv.indexOf("--provider") + 1] : "opengo2";
  if (providerFlag === "vllm") {
    const { loadVllmConfig, pingVllm } = await import("./vllm-adapter.js");
    const vllmConfig = loadVllmConfig();
    if (!vllmConfig) {
      console.error(`[run-matrix] vLLM 未配置（需 VLLM_BASE_URL + VLLM_MODEL 环境变量）`);
      return 3;
    }
    const pingErr = await pingVllm(vllmConfig);
    if (pingErr) {
      console.error(`[run-matrix] vLLM 预检失败：${pingErr}`);
      return 3;
    }
    console.log(`[run-matrix] vLLM provider: ${vllmConfig.baseURL} model=${vllmConfig.model}`);
    console.error(`[run-matrix] 真跑模式（vLLM lane）待 Lane A pilot 发射——骨架已就绪`);
    return 2;
  }

  console.error(`\n[run-matrix] 真跑模式（zen lane）待 Lane B 额度解锁——骨架已就绪`);
  console.error(`  熔断参数已锁定: K=${BREAKER_PARAMS.k}/N=${BREAKER_PARAMS.n}（breaker-replay 定档）`);
  console.error(`  envelope: ${budget.maxTurns}t/${budget.maxTokens}tok/${budget.timeoutMs / 1000}s`);
  return 2;
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => { console.error("[run-matrix] fatal:", err); process.exitCode = 1; },
);
