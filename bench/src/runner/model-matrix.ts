/**
 * 多模型矩阵构建：聚合基线（deepseek-v4-flash）与各 --model 批次的 all-summary，
 * 输出 bench/out/model-matrix.json（findings 只报数据，不硬造解释）。
 *
 *   pnpm --filter bench model-matrix
 */
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { DEFAULT_MODEL } from "./llm.js";
import { SLICE_QUESTION_IDS } from "./run-slice-ids.js";

const OUT_DIR = path.join(REPO_ROOT, "bench", "out");
const RUNS_DIR = path.join(OUT_DIR, "runs");
const MATRIX_PATH = path.join(OUT_DIR, "model-matrix.json");

interface ArmBlock {
  majority_correct: boolean | null;
  outcome_breakdown?: Record<string, number> | null;
  avg_input_tokens: number | null;
  avg_turns: number | null;
  avg_tool_render_chars: number | null;
  avg_interface_tokens: number | null;
}

interface ModelSummary {
  model: string;
  routing_error?: boolean;
  questions: Array<{ question_id: string; bash: ArmBlock; ast: ArmBlock }>;
  summary: { interface_tax_avg: number | null; [k: string]: unknown };
}

const meanOf = (xs: number[]): number => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);

function armAggregate(questions: ModelSummary["questions"], arm: "bash" | "ast"): Record<string, unknown> {
  const perQ = questions.map((x) => x[arm]).filter((x) => x.majority_correct !== null);
  const correct = perQ.filter((x) => x.majority_correct === true).length;
  const breakdown = { forensic_correct: 0, forensic_wrong: 0, protocol_noncompliance: 0, budget_exhausted: 0 };
  for (const x of perQ) {
    for (const k of Object.keys(breakdown) as Array<keyof typeof breakdown>) {
      breakdown[k] += x.outcome_breakdown?.[k] ?? 0;
    }
  }
  const avg = (f: (x: ArmBlock) => number | null): number | null => {
    const v = perQ.map(f).filter((x): x is number => x !== null);
    return v.length === 0 ? null : Math.round(meanOf(v));
  };
  return {
    correct: `${correct}/${perQ.length}`,
    avg_turns: avg((x) => x.avg_turns),
    avg_input_tokens: avg((x) => x.avg_input_tokens),
    interface_tokens_est_per_request: avg((x) => x.avg_interface_tokens),
    render_chars_avg: avg((x) => x.avg_tool_render_chars),
    outcome_breakdown: breakdown,
    F6_protocol: breakdown.protocol_noncompliance,
    budget_exhausted: breakdown.budget_exhausted,
  };
}

async function readSummary(file: string, modelFallback: string): Promise<ModelSummary | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as ModelSummary;
  } catch {
    console.warn(`无法读取 ${file}（记为空批：${modelFallback}）`);
    return null;
  }
}

async function main(): Promise<number> {
  const models: Record<string, unknown> = {};

  // 基线：deepseek-v4-flash（E1 兼容路径）
  const baseline = await readSummary(path.join(OUT_DIR, "all-summary.json"), DEFAULT_MODEL);
  if (baseline) {
    models[DEFAULT_MODEL] = { bash: armAggregate(baseline.questions, "bash"), ast: armAggregate(baseline.questions, "ast") };
  }

  // 各 --model 批次
  let entries: string[] = [];
  try {
    entries = (await readdir(RUNS_DIR)).filter((d) => d.startsWith("model-")).sort();
  } catch {
    /* 无模型批次目录 */
  }
  for (const dir of entries) {
    const model = dir.slice("model-".length);
    assertSafeBasename(model, "模型名");
    const s = await readSummary(path.join(RUNS_DIR, dir, "all-summary.json"), model);
    if (!s) {
      models[model] = { routing_error: true, note: "批次未产出 all-summary（路由失败或未跑完）" };
      continue;
    }
    models[model] = { bash: armAggregate(s.questions, "bash"), ast: armAggregate(s.questions, "ast") };
  }

  // findings：只报数据
  const taxValues: number[] = [];
  const f6Rates: string[] = [];
  const turnsRows: string[] = [];
  const broken: string[] = [];
  const modelNames = Object.keys(models);
  for (const name of modelNames) {
    const m = models[name] as {
      bash?: { correct: string; outcome_breakdown: Record<string, number>; avg_turns: number | null };
      ast?: { correct: string; outcome_breakdown: Record<string, number>; avg_turns: number | null };
    };
    // 分母 = run 数（各臂 outcome_breakdown 四桶之和），分子 = run 级失败数
    const runsOf = (x?: { outcome_breakdown: Record<string, number> }): number =>
      Object.values(x?.outcome_breakdown ?? {}).reduce((a, b) => a + b, 0);
    const runs = runsOf(m.bash) + runsOf(m.ast);
    const f6 = (m.bash?.outcome_breakdown.protocol_noncompliance ?? 0) + (m.ast?.outcome_breakdown.protocol_noncompliance ?? 0);
    const budget = (m.bash?.outcome_breakdown.budget_exhausted ?? 0) + (m.ast?.outcome_breakdown.budget_exhausted ?? 0);
    f6Rates.push(`${name}: protocol_noncompliance ${f6}/${runs} runs，budget_exhausted ${budget}/${runs} runs`);
    turnsRows.push(`${name}: bash ${m.bash?.avg_turns ?? "?"} / ast ${m.ast?.avg_turns ?? "?"} 轮`);
    if (m.bash && m.bash.correct !== `5/5` && m.bash.correct !== "0/0") broken.push(`${name}/bash ${m.bash.correct}`);
    if (m.ast && m.ast.correct !== `5/5` && m.ast.correct !== "0/0") broken.push(`${name}/ast ${m.ast.correct}`);
  }
  // 接口税范围：基线 + 各批次 summary.interface_tax_avg
  const taxSources: Array<[string, number]> = [];
  if (baseline?.summary?.interface_tax_avg != null) taxSources.push([DEFAULT_MODEL, baseline.summary.interface_tax_avg as number]);
  for (const dir of entries) {
    const model = dir.slice("model-".length);
    const s = await readSummary(path.join(RUNS_DIR, dir, "all-summary.json"), model);
    if (s?.summary?.interface_tax_avg != null) taxSources.push([model, s.summary.interface_tax_avg as number]);
  }
  for (const [, v] of taxSources) taxValues.push(v);

  const matrix = {
    generated_at: new Date().toISOString(),
    budget: { maxTurns: 8, maxTokens: 4000, timeoutMs: 180000 },
    unit_note: "interface 计量为 chars/4 估计 tokens（与 E1 同口径）；render 为渲染 chars",
    models,
    findings: {
      interface_tax_range: taxValues.length > 0 ? `${Math.min(...taxValues).toFixed(2)}× - ${Math.max(...taxValues).toFixed(2)}×` : null,
      interface_tax_by_model: Object.fromEntries(taxSources),
      f6_rate_by_model: f6Rates,
      ceiling_broken: broken.length === 0 ? "none（全部模型/臂 5/5）" : broken.join("; "),
      turns_by_model: turnsRows,
    },
  };
  await writeFile(MATRIX_PATH, `${JSON.stringify(matrix, null, 2)}\n`);
  console.log(`model-matrix 写入 ${MATRIX_PATH}（模型：${modelNames.join(", ")}）`);
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[model-matrix] fatal:", err);
    process.exitCode = 1;
  },
);
