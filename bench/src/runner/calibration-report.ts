/**
 * T4 标定报告聚合器（S3 首卡大包标定批）。
 *
 *   tsx src/runner/calibration-report.ts                       # 默认扫描 runs/budget-sweep/
 *   tsx src/runner/calibration-report.ts --out <path.json>
 *
 * 输入：bench/out/runs/budget-sweep/<角点>/<模型目录>/<qid>/<臂>/runs.json
 *      （run-slice --budget-sweep 的逐 run 落盘；query_schema=explicit-v1 防陈旧）
 * 输出：bench/out/calibration-report.json
 *   - 完成率 × 预算曲线（ρ 档 × 臂 × 模型分面；majority + excluding_F6 双口径）
 *   - 预算饱和点判读（该 facet 内完成率达到峰值的最小角点 = 预算下限）
 *   - 大包接口税实测表（对照 E1 2.82× 实测 / 任务书 2.90× 参照）+ 乘性外推线性核验
 *   - 每 run 墙钟分布 → timeout 建议
 *   - D9 建议表：ρ 档 → (maxTurns, maxTokens, timeout) 三元组
 *
 * 纯只读聚合，不发任何网络请求。
 */
import { existsSync } from "node:fs";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";

const SWEEP_ROOT = path.join(REPO_ROOT, "bench", "out", "runs", "budget-sweep");
const DEFAULT_OUT = path.join(REPO_ROOT, "bench", "out", "calibration-report.json");
/** E1 实测接口税（每请求，chars/4 估计，跨 4 模型一致）；任务书引用 2.90× */
const E1_REFERENCE = { bash_per_request: 621, ast_per_request: 1750, measured_ratio: 2.82, task_book_reference: 2.9 };

interface RunRecord {
  run_index: number;
  query_schema?: string;
  classification: string;
  f6: Record<string, unknown>;
  outcome_bucket: string;
  metrics: {
    llmCalls: number;
    inputTokens: number;
    outputTokens: number;
    interfaceTokens: number;
    wallMs: number;
    budgetExhausted: boolean;
  };
  aborted: unknown;
}

interface Cell {
  corner: string;
  budget: { maxTurns: number; maxTokens: number; timeoutMs: number };
  model: string;
  questionId: string;
  arm: string;
  dir: string;
}

function mean(xs: number[]): number {
  return xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length;
}
function percentile(xs: number[], p: number): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]!;
}
const r1f = (x: number): number => Number(x.toFixed(1));
const r2f = (x: number): number => Number(x.toFixed(2));

/** completion 口径：raw = correct/全部；excluding_F6F7 = correct/(forensic_* + budget_exhausted)（ρ 测量主口径） */
function completionOf(runs: RunRecord[]): { raw: string; excluding: string; majority: boolean; n: number } {
  const buckets = runs.map((r) => r.outcome_bucket);
  const correct = buckets.filter((b) => b === "forensic_correct").length;
  const forensic = buckets.filter((b) => b.startsWith("forensic_")).length;
  const usable = buckets.filter((b) => b !== "protocol_noncompliance" && b !== "tool_binding_failure").length;
  return {
    raw: `${correct}/${runs.length}`,
    excluding: `${correct}/${usable}`,
    majority: correct > runs.length / 2,
    n: runs.length,
  };
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const outIdx = argv.indexOf("--out");
  const outPath = outIdx >= 0 ? path.resolve(argv[outIdx + 1]!) : DEFAULT_OUT;

  if (!existsSync(SWEEP_ROOT)) {
    console.error(`[calibrate] 扫描根不存在：${SWEEP_ROOT}（先跑 run-slice --budget-sweep）`);
    return 2;
  }

  const cells: Cell[] = [];
  for (const corner of (await readdir(SWEEP_ROOT)).sort()) {
    const cornerDir = path.join(SWEEP_ROOT, corner);
    if (!(await stat(cornerDir)).isDirectory()) continue;
    assertSafeBasename(corner, "角点目录");
    for (const modelDir of (await readdir(cornerDir)).sort()) {
      const mDir = path.join(cornerDir, modelDir);
      if (!(await stat(mDir)).isDirectory()) continue;
      const model = modelDir.startsWith("model-") ? modelDir.slice("model-".length) : "deepseek-v4-flash";
      for (const qid of (await readdir(mDir)).sort()) {
        const qDir = path.join(mDir, qid);
        if (!(await stat(qDir)).isDirectory()) continue;
        for (const arm of (await readdir(qDir)).sort()) {
          const p = path.join(qDir, arm, "runs.json");
          if (!(await stat(path.join(qDir, arm)).then((s) => s.isDirectory()).catch(() => false))) continue;
          cells.push({ corner, budget: await budgetOf(corner), model, questionId: qid, arm, dir: path.join(qDir, arm) });
        }
      }
    }
  }
  if (cells.length === 0) {
    console.error("[calibrate] 未发现任何 runs.json——sweep 数据为空");
    return 2;
  }

  const rows: Array<Record<string, unknown>> = [];
  for (const cell of cells) {
    let runs: RunRecord[];
    try {
      runs = JSON.parse(await readFile(path.join(cell.dir, "runs.json"), "utf8")) as RunRecord[];
    } catch {
      continue;
    }
    if (!Array.isArray(runs) || runs.length === 0) continue;
    const completed = completionOf(runs);
    const walls = runs.map((r) => r.metrics.wallMs);
    const turns = runs.map((r) => r.metrics.llmCalls);
    const ifacePerReq = mean(runs.map((r) => r.metrics.interfaceTokens));
    const ifaceTotal = ifacePerReq * mean(turns);
    const inputTotal = mean(runs.map((r) => r.metrics.inputTokens));
    rows.push({
      corner: cell.corner,
      budget: cell.budget,
      timeout_s: Math.round(cell.budget.timeoutMs / 1000),
      model: cell.model,
      question_id: cell.questionId,
      arm: cell.arm,
      runs: runs.length,
      majority_correct: completed.majority,
      majority_detail: `${runs.filter((r) => r.classification === "correct").length}/${runs.length}`,
      completion_raw: completed.raw,
      completion_excluding_F6F7: completed.excluding,
      outcome_mix: Object.fromEntries(
        [...new Set(runs.map((r) => r.outcome_bucket))].map((b) => [b, runs.filter((r) => r.outcome_bucket === b).length]),
      ),
      means: {
        turns: r1f(mean(turns)),
        input_tokens: Math.round(inputTotal),
        output_tokens: Math.round(mean(runs.map((r) => r.metrics.outputTokens))),
        interface_tokens_per_request: Math.round(ifacePerReq),
        interface_total_est: Math.round(ifaceTotal),
        interface_input_share_pct: inputTotal > 0 ? r1f((100 * ifaceTotal) / inputTotal) : null,
        wall_ms: { mean: Math.round(mean(walls)), p50: Math.round(percentile(walls, 0.5)), p90: Math.round(percentile(walls, 0.9)), max: Math.round(Math.max(...walls)) },
      },
      // 乘性外推核验（E1 §3.3）：iface_total ≈ 轮次 × per-request iface → 线性比 ≈ 1
      interface_linearity_ratio: ifacePerReq > 0 ? r2f(ifaceTotal / (ifacePerReq * mean(turns))) : null,
      budget_exhausted_runs: runs.filter((r) => r.metrics.budgetExhausted).length,
    });
  }

  // ---- 饱和点判读与 D9 ----
  const facetKey = (row: Record<string, unknown>): string => `${row.model}|${row.arm}|${row.question_id}`;
  const CORNER_ORDER = ["t08-tok4000", "t16-tok8000", "t32-tok16000"];
  const cornerRank = (c: unknown): number => {
    const i = CORNER_ORDER.indexOf(String(c));
    return i >= 0 ? i : CORNER_ORDER.length;
  };

  const facets = new Map<string, Array<Record<string, unknown>>>();
  for (const row of rows) {
    const k = facetKey(row);
    if (!facets.has(k)) facets.set(k, []);
    facets.get(k)!.push(row);
  }

  const saturation: Array<Record<string, unknown>> = [];
  for (const [facet, facetRows] of facets) {
    const [model, arm, questionId] = facet.split("|");
    for (const qid of [...new Set(facetRows.map((r) => String(r.question_id)))]) {
      const series = facetRows
        .filter((r) => r.question_id === qid)
        .sort((a, b) => cornerRank(a.corner) - cornerRank(b.corner));
      if (series.length === 0) continue;
      const rateOf = (r: Record<string, unknown>): number => {
        const [c, t] = String(r.completion_excluding_F6F7).split("/").map(Number);
        return t! > 0 ? c! / t! : 0;
      };
      const peak = Math.max(...series.map(rateOf));
      const saturatedIdx = series.findIndex((r) => rateOf(r) >= peak && series.slice(series.indexOf(r)).every((x) => rateOf(x) >= peak - 1e-9));
      const sat = saturatedIdx >= 0 ? series[saturatedIdx]! : null;
      saturation.push({
        model,
        arm,
        question_id: qid,
        completion_series: series.map((r) => ({ corner: r.corner, budget: r.budget, completion_excluding_F6F7: r.completion_excluding_F6F7, completion_raw: r.completion_raw })),
        peak_rate: r2f(peak),
        saturated_at: sat ? { corner: sat.corner, budget: sat.budget, timeout_s: sat.timeout_s } : null,
        reading: peak === 0 ? "全角点零完成——预算不是首要瓶颈（失败形态见 outcome_mix）" : sat ? `自 ${sat.corner} 起完成率平台化 → 该 facet 的预算下限` : "无饱和（未平台化，最大角点仍为峰值）",
      });
    }
  }

  // ---- 接口税实测表 ----
  const taxTable = [...new Set(rows.map((r) => `${r.corner}|${r.model}|${r.question_id}`))].map((k) => {
    const [corner, model, questionId] = k.split("|");
    const bash = rows.find((r) => r.corner === corner && r.model === model && r.question_id === questionId && String(r.arm).startsWith("bash-"));
    const ast = rows.find((r) => r.corner === corner && r.model === model && r.question_id === questionId && String(r.arm).startsWith("ast-"));
    if (!bash || !ast) return null;
    const b = (bash.means as Record<string, unknown>).interface_tokens_per_request as number;
    const a = (ast.means as Record<string, unknown>).interface_tokens_per_request as number;
    const turnsAst = (ast.means as Record<string, unknown>).turns as number;
    const ifaceTotalAst = (ast.means as Record<string, unknown>).interface_total_est as number;
    return {
      corner,
      model,
      question_id: questionId,
      bash_per_request: b,
      ast_per_request: a,
      per_request_ratio: b > 0 ? r2f(a / b) : null,
      ast_turns: turnsAst,
      ast_iface_total_est: ifaceTotalAst,
      // 与 E1（32 包、H≈6-8）对照：大包深下钻下 per-request 税应保持工具面常量，
      // 总税 = turns × per-request 的乘性结构在线性比 ≈ 1 时成立
      linearity_ratio_ast: (ast as Record<string, unknown>).interface_linearity_ratio,
      e1_measured_ratio: E1_REFERENCE.measured_ratio,
      task_book_reference_ratio: E1_REFERENCE.task_book_reference,
    };
  }).filter((x) => x !== null);

  // ---- D9 建议表：ρ 档 → 最小可行角点（该 ρ 全部 facet 达峰值完成率的最小角点） ----
  const d9: Array<Record<string, unknown>> = [];
  const rhoKeys = [...new Set(rows.map((r) => String(r.question_id)))].sort();
  const rateOfRow = (r: Record<string, unknown>): number => {
    const [c, t] = String(r.completion_excluding_F6F7).split("/").map(Number);
    return t! > 0 ? c! / t! : 0;
  };
  for (const qid of rhoKeys) {
    const rhoRows = rows.filter((r) => r.question_id === qid);
    const peakByFacet = new Map<string, number>();
    for (const r of rhoRows) {
      const f = `${r.model}|${r.arm}`;
      peakByFacet.set(f, Math.max(peakByFacet.get(f) ?? 0, rateOfRow(r)));
    }
    const rateAt = (facet: string, corner: string): number => {
      const r = rhoRows.find((x) => `${x.model}|${x.arm}` === facet && x.corner === corner);
      return r ? rateOfRow(r) : -1;
    };
    const feasible = [...rhoRows]
      .sort((a, b) => cornerRank(a.corner) - cornerRank(b.corner))
      .find((r) => peakByFacet.size > 0 && [...peakByFacet.keys()].every((f) => rateAt(f, String(r.corner)) >= peakByFacet.get(f)! - 1e-9));
    // timeout 建议：选中角点的墙钟 p90 × 1.5，且不超过该角点名义 timeout 的 2 倍
    let timeoutSuggestion: Record<string, unknown> | null = null;
    if (feasible) {
      const budget = feasible.budget as { maxTurns: number; maxTokens: number; timeoutMs: number };
      const walls = rhoRows
        .filter((r) => r.corner === feasible.corner)
        .map((r) => ((r.means as Record<string, unknown>).wall_ms as Record<string, number | undefined>).p90 ?? 0);
      const p90 = Math.max(...walls);
      timeoutSuggestion = {
        rule: "该 ρ 全 facet 在选中角点的墙钟 p90 × 1.5（上限 = 角点名义 timeout × 2）",
        wall_p90_ms: Math.round(p90),
        suggested_timeout_ms: Math.min(Math.round(p90 * 1.5), budget.timeoutMs * 2),
      };
      d9.push({
        question_id: qid,
        rho_note: "ρ 档以 question_id 尾段区分（-r1 中档 / -r2 大档），attack share 见实例 meta.json",
        suggested: { corner: feasible.corner, maxTurns: budget.maxTurns, maxTokens: budget.maxTokens, timeout_ms: budget.timeoutMs },
        timeout: timeoutSuggestion,
        basis: "全部 facet（模型×臂）达到各自峰值完成率的最小角点（先粗后细：不外推未实测角点）",
      });
    } else {
      d9.push({
        question_id: qid,
        rho_note: "ρ 档以 question_id 尾段区分（-r1 中档 / -r2 大档），attack share 见实例 meta.json",
        suggested: null,
        timeout: null,
        basis: "无可行角点：存在 facet 在所有角点均未达峰值——查 outcome_mix 定位失败形态",
      });
    }
  }

  const report = {
    generated_at: new Date().toISOString(),
    source_root: path.relative(REPO_ROOT, SWEEP_ROOT),
    timeout_rule: "timeoutMs = 180s × maxTurns/8（与 E1 冻结预算同源等比放大；报告口径）",
    completion_metrics_note: "completion_raw = correct/全部 run；completion_excluding_F6F7 = correct/(forensic_*) + budget_exhausted（F6/F7 不污染 ρ 测量，主口径）",
    matrix: {
      corners: [...new Set(rows.map((r) => r.corner))].sort(),
      models: [...new Set(rows.map((r) => r.model))].sort(),
      arms: [...new Set(rows.map((r) => r.arm))].sort(),
      questions: rhoKeys,
      total_runs: rows.reduce((a, b) => a + Number(b.runs), 0),
    },
    completion_by_budget: rows,
    saturation,
    interface_tax: {
      e1_reference: E1_REFERENCE,
      cells: taxTable,
      note: "per-request 税为工具面属性（不随模型/预算角点变化）；乘性外推 = 轮次 × per-request，linearity_ratio_ast ≈ 1.0 即线性成立",
    },
    d9_recommendation: d9,
  };

  await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`[calibrate] ${rows.length} 个 cell（${report.matrix.total_runs} run）→ ${outPath}`);
  for (const s of saturation) {
    console.log(`  [sat] ${s.model}/${s.arm}/${s.question_id}: ${s.reading}`);
  }
  return 0;
}

/** 角点名 → 预算三元组（命名约定 t<NN>-tok<N>；解析失败视为非法角点目录） */
async function budgetOf(corner: string): Promise<{ maxTurns: number; maxTokens: number; timeoutMs: number }> {
  const m = /^t(\d+)-tok(\d+)$/.exec(corner);
  if (!m) throw new Error(`角点目录名不合法：${corner}（期望 t<NN>-tok<N>）`);
  const maxTurns = Number(m[1]);
  const maxTokens = Number(m[2]);
  return { maxTurns, maxTokens, timeoutMs: Math.round((180_000 / 8) * maxTurns) };
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[calibrate] fatal:", err);
    process.exitCode = 1;
  },
);
