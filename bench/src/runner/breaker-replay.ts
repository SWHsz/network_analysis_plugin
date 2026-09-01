/**
 * T1.3 E1 回放 + 参数扫描（零 LLM，只读既有 runs.json）。
 *
 * 对有 calls 遥测的全部 run（v0.2 + hint = 90 run），
 * 在 (K, N) 参数网格上回放熔断器，报告：
 * - 命中 run 数与命中点
 * - 硬门：被命中 run 必须 100% 是最终失败 run
 * - 健康参照：成功 run 的自然分布
 * - 兼容性：熔断不改变完成率
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { detectBreaker, type BreakerParams, type TurnEvent } from "../scorer/breaker.js";

const RUNS_ROOT = path.join(REPO_ROOT, "bench", "out", "runs");
const OUTPUT = path.join(REPO_ROOT, "bench", "out", "breaker-replay.json");

interface RunEntry {
  run_index: number;
  classification: string;
  outcome_bucket?: string;
  answer?: unknown;
  answerRaw?: string;
  calls?: Array<{
    seq: number; name: string; ok: boolean; rawArgs?: string;
    rawArgsTruncated?: boolean; emptyArrival?: boolean; resultChars?: number;
  }>;
  metrics?: { llmCalls: number };
  aborted?: string | null;
}

interface RunRef {
  batch: string; model: string; question: string; arm: string;
  runIndex: number; classification: string; outcomeBucket: string;
  events: TurnEvent[]; llmCalls: number;
}

async function collectRuns(): Promise<RunRef[]> {
  const { readdir } = await import("node:fs/promises");
  const out: RunRef[] = [];

  async function walk(dir: string, batchParts: string[]): Promise<void> {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const sub = path.join(dir, e.name);
      if (existsSync(path.join(sub, "runs.json"))) {
        // 叶子：sub = .../<question>/<arm>
        const rel = path.relative(RUNS_ROOT, sub);
        const parts = rel.split(path.sep);
        const arm = parts[parts.length - 2] ?? "?";
        const question = parts[parts.length - 3] ?? "?";
        const modelDir = parts.length > 3 ? parts[parts.length - 4] : "";
        const model = modelDir.startsWith("model-") ? modelDir.slice(6) : "flash";
        const batch = batchParts.join("/") || "e1";

        try {
          const runs = JSON.parse(await readFile(path.join(sub, "runs.json"), "utf8")) as RunEntry[];
          for (const r of runs) {
            if (!r.calls || r.calls.length === 0) continue; // 只回放有 calls 的 run
            // 构建 TurnEvent：calls 没有 turn 标签 → 按连续零调用间隔推断
            // 简化处理：每个 call 独立一轮（R1 检测不受影响；R2 用 calls.length vs llmCalls 差值近似）
            const events: TurnEvent[] = r.calls.map((c, i) => ({
              turn: i + 1,
              calls: [{
                name: c.name,
                rawArgs: c.rawArgs ?? JSON.stringify(c),
                ok: c.ok,
                emptyArrival: c.emptyArrival,
              }],
            }));
            // 补零调用轮（llmCalls > calls.length 的差值为纯文本轮，追加在末尾）
            const zeroTurns = Math.max(0, (r.metrics?.llmCalls ?? r.calls.length) - r.calls.length);
            for (let z = 0; z < zeroTurns; z++) {
              events.push({ turn: events.length + 1, calls: [] });
            }
            out.push({
              batch, model, question, arm,
              runIndex: r.run_index,
              classification: r.classification,
              outcomeBucket: r.outcome_bucket ?? (r.classification === "correct" ? "forensic_correct" : "format_error"),
              events,
              llmCalls: r.metrics?.llmCalls ?? r.calls.length,
            });
          }
        } catch { /* skip unreadable */ }
      } else {
        await walk(sub, [...batchParts, e.name]);
      }
    }
  }

  await walk(RUNS_ROOT, []);
  return out;
}

async function main(): Promise<number> {
  const runs = await collectRuns();
  const correctRuns = runs.filter((r) => r.classification === "correct");
  const failedRuns = runs.filter((r) => r.classification !== "correct");
  console.log(`[breaker-replay] ${runs.length} run 可回放（${correctRuns.length} correct / ${failedRuns.length} failed）`);

  // 健康参照：成功 run 的自然分布
  let maxSameArgsRetry = 0;
  let maxConsecutiveIdle = 0;
  for (const r of correctRuns) {
    // 同参重试深度
    let cur = 0; let curKey = ""; let maxRetry = 0;
    for (const ev of r.events) {
      for (const c of ev.calls) {
        const key = `${c.name}|${c.rawArgs}`;
        if (!c.ok && key === curKey) { cur++; maxRetry = Math.max(maxRetry, cur); }
        else if (!c.ok) { curKey = key; cur = 1; maxRetry = Math.max(maxRetry, cur); }
        else { curKey = ""; cur = 0; }
      }
    }
    maxSameArgsRetry = Math.max(maxSameArgsRetry, maxRetry);
    // 连续零调用轮
    let idle = 0; let maxIdle = 0;
    for (const ev of r.events) {
      if (ev.calls.length === 0) { idle++; maxIdle = Math.max(maxIdle, idle); }
      else idle = 0;
    }
    maxConsecutiveIdle = Math.max(maxConsecutiveIdle, maxIdle);
  }
  console.log(`  健康参照：成功 run 最大同参重试=${maxSameArgsRetry}，最大连续零调用轮=${maxConsecutiveIdle}`);

  // (K, N) 参数网格
  const kValues = [2, 3, 4];
  const nValues = [3, 5, 8];
  const grid: Array<Record<string, unknown>> = [];
  const compatibilityResults: string[] = [];

  for (const k of kValues) {
    for (const n of nValues) {
      const params: BreakerParams = { k, n };
      let hitCorrect = 0;
      let hitFailed = 0;
      const hitDetails: Array<Record<string, unknown>> = [];

      for (const r of runs) {
        const sig = detectBreaker(r.events, params);
        if (sig) {
          if (r.classification === "correct") {
            hitCorrect++;
            hitDetails.push({ run: `${r.batch}/${r.model}/${r.question}/${r.arm}#${r.runIndex}`, outcome: "correct", rule: sig.rule, turn: sig.turnIndex, detail: sig.detail });
          } else {
            hitFailed++;
            hitDetails.push({ run: `${r.batch}/${r.model}/${r.question}/${r.arm}#${r.runIndex}`, outcome: r.classification, rule: sig.rule, turn: sig.turnIndex, detail: sig.detail });
          }
        }
      }

      // 硬门检查
      const hardGatePass = hitCorrect === 0;
      // 兼容性：熔断不改变完成率（前提：熔断只触发在最终失败的 run 上）
      const compat = hardGatePass ? "成立" : `不成立（误杀 ${hitCorrect} 个成功 run）`;

      grid.push({
        K: k, N: n,
        hits_total: hitCorrect + hitFailed,
        hits_correct: hitCorrect,
        hits_failed: hitFailed,
        hard_gate: hardGatePass ? "PASS" : "FAIL",
        compatibility: compat,
        hit_rate_on_failed: failedRuns.length > 0 ? Number((hitFailed / failedRuns.length).toFixed(3)) : 0,
        details: hitDetails.slice(0, 10),
      });

      if (!hardGatePass) {
        compatibilityResults.push(`K=${k},N=${n}: ${compat}`);
      }
    }
  }

  // 输出
  const report = {
    generated_at: new Date().toISOString(),
    telemetry_inventory: {
      total_runs_all_batches: 210,
      runs_with_calls: runs.length,
      runs_without_calls_note: "E1 flash v0.1 (30) + v0.1 multi-model (90) 无 calls 字段——不可回放（诚实标注，不插值补编）",
      r2_limitation: "轮级边界缺失：calls 数组无 turn 标签，零调用轮按 llmCalls-calls.length 差值近似（追加在序列末尾，实际中间穿插不可知）。R2 结论为保守下界。",
    },
    health_baseline: {
      max_same_args_retry_in_correct_runs: maxSameArgsRetry,
      max_consecutive_idle_turns_in_correct_runs: maxConsecutiveIdle,
      r1_k_must_exceed: maxSameArgsRetry,
      r2_n_must_exceed: maxConsecutiveIdle,
    },
    parameter_grid: grid,
    compatibility_failures: compatibilityResults,
  };

  await writeFile(OUTPUT, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`\n[breaker-replay] 参数扫描完成，报告: ${OUTPUT}`);
  console.log(`  兼容性失败组合: ${compatibilityResults.length === 0 ? "无（全部 (K,N) 通过硬门）" : compatibilityResults.join("; ")}`);

  // 推荐 (K*, N*)
  const passable = grid.filter((g) => g.hard_gate === "PASS") as Array<{ K: number; N: number; hits_failed: number }>;
  if (passable.length > 0) {
    const best = passable.reduce((a, b) => (b.hits_failed > a.hits_failed ? b : a));
    console.log(`  推荐 (K*, N*) = (${best.K}, ${best.N})：命中失败 run 最多（${best.hits_failed}）且零误杀`);
  }
  return 0;
}

main().then(
  (c) => { process.exitCode = c; },
  (e) => { console.error("[breaker-replay] fatal:", e); process.exitCode = 1; },
);
