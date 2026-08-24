/**
 * E1 回填重分类：用 F6 分类逻辑重新标注 E1 已有的 30 个 run（不重跑）。
 *
 * 输入：bench/out/runs/<qid>/<arm>/runs.json（E1 --all 批次）
 * 规则（scorer/f6.ts）：
 *   - format_error + answerRaw 空 → no_finish_call
 *   - format_error + maxTurns 打满（llmCalls>=8）→ budget_exhausted 桶
 *   - format_error + 未打满 → protocol_noncompliance 桶
 *   - toolRenderChars===0 作 no_tool_exploration 的旧数据代理
 * 验证断言（任务书）：q-web-002/ast#2 → budget_exhausted；q-edge-001/bash#2 →
 * protocol_noncompliance；其余 28 → forensic_correct。不一致即非零退出。
 * 产物：all-summary.json 增加 reclassified_e1 块，并把 outcome_breakdown
 * 注入 questions[].{bash,ast}（供 model-matrix 统一消费）。
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { classifyF6, completionRates, emptyBreakdown, outcomeBucket } from "../scorer/f6.js";
import type { RunClassification } from "../scorer/pipeline.js";
import { SLICE_QUESTION_IDS } from "./run-slice-ids.js";

const RUNS_DIR = path.join(REPO_ROOT, "bench", "out", "runs");
const ALL_SUMMARY = path.join(REPO_ROOT, "bench", "out", "all-summary.json");
const ARMS = ["bash-v0.1", "ast-v0.4"] as const;
const E1_MAX_TURNS = 8;

interface LegacyRun {
  run_index: number;
  classification: string;
  answerRaw?: string;
  metrics: { llmCalls: number; toolRenderChars: number; budgetExhausted: boolean };
  aborted?: string | null;
}

function normalizeClassification(c: string): RunClassification {
  if (c === "correct" || c === "format_error") return c;
  return "wrong_answer"; // 旧枚举 "wrong" 的兼容映射
}

async function main(): Promise<number> {
  const summary = JSON.parse(await readFile(ALL_SUMMARY, "utf8")) as {
    questions: Array<{ question_id: string; bash: Record<string, unknown>; ast: Record<string, unknown> }>;
    [k: string]: unknown;
  };
  const perRun: Array<Record<string, unknown>> = [];
  const totals = { forensic_correct: 0, forensic_wrong: 0, protocol_noncompliance: 0, budget_exhausted: 0 };
  const perQuestionArm = new Map<string, ReturnType<typeof emptyBreakdown>>();

  for (const qid of SLICE_QUESTION_IDS) {
    for (const arm of ARMS) {
      const breakdown = emptyBreakdown();
      assertSafeBasename(qid, "题号");
      assertSafeBasename(arm, "臂名");
      const p = path.join(RUNS_DIR, qid, arm, "runs.json");
      let runs: LegacyRun[];
      try {
        runs = JSON.parse(await readFile(p, "utf8")) as LegacyRun[];
      } catch {
        console.error(`跳过（无数据）：${qid}/${arm}`);
        continue;
      }
      for (const r of runs) {
        const classification = normalizeClassification(r.classification);
        const f6 = classifyF6({
          classification,
          answerRaw: r.answerRaw ?? "",
          // 旧数据无工具调用数：渲染字符为 0 作零调用的代理
          toolCallCount: r.metrics.toolRenderChars === 0 ? 0 : 1,
          llmCalls: r.metrics.llmCalls,
          maxTurns: E1_MAX_TURNS,
        });
        const bucket = outcomeBucket(classification, f6);
        breakdown[bucket]++;
        totals[bucket]++;
        perRun.push({ question_id: qid, arm, run_index: r.run_index, classification, f6, outcome_bucket: bucket });
      }
      perQuestionArm.set(`${qid}|${arm}`, breakdown);
      const entry = summary.questions.find((x) => x.question_id === qid);
      if (entry) {
        const key = arm === "bash-v0.1" ? "bash" : "ast";
        entry[key]!.outcome_breakdown = breakdown;
        entry[key]!.completion_rate_excluding_F6 = completionRates(breakdown).completion_rate_excluding_F6;
      }
    }
  }

  // 任务书验证断言
  const failures: string[] = [];
  const expect = (qid: string, arm: string, runIndex: number, bucket: string): void => {
    const hit = perRun.find((x) => x.question_id === qid && x.arm === arm && x.run_index === runIndex);
    if (!hit || hit.outcome_bucket !== bucket) {
      failures.push(`${qid}/${arm}#${runIndex} 期望 ${bucket}，实际 ${hit?.outcome_bucket ?? "缺失"}`);
    }
  };
  expect("q-web-002", "ast-v0.4", 2, "budget_exhausted");
  expect("q-edge-001", "bash-v0.1", 2, "protocol_noncompliance");
  for (const r of perRun) {
    const isExpectedFailure =
      (r.question_id === "q-web-002" && r.arm === "ast-v0.4" && r.run_index === 2) ||
      (r.question_id === "q-edge-001" && r.arm === "bash-v0.1" && r.run_index === 2);
    if (!isExpectedFailure && r.outcome_bucket !== "forensic_correct") {
      failures.push(`${r.question_id}/${r.arm}#${r.run_index} 期望 forensic_correct，实际 ${r.outcome_bucket}`);
    }
  }

  summary.reclassified_e1 = {
    generated_at: new Date().toISOString(),
    rule: "format_error+空answerRaw=no_finish_call；maxTurns打满(llmCalls>=8)→budget_exhausted；未打满格式失败→protocol_noncompliance；toolRenderChars===0 作 no_tool_exploration 代理",
    totals,
    per_run: perRun,
    verification: failures.length === 0 ? "PASS（30/30 与任务书预期一致）" : failures,
  };

  await writeFile(ALL_SUMMARY, `${JSON.stringify(summary, null, 2)}\n`);
  console.log("outcome totals:", totals);
  if (failures.length > 0) {
    console.error("回填验证失败：");
    for (const f of failures) console.error(`  ✗ ${f}`);
    return 1;
  }
  console.log("回填验证 PASS：reclassified_e1 已写入 bench/out/all-summary.json");
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[reclassify-e1] fatal:", err);
    process.exitCode = 1;
  },
);
