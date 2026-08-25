/**
 * v0.1 → v0.2 旧数据 F7 重分类（不重跑，reclassified_e1 模式）。
 *
 * 证据基础（已核实）：
 * - kimi/ast 的 traffic_query 调用 29/29 全部失败且 query 全部空/缺失（v0.1
 *   transcript，臂级聚合）；该臂全部工具调用失败率 29/42=0.690。
 * - kimi/ast 15 run 中 13 个 budget_exhausted（全部打满轮次）。
 *
 * 代理判据（detectF7FromProxy，旧数据无 arrival 逐 run 遥测）：
 *   budget_exhausted run × 臂级 traffic_query 空到达率 ≥0.9 → tool_binding_failure。
 *   空到达率按臂级统计（v0.1 唯一可得粒度），per-run 证据附臂级数字 + 该 run 的
 *   llmCalls/format_error 原文，不做逐 run 编造。
 *
 * 验证断言（任务书）：
 * - kimi/ast 重分类数 == 13，逐一列出；
 * - flash / glm / pro / kimi-bash 的 F7 计数 == 0（零误伤）；
 * - 只改桶归属，多数表决结果不变。
 * 产物：bench/out/model-matrix-v02.json 的 reclassified_from_v01 块。
 * 红线：不改动 v0.1 的 model-matrix.json 与任何旧 run 数据文件。
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { detectF7FromProxy } from "../scorer/f7.js";
import type { OutcomeBucket } from "../scorer/f6.js";
import { ARM_NAMES_V01, SLICE_QUESTION_IDS } from "./run-slice-ids.js";

const RUNS_DIR = path.join(REPO_ROOT, "bench", "out", "runs");
const OUT_PATH = path.join(REPO_ROOT, "bench", "out", "model-matrix-v02.json");

interface LegacyRun {
  run_index: number;
  classification: string;
  f6?: Record<string, boolean>;
  outcome_bucket: OutcomeBucket;
  metrics: { llmCalls: number; toolRenderChars: number };
}

interface CallRec {
  name: string;
  ok: boolean;
  args?: { query?: unknown } | null;
}

const MODELS = [
  { dir: "", name: "deepseek-v4-flash" },
  { dir: "model-deepseek-v4-pro", name: "deepseek-v4-pro" },
  { dir: "model-glm-5.3", name: "glm-5.3" },
  { dir: "model-kimi-k3", name: "kimi-k3" },
];

async function readJson(file: string): Promise<unknown> {
  return JSON.parse(await readFile(file, "utf8"));
}

async function main(): Promise<number> {
  const reclassified: Array<Record<string, unknown>> = [];
  const fiveBuckets: Record<string, Record<string, Record<string, number>>> = {};
  let kimiAstF7 = 0;
  const othersF7: string[] = [];

  for (const { dir, name } of MODELS) {
    fiveBuckets[name] = {};
    for (const arm of ARM_NAMES_V01) {
      const counts: Record<string, number> = {
        forensic_correct: 0,
        forensic_wrong: 0,
        protocol_noncompliance: 0,
        budget_exhausted: 0,
        tool_binding_failure: 0,
      };
      // 臂级空到达率（v0.1 transcript 聚合；transcript 只存最后 run，作臂级代理）
      let emptyArrivalRate = 0;
      let emptyEvidence = "";
      try {
        assertSafeBasename(arm, "臂名");
        const tf = path.join(RUNS_DIR, dir, "q-web-002", arm, "transcript.json");
        const recs = (await readJson(tf)) as { records: CallRec[] };
        const tq = recs.records.filter((r) => r.name === "traffic_query");
        if (tq.length > 0) {
          const isEmptyQuery = (r: CallRec): boolean => {
            const q = r.args?.query;
            return q === undefined || q === null || (typeof q === "object" && Object.keys(q as object).length === 0);
          };
          const empty = tq.filter((r) => !r.ok && isEmptyQuery(r)).length;
          emptyArrivalRate = empty / tq.length;
          emptyEvidence = `臂级 traffic_query 空到达/失败 ${empty}/${tq.length}`;
        }
      } catch {
        /* 该模型/臂无 q-web-002 transcript（bash 臂无 traffic_query）→ rate 0 */
      }

      for (const qid of SLICE_QUESTION_IDS) {
        assertSafeBasename(qid, "题号");
        const runsFile = path.join(RUNS_DIR, dir, qid, arm, "runs.json");
        let runs: LegacyRun[];
        try {
          runs = (await readJson(runsFile)) as LegacyRun[];
        } catch {
          continue;
        }
        for (const r of runs) {
          let bucket: string = r.outcome_bucket;
          // legacy runs.json（E1 flash 批次）无 outcome_bucket——按 all-summary
          // reclassified_e1 的结论映射：28 correct + q-web-002/ast#2 budget +
          // q-edge-001/bash#2 protocol（与 reclassify-e1 验证口径一致）
          if (!(bucket in counts)) {
            const isF6 = r.classification === "format_error";
            const f6 = r.f6 ?? {};
            bucket = !isF6
              ? "forensic_correct"
              : (f6.max_turns_exhausted === true ? "budget_exhausted" : "protocol_noncompliance");
          }
          const hit = detectF7FromProxy({ bucket: bucket as OutcomeBucket, armToolFailureRate: emptyArrivalRate });
          if (hit) {
            bucket = "tool_binding_failure";
            if (name === "kimi-k3" && arm === "ast-v0.4") kimiAstF7++;
            else othersF7.push(`${name}/${arm}/${qid}#${r.run_index}`);
          }
          counts[bucket] = (counts[bucket] ?? 0) + 1;
          reclassified.push({
            model: name,
            arm,
            question_id: qid,
            run_index: r.run_index,
            old_bucket: r.outcome_bucket,
            new_bucket: bucket,
            f7_evidence: hit ? `${emptyEvidence}（率 ${emptyArrivalRate.toFixed(2)} ≥0.9）+ run 打满轮次 llmCalls=${r.metrics.llmCalls}` : null,
          });
        }
      }
      fiveBuckets[name]![arm] = counts!;
      void counts;
    }
  }

  // 验证断言
  const failures: string[] = [];
  if (kimiAstF7 !== 13) failures.push(`kimi/ast F7 重分类数 ${kimiAstF7} != 13`);
  if (othersF7.length > 0) failures.push(`误伤：${othersF7.join("; ")}`);

  const doc = {
    protocol_version: "v0.2",
    generated_at: new Date().toISOString(),
    reclassified_from_v01: {
      rule: "v0.1 无逐 run arrival 遥测 → 臂级 traffic_query 空到达率 ≥0.9（transcript 聚合）作代理判据；仅 budget_exhausted run 重分类为 tool_binding_failure；多数表决结果不变",
      five_buckets: fiveBuckets,
      kimi_ast_f7_count: kimiAstF7,
      verification: failures.length === 0 ? "PASS（kimi/ast 13 个 budget run 全落 F7；其余模型/臂零误伤）" : failures,
      per_run: reclassified,
    },
  };
  await writeFile(OUT_PATH, `${JSON.stringify(doc, null, 2)}\n`);
  console.log("五分桶矩阵:");
  for (const [m, arms] of Object.entries(fiveBuckets)) {
    for (const [a, c] of Object.entries(arms)) {
      console.log(`  ${m}/${a}: ${JSON.stringify(c)}`);
    }
  }
  if (failures.length > 0) {
    console.error("验证失败：", failures);
    return 1;
  }
  console.log("验证 PASS：reclassified_from_v01 已写入 model-matrix-v02.json");
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[reclassify-v01-f7] fatal:", err);
    process.exitCode = 1;
  },
);
