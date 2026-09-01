/**
 * T2 交付：S3 72-run 离线重打分（零 LLM，只读既有 transcript）。
 *
 * 读入 bench/out/runs/budget-sweep/ 下的全部 runs.json，
 * 对每个有 answer 的 run 用三种口径计算 M3：
 *   naive     — |cited ∩ gold_sample| / |cited|（旧口径，把彻底误罚为不精确）
 *   cluster   — |cited ∩ attack_cluster| / |cited|（簇锚定 precision）
 *   sample_R  — |cited ∩ gold_sample| / |gold_sample|（采样锚定 recall）
 * 并输出三列对照表。
 *
 * 运行：node node_modules/vitest/vitest.mjs run ... 或者 tsx src/runner/rescore-s3.ts
 * 红线：禁止发起任何模型调用。
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { buildClusterFromBenchGt, buildClusterInput, scoreM3Cluster } from "../scorer/m3-cluster.js";

const SWEEP_DIR = path.join(REPO_ROOT, "bench", "out", "runs", "budget-sweep");
const INSTANCES_DIR = path.join(REPO_ROOT, "bench", "fixtures", "instances");
const OUTPUT_PATH = path.join(REPO_ROOT, "bench", "out", "m3-rescore-s3.json");

interface RunEntry {
  run_index: number;
  classification: string;
  outcome_bucket: string;
  answer?: Record<string, unknown>;
  answerRaw?: string;
  metrics?: { llmCalls: number; inputTokens: number; wallMs: number };
}

async function readJson(file: string): Promise<unknown> {
  return JSON.parse(await readFile(file, "utf8"));
}

async function main(): Promise<number> {
  const { readdir } = await import("node:fs/promises");
  const results: Array<Record<string, unknown>> = [];
  let total = 0;
  let scored = 0;
  let noAnswer = 0;

  // 递归收集全部 runs.json（目录结构有平坦和嵌套两种布局，glob 一致处理）
  async function collectRuns(dir: string): Promise<string[]> {
    const out: string[] = [];
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const sub = path.join(dir, e.name);
      if (e.name === "runs.json") continue;
      // 叶子判断：目录下有 runs.json 则它是臂目录
      try {
        const inner = await readdir(sub, { withFileTypes: true });
        if (inner.some((x) => x.isFile() && x.name === "runs.json")) {
          out.push(path.join(sub, "runs.json"));
        } else {
          out.push(...(await collectRuns(sub)));
        }
      } catch {
        out.push(...(await collectRuns(sub)));
      }
    }
    return out;
  }

  const runFiles = await collectRuns(SWEEP_DIR);

  for (const runsFile of runFiles) {
    // 路径解析：budget-sweep/[budget]/([model-*/])/[qid]/[arm]/runs.json
    const rel = path.relative(SWEEP_DIR, runsFile);
    const parts = rel.split(path.sep);
    const budget = parts[0] ?? "?";
    const arm = parts[parts.length - 2] ?? "?";
    const qid = parts[parts.length - 3] ?? "?";
    const modelDir = parts.length > 4 ? parts[1]! : "";
    const model = modelDir.startsWith("model-") ? modelDir.slice(6) : "flash";

    // gold 路径推导
    const match = qid.match(/^q-(s\d+)-(i\d+)-(r\d+)$/);
    if (!match) continue;
    const s = match[1]!;
    const i = match[2]!;
    const r = match[3]!;
    const instDir = path.join(INSTANCES_DIR, s, i, r);
    let clusterInput;
    let clusterSize = 0;
    // 优先用 bench-gt（含全量攻击帧 kind 标记）
    try {
      const benchGt = (await readJson(path.join(instDir, "bench-gt.json"))) as Parameters<typeof buildClusterFromBenchGt>[0];
      const fromGt = buildClusterFromBenchGt(benchGt);
      // 补充 stage 级信息（来自 gold.json 的 attack_chain 采样分配）
      try {
        const gold = (await readJson(path.join(instDir, "gold.json"))) as Parameters<typeof buildClusterInput>[0];
        const fromGold = buildClusterInput(gold);
        fromGt.stages = fromGold.stages;
      } catch { /* stage 级信息可选 */ }
      clusterInput = fromGt;
      clusterSize = fromGt.clusterSize;
    } catch {
      // 回退到 gold.json（只有采样帧的簇）
      try {
        const gold = (await readJson(path.join(instDir, "gold.json"))) as Parameters<typeof buildClusterInput>[0];
        clusterInput = buildClusterInput(gold);
        clusterSize = clusterInput.attackCluster.length;
      } catch {
        console.warn(`gold not found: ${instDir}`);
        continue;
      }
    }

    let runs: RunEntry[];
    try {
      runs = (await readJson(runsFile)) as RunEntry[];
    } catch {
      continue;
    }

    for (const run of runs) {
      total++;
      if (!run.answer || typeof run.answer !== "object") {
        noAnswer++;
        results.push({
          budget,
          model,
          question: qid,
          arm,
          run: run.run_index,
          classification: run.classification,
          m3: null,
          note: "no answer (format_error/budget/etc)",
        });
        continue;
      }
      scored++;
      const m3 = scoreM3Cluster(run.answer, clusterInput);
      results.push({
        budget,
        model,
        question: qid,
        arm,
        run: run.run_index,
        classification: run.classification,
        m3: {
          overall: {
            precision_naive: round3(m3.overall.precisionNaive),
            precision_cluster: round3(m3.overall.precisionCluster),
            recall_sample: round3(m3.overall.recallSample),
          },
          stages: m3.stages.map((st) => ({
            stage: st.stage,
            precision_cluster: round3(st.precisionCluster),
            recall_sample: round3(st.recallSample),
            cited_count: st.citedCount,
          })),
          fields: Object.fromEntries(
            Object.entries(m3.fields).map(([k, v]) => [
              k,
              {
                precision_naive: round3(v.precisionNaive),
                precision_cluster: round3(v.precisionCluster),
                recall_sample: round3(v.recallSample),
                cited_count: v.citedCount,
              },
            ]),
          ),
        },
      });
    }
  }

  // 汇总
  const scoredResults = results.filter((r) => r.m3) as Array<{ m3: { overall: { precision_naive: number; precision_cluster: number; recall_sample: number } } }>;
  const avg = (f: (r: { m3: { overall: { precision_naive: number; precision_cluster: number; recall_sample: number } } }) => number): number =>
    scoredResults.length === 0 ? 0 : Number((scoredResults.reduce((a, b) => a + f(b), 0) / scoredResults.length).toFixed(3));

  const summary = {
    total_runs: total,
    scored_runs: scored,
    no_answer_runs: noAnswer,
    naive_precision_avg: avg((r) => r.m3.overall.precision_naive),
    cluster_precision_avg: avg((r) => r.m3.overall.precision_cluster),
    sample_recall_avg: avg((r) => r.m3.overall.recall_sample),
    note: "naive 把取证彻底误罚为不精确（cited 全攻击帧 vs gold 6 采样帧）；cluster 锚定修复 precision；sample recall 是独立维度",
  };

  const output = { generated_at: new Date().toISOString(), summary, runs: results };
  await writeFile(OUTPUT_PATH, `${JSON.stringify(output, null, 2)}\n`);
  console.log(`S3 重打分完成：${total} run（${scored} 有答案、${noAnswer} 无答案）`);
  console.log(`  naive_precision_avg   = ${summary.naive_precision_avg}`);
  console.log(`  cluster_precision_avg = ${summary.cluster_precision_avg}`);
  console.log(`  sample_recall_avg     = ${summary.sample_recall_avg}`);
  console.log(`产物：${OUTPUT_PATH}`);
  return 0;
}

function round3(x: number): number {
  return Number(x.toFixed(3));
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[rescore-s3] fatal:", err);
    process.exitCode = 1;
  },
);
