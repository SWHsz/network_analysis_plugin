/**
 * Lane B zen pilot：4 模型 × 3 臂 × 可用 cell × N run，经 opengo2 路由。
 *
 *   tsx src/runner/run-zen-pilot.ts --runs 3 --yes                # 全量
 *   tsx src/runner/run-zen-pilot.ts --runs 1 --model flash --arm bash --cell s01/i1/r1 --yes  # 冒烟
 *   tsx src/runner/run-zen-pilot.ts --wave 1 --yes                # wave1 = r1 only
 *
 * Envelope 64t/32k/1440s，Breaker K=3/N=5，逐 cell×arm×model 增量落盘。
 */
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import readline from "node:readline/promises";
import path from "node:path";
import { Agent } from "@stirrup/stirrup";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { scoreRun } from "../scorer/pipeline.js";
import { detectBreaker, type TurnEvent, type BreakerSignal } from "../scorer/breaker.js";
import { PROVIDERS, loadApiKey, startRecordingProxy, pingProvider, interfaceTokensOf } from "./llm.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import { SqlArm } from "./sql-arm.js";
import { FINISH_TOOL_V02 } from "./finish-tool.js";
import type { Budget, ToolCallRecord } from "./types.js";

const INSTANCES_DIR = path.join(REPO_ROOT, "bench", "fixtures", "instances");
const OUTPUT_DIR = path.join(REPO_ROOT, "bench", "out", "pilot-lane-b");
const ENVELOPE: Budget = { maxTurns: 64, maxTokens: 32_000, timeoutMs: 1_440_000 };
const BREAKER = { k: 3, n: 5 };
const ARMS = ["bash-v0.2", "ast-v0.5", "sql-v0.1"] as const;
const ZEN_MODELS = ["deepseek-v4-flash", "deepseek-v4-pro", "glm-5.3", "kimi-k3"] as const;

async function discoverCells(): Promise<string[]> {
  const { readdir } = await import("node:fs/promises");
  const cells: string[] = [];
  if (!existsSync(INSTANCES_DIR)) return cells;
  for (const s of await readdir(INSTANCES_DIR, { withFileTypes: true })) {
    if (!s.isDirectory()) continue;
    for (const i of await readdir(path.join(INSTANCES_DIR, s.name), { withFileTypes: true })) {
      if (!i.isDirectory()) continue;
      for (const r of await readdir(path.join(INSTANCES_DIR, s.name, i.name), { withFileTypes: true })) {
        if (r.isDirectory() && existsSync(path.join(INSTANCES_DIR, s.name, i.name, r.name, "bench-question.json"))) {
          cells.push(`${s.name}/${i.name}/${r.name}`);
        }
      }
    }
  }
  return cells.sort();
}

/** 逐 cell×arm×model 增量落盘路径（白名单段拼接） */
function runFile(model: string, arm: string, cell: string, runIdx: number): string {
  const cellSlug = cell.replace(/\//g, "-");
  assertSafeBasename(model, "模型名");
  assertSafeBasename(arm, "臂名");
  assertSafeBasename(cellSlug, "cell 名");
  const dir = path.join(OUTPUT_DIR, model, arm, cellSlug);
  return path.join(dir, `run-${runIdx}.json`);
}

function runExists(model: string, arm: string, cell: string, runIdx: number): boolean {
  return existsSync(runFile(model, arm, cell, runIdx));
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const assumeYes = argv.includes("--yes");
  const runsPerCombo = argv.includes("--runs") ? Number(argv[argv.indexOf("--runs") + 1]) || 3 : 3;
  const modelFilter = argv.includes("--model") ? argv[argv.indexOf("--model") + 1] : "";
  const armFilter = argv.includes("--arm") ? argv[argv.indexOf("--arm") + 1] : "";
  const cellFilter = argv.includes("--cell") ? argv[argv.indexOf("--cell") + 1] : "";
  const wave = argv.includes("--wave") ? Number(argv[argv.indexOf("--wave") + 1]) || 0 : 0;

  const allCells = await discoverCells();
  const models = ZEN_MODELS.filter((m) => !modelFilter || m.includes(modelFilter));
  const arms = ARMS.filter((a) => !armFilter || a.startsWith(armFilter));
  let cells = allCells.filter((c) => !cellFilter || c.includes(cellFilter));
  if (wave === 1) cells = cells.filter((c) => c.includes("r1"));
  if (wave === 2) cells = cells.filter((c) => !c.includes("r1"));

  const totalPlanned = models.length * arms.length * cells.length * runsPerCombo;
  console.log(`[zen-pilot] models=${models.length} arms=${arms.length} cells=${cells.length} runs=${runsPerCombo} → ${totalPlanned} run`);
  console.log(`  envelope=${JSON.stringify(ENVELOPE)} breaker=K${BREAKER.k}/N${BREAKER.n}`);

  // 预检全部模型
  const provider = PROVIDERS.opengo2!;
  const key = await loadApiKey(provider);
  for (const m of models) {
    const err = await pingProvider(provider, key, m);
    if (err) {
      console.error(`[zen-pilot] 预检失败 ${m}: ${err}`);
      return 3;
    }
  }
  console.log(`  预检: ${models.length}/${models.length} PASS`);

  const proxy = await startRecordingProxy(provider.upstream);
  console.log(`  proxy=${proxy.baseURL}`);

  const results: Array<Record<string, unknown>> = [];
  let completed = 0, skipped = 0;

  try {
    for (const model of models) {
      // 逐模型建 client（model 名是 client 级配置，非请求级）
      const client = new ChatCompletionsClient({ model, apiKey: key, baseURL: proxy.baseURL });
      for (const cell of cells) {
        const [s, i, r] = cell.split("/");
        const instDir = path.join(INSTANCES_DIR, s!, i!, r!);
        const q = JSON.parse(await readFile(path.join(instDir, "bench-question.json"), "utf8")) as Record<string, unknown>;
        const pcapPath = path.join(instDir, "benchmark.pcap");
        const task = [
          `Question (${q.question_id}): ${q.question}`,
          "",
          "Answer schema (the fenced block must conform to it):",
          JSON.stringify(q.answer_schema, null, 2),
          "",
          'Reminder: finish reason contains exactly one ```json block; every factual node carries {"value", "evidence":[frames]}.',
        ].join("\n");

        for (const armName of arms) {
          for (let runIdx = 1; runIdx <= runsPerCombo; runIdx++) {
            // 增量跳过已落盘 run
            if (runExists(model, armName, cell, runIdx)) {
              skipped++;
              continue;
            }

            console.log(`\n===== ${model}/${cell}/${armName} run ${runIdx}/${runsPerCombo} =====`);
            const arm = armName === "bash-v0.2" ? new BashArm(pcapPath)
              : armName === "ast-v0.5" ? new AstArm(pcapPath)
              : new SqlArm(pcapPath);

            const t0 = Date.now();
            const records: ToolCallRecord[] = [];
            const turnEvents: TurnEvent[] = [];
            let llmCalls = 0, inputTokens = 0, outputTokens = 0;
            let answerRaw = "", finishCalled = false, aborted: string | null = null;
            let breakerSignal: import("../scorer/breaker.js").BreakerSignal | null = null;

            try {
              const agent = new Agent({
                client,
                name: `zen-${model}-${armName}`.replace(/[^a-zA-Z0-9_-]/g, "-"),
                maxTurns: ENVELOPE.maxTurns,
                systemPrompt: arm.systemPrompt,
                tools: arm.buildTools(records),
                finishTool: FINISH_TOOL_V02,
              });

              const ac = new AbortController();
              agent.on("turn:complete", (d: { tokenUsage?: { input?: number; output?: number } }) => {
                llmCalls++;
                inputTokens += d.tokenUsage?.input ?? 0;
                outputTokens += d.tokenUsage?.output ?? 0;
                const prevCount = turnEvents.reduce((a, ev) => a + ev.calls.length, 0);
                const newRecords = records.slice(prevCount);
                turnEvents.push({
                  turn: llmCalls,
                  calls: newRecords.map((rec) => ({
                    name: rec.name, rawArgs: rec.rawArgs ?? JSON.stringify(rec.args ?? {}),
                    ok: rec.ok, emptyArrival: rec.emptyArrival,
                  })),
                });
                breakerSignal = detectBreaker(turnEvents, BREAKER);
                if (breakerSignal) {
                  const bs: import("../scorer/breaker.js").BreakerSignal = breakerSignal;
                  console.error(`  [BREAKER] ${bs.rule} @ turn ${bs.turnIndex}: ${bs.detail}`);
                  ac.abort(new Error(`breaker: ${breakerSignal.rule}`));
                }
                if (outputTokens > ENVELOPE.maxTokens) {
                  ac.abort(new Error(`output budget: ${outputTokens} > ${ENVELOPE.maxTokens}`));
                }
              });

              const timer = setTimeout(() => ac.abort(new Error(`timeout ${ENVELOPE.timeoutMs}ms`)), ENVELOPE.timeoutMs);
              agent.session({ noLogger: true });
              try {
                const result = await agent.run(task, { signal: ac.signal });
                const fp = (result as { finishParams?: { reason?: string } }).finishParams;
                answerRaw = fp?.reason ?? "";
                finishCalled = fp !== undefined;
              } catch (e) {
                aborted = (e as Error).message;
              } finally {
                clearTimeout(timer);
              }
            } catch (e) {
              aborted = (e as Error).message;
            }

            const wallMs = Date.now() - t0;
            const extraction = extractFinalAnswer(answerRaw);
            const contract = validateAgainstContract(q.answer_schema as never, extraction);
            const scored = scoreRun(q as never, q as never, answerRaw, `${armName}#${runIdx}`);

            const entry = {
              model, cell, arm: armName, run_index: runIdx,
              classification: scored.classification,
              answerRaw: answerRaw.slice(0, 500),
              answer: "answer" in contract ? contract.answer : null,
              formatError: "formatError" in contract ? contract.formatError : null,
              metrics: {
                llmCalls, inputTokens, outputTokens, wallMs,
                toolCalls: records.length,
                toolRenderChars: records.reduce((a, b) => a + b.resultChars, 0),
                budgetExhausted: aborted !== null || !finishCalled,
                breaker_fired: breakerSignal !== null,
                breaker_rule: breakerSignal?.rule ?? null,
                breaker_turn_index: breakerSignal?.turnIndex ?? null,
              },
              aborted,
            };
            results.push(entry);
            completed++;

            console.error(`  turns=${llmCalls} in=${inputTokens} out=${outputTokens} wall=${(wallMs/1000).toFixed(0)}s`);
            console.error(`  breaker=${breakerSignal?.rule ?? "no"} exhausted=${entry.metrics.budgetExhausted}`);
            console.error(`  → ${scored.classification}`);

            // 逐 run 落盘
            const rf = runFile(model, armName, cell, runIdx);
            await mkdir(path.dirname(rf), { recursive: true });
            await writeFile(rf, `${JSON.stringify(entry, null, 2)}\n`);
          }
        }
      }
    }
  } finally {
    proxy.close();
  }

  // 汇总
  const summaryPath = path.join(OUTPUT_DIR, "zen-pilot-summary.json");
  const summary = {
    generated_at: new Date().toISOString(),
    models, arms, cells, runs_per_combo: runsPerCombo,
    envelope: ENVELOPE, breaker: BREAKER,
    completed, skipped,
    classifications: results.reduce((acc: Record<string, number>, r) => {
      const c = (r as { classification: string }).classification;
      acc[c] = (acc[c] ?? 0) + 1; return acc;
    }, {}),
    runs: results,
  };
  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`\n[zen-pilot] 完成：${completed} run（跳过 ${skipped} 已有），报告 ${summaryPath}`);
  console.log(`  分类：${JSON.stringify(summary.classifications)}`);
  return 0;
}

main().then(
  (c) => { process.exitCode = c; },
  (e) => { console.error("[zen-pilot] fatal:", e); process.exitCode = 1; },
);
