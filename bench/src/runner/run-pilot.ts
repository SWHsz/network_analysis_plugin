/**
 * Lane A pilot runner（vLLM 本地 lane）：S01-i1 × {r1,r2} × 3 臂 × qwen3.8-27b-fp8 × N run。
 *
 *   VLLM_BASE_URL=http://localhost:8000/v1 VLLM_MODEL=/data/models/qwen3.8-27b-fp8 \
 *     tsx src/runner/run-pilot.ts --lane vllm --runs 1 --yes
 *
 * Envelope：64 turns / 32k tokens / 1440s（C 方案宽 ceiling）
 * Breaker：K=3 / N=5（锁定，breaker-replay 定档）
 * 三臂：bash-v0.2 / ast-v0.5 / sql-v0.1
 */
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import readline from "node:readline/promises";
import path from "node:path";
import { Agent } from "@stirrup/stirrup";
import { SIMPLE_FINISH_TOOL } from "@stirrup/stirrup";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { scoreRun } from "../scorer/pipeline.js";
import { loadVllmConfig, pingVllm, startVllmRecordingProxy } from "./vllm-adapter.js";
import { detectBreaker, type TurnEvent } from "../scorer/breaker.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import { SqlArm } from "./sql-arm.js";
import { FINISH_TOOL_V02 } from "./finish-tool.js";
import { withTiming } from "./bash-arm.js";
import type { ArmResult, Budget, ToolCallRecord } from "./types.js";

const INSTANCES_DIR = path.join(REPO_ROOT, "bench", "fixtures", "instances");
const OUTPUT_DIR = path.join(REPO_ROOT, "bench", "out", "pilot-lane-a");
const ENVELOPE: Budget = { maxTurns: 64, maxTokens: 32_000, timeoutMs: 1_440_000 };
const BREAKER = { k: 3, n: 5 };
const ARMS = ["bash-v0.2", "ast-v0.5", "sql-v0.1"] as const;
const MODEL = "qwen3.8-27b-fp8";

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const assumeYes = argv.includes("--yes");
  const runs = argv.includes("--runs") ? Number(argv[argv.indexOf("--runs") + 1]) || 1 : 1;
  const cellFilter = argv.includes("--cell") ? argv[argv.indexOf("--cell") + 1] : "";
  const armFilter = argv.includes("--arm") ? argv[argv.indexOf("--arm") + 1] : "";
  const activeArms = armFilter ? ARMS.filter((a) => a.startsWith(armFilter)) : ARMS;

  // vLLM 配置
  const vllm = loadVllmConfig();
  if (!vllm) {
    console.error("[pilot] 需 VLLM_BASE_URL + VLLM_MODEL 环境变量");
    return 3;
  }
  const pingErr = await pingVllm(vllm);
  if (pingErr) {
    console.error(`[pilot] vLLM 预检失败：${pingErr}`);
    return 3;
  }

  // 发现可用 cell
  const cells: string[] = [];
  if (existsSync(INSTANCES_DIR)) {
    const { readdir } = await import("node:fs/promises");
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
  }
  cells.sort();
  const activeCells = cells.filter((c) => !cellFilter || c.includes(cellFilter));
  console.log(`[pilot] vLLM model=${vllm.model} cells=${activeCells.length} arms=${activeArms.length} runs=${runs}`);
  console.log(`  envelope=${JSON.stringify(ENVELOPE)} breaker=K${BREAKER.k}/N${BREAKER.n}`);

  // 启动 vLLM 录制代理（--direct 跳过 proxy 排障）
  const useDirect = argv.includes("--direct");
  let clientBaseURL: string;
  let proxy: Awaited<ReturnType<typeof startVllmRecordingProxy>> | null = null;
  if (useDirect) {
    clientBaseURL = vllm.baseURL;
    console.log(`  direct=${clientBaseURL} (no proxy)`);
  } else {
    proxy = await startVllmRecordingProxy(vllm);
    clientBaseURL = proxy.baseURL;
    console.log(`  proxy=${clientBaseURL}`);
  }
  const client = new ChatCompletionsClient({ model: vllm.model, apiKey: vllm.apiKey, baseURL: clientBaseURL });

  const results: Array<Record<string, unknown>> = [];

  try {
    for (const cell of activeCells) {
      const [s, i, r] = cell.split("/");
      assertSafeBasename(s!, "scenario");
      assertSafeBasename(i!, "instance");
      assertSafeBasename(r!, "tier");
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

      for (const armName of activeArms) {
        const arm = armName === "bash-v0.2" ? new BashArm(pcapPath)
          : armName === "ast-v0.5" ? new AstArm(pcapPath)
          : new SqlArm(pcapPath);

        for (let runIdx = 1; runIdx <= runs; runIdx++) {
          console.error(`\n===== ${cell}/${armName} run ${runIdx}/${runs} =====`);
          const t0 = Date.now();
          const records: ToolCallRecord[] = [];
          const turnEvents: TurnEvent[] = [];
          let llmCalls = 0, inputTokens = 0, outputTokens = 0;
          let answerRaw = "", finishCalled = false, aborted: string | null = null;
          let breakerSignal: import("../scorer/breaker.js").BreakerSignal | null = null;

          try {
            const agent = new Agent({
              client,
              name: `pilot-${armName.replace(/[^a-zA-Z0-9_-]/g, "-")}`,
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
              // 构建该轮的 TurnEvent（从该轮新增的 records 推断）
              const prevCount = turnEvents.reduce((a, ev) => a + ev.calls.length, 0);
              const newRecords = records.slice(prevCount);
              turnEvents.push({
                turn: llmCalls,
                calls: newRecords.map((rec) => ({
                  name: rec.name,
                  rawArgs: rec.rawArgs ?? JSON.stringify(rec.args ?? {}),
                  ok: rec.ok,
                  emptyArrival: rec.emptyArrival,
                })),
              });
              // 熔断检测
              breakerSignal = detectBreaker(turnEvents, BREAKER);
              if (breakerSignal) {
                console.error(`  [BREAKER] ${breakerSignal.rule} @ turn ${breakerSignal.turnIndex}: ${breakerSignal.detail}`);
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
              answerRaw = ((result as { finishParams?: { reason?: string } }).finishParams as { reason?: string })?.reason ?? "";
              finishCalled = result !== null && (result as { finishParams?: unknown }).finishParams !== undefined;
            } catch (e) {
              aborted = (e as Error).message;
            } finally {
              clearTimeout(timer);
            }
          } catch (e) {
            aborted = (e as Error).message;
          }

          const wallMs = Date.now() - t0;
          // 判分
          const extraction = extractFinalAnswer(answerRaw);
          const contract = validateAgainstContract(q.answer_schema as never, extraction);
          const scored = scoreRun(q as never, q as never, answerRaw, `${armName}#${runIdx}`);

          const entry = {
            cell, arm: armName, model: MODEL, run_index: runIdx,
            classification: scored.classification,
            answerRaw: answerRaw.slice(0, 500),
            answer: "answer" in contract ? contract.answer : null,
            formatError: "formatError" in contract ? contract.formatError : null,
            metrics: {
              llmCalls, inputTokens, outputTokens, wallMs,
              toolCalls: records.length,
              toolRenderChars: records.reduce((a, b) => a + b.resultChars, 0),
              interfaceTokens: proxy ? proxy.getCaptures()[0]?.estTokens ?? 0 : 0,
              budgetExhausted: aborted !== null || !finishCalled,
              breaker_fired: breakerSignal !== null,
              breaker_rule: breakerSignal?.rule ?? null,
              breaker_turn_index: breakerSignal?.turnIndex ?? null,
            },
            aborted,
          };
          results.push(entry);

          // 打印摘要
          for (const rec of records.slice(0, 5)) {
            console.error(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
          }
          if (records.length > 5) console.log(`  ... ${records.length - 5} more tool calls`);
          console.error(`  llmCalls=${llmCalls} in=${inputTokens} out=${outputTokens} wall=${wallMs}ms`);
          console.error(`  breaker=${breakerSignal ? breakerSignal.rule : "no"} exhausted=${entry.metrics.budgetExhausted}`);
          console.error(`  提取：${extraction.status === "ok" ? JSON.stringify(extraction.value).slice(0, 100) : `format_error(${extraction.reason})`} → ${scored.classification}`);

          // 逐 cell×arm 落盘（增量）
          const outDir = path.join(OUTPUT_DIR, cell.replace(/\//g, "-"), armName);
          await mkdir(outDir, { recursive: true });
          await writeFile(path.join(outDir, `run-${runIdx}.json`), `${JSON.stringify(entry, null, 2)}\n`);
        }
      }
    }
  } finally {
    if (proxy) proxy.close();
  }

  // 汇总报告
  const reportPath = path.join(OUTPUT_DIR, "pilot-summary.json");
  const summary = {
    generated_at: new Date().toISOString(),
    model: MODEL,
    envelope: ENVELOPE,
    breaker: BREAKER,
    total_runs: results.length,
    classifications: results.reduce((acc: Record<string, number>, r) => {
      const c = (r as { classification: string }).classification;
      acc[c] = (acc[c] ?? 0) + 1;
      return acc;
    }, {}),
    breaker_fired_count: results.filter((r) => (r as { metrics: { breaker_fired?: boolean } }).metrics.breaker_fired).length,
    budget_exhausted_count: results.filter((r) => (r as { metrics: { budgetExhausted?: boolean } }).metrics.budgetExhausted).length,
    runs: results,
  };
  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`\n[pilot] 完成：${results.length} run，报告 ${reportPath}`);
  console.log(`  分类：${JSON.stringify(summary.classifications)}`);
  console.log(`  熔断：${summary.breaker_fired_count}，触顶：${summary.budget_exhausted_count}`);

  return 0;
}

main().then(
  (c) => { process.exitCode = c; },
  (e) => { console.error("[pilot] fatal:", e); process.exitCode = 1; },
);
