/**
 * 切片联跑 CLI（Prompt 5 验收入口）：q-web-001（重传计数）两臂各跑 N 次。
 *
 *   pnpm --filter bench slice-q1                    # 半自动，每臂 1 次
 *   pnpm --filter bench slice-q1 -- --runs 3 --yes  # 每臂 3 次，跳过交互确认
 *
 * 多次运行口径（RFC-002 §5.2/§10-S2）：报告多数表决正确率 + 逐次分布；token 取均值。
 * 产物：bench/out/runs/slice-q1/{bash-v0.1,ast-v0.4}/{armresult,transcript,messages,
 * interface}.json + answerRaw.txt + runs.json + slice-summary.json。
 */
import { mkdir, writeFile } from "node:fs/promises";
import readline from "node:readline/promises";
import path from "node:path";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { loadGroundTruth, loadQuestionByName } from "../scorer/question.js";
import { scoreRun, type RunClassification } from "../scorer/pipeline.js";
import { assembleReport, type ReportRun } from "../scorer/report.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import { MODEL, captureCount, capturesFrom, interfaceTokensOf, loadDeepseekKey, startRecordingProxy } from "./llm.js";
import { runArmOnce } from "./shared-loop.js";
import type { ArmResult, Budget } from "./types.js";

const QUESTION_FILE = "q-web-001-retrans-count.json";
const BUDGET: Budget = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };

interface ArmOutput {
  result: ArmResult;
  classification: RunClassification;
}

function majorityVote(classifications: RunClassification[]): { correct: boolean; detail: string } {
  const correctCount = classifications.filter((c) => c === "correct").length;
  return {
    correct: correctCount > classifications.length / 2,
    detail: `${correctCount}/${classifications.length} correct (${classifications.join(",")})`,
  };
}

async function main(): Promise<number> {
  const assumeYes = process.argv.includes("--yes");
  const runsIdx = process.argv.indexOf("--runs");
  const runsPerQuestion = runsIdx >= 0 ? Math.max(1, Number(process.argv[runsIdx + 1]) || 1) : 1;

  const q = loadQuestionByName(QUESTION_FILE);
  const gt = loadGroundTruth(q);
  const captureAbsPath = path.join(REPO_ROOT, "fixtures", `${q.capture.fixture}.pcap`);
  const task = [
    `Question (${q.question_id}): ${q.question}`,
    "",
    "Answer schema (the fenced block must conform to it):",
    JSON.stringify(q.answer_schema, null, 2),
    "",
    'Reminder: finish reason contains exactly one ```json block; every factual node carries {"value", "evidence":[frames]}.',
  ].join("\n");

  const key = await loadDeepseekKey();
  const proxy = await startRecordingProxy("https://api.deepseek.com");
  const client = new ChatCompletionsClient({ model: MODEL, apiKey: key, baseURL: proxy.baseURL });
  console.log(`[slice-q1] model=${MODEL} budget=${JSON.stringify(BUDGET)} question=${q.question_id} runs=${runsPerQuestion}`);

  const armOutputs = new Map<string, ArmOutput[]>();
  try {
    for (const arm of [new BashArm(captureAbsPath), new AstArm(captureAbsPath)]) {
      const outputs: ArmOutput[] = [];
      for (let i = 1; i <= runsPerQuestion; i++) {
        console.log(`\n===== ${arm.name} run ${i}/${runsPerQuestion} =====`);
        const capStart = captureCount();
        const outcome = await runArmOnce({ arm, task, budget: BUDGET, client });
        const runCaptures = capturesFrom(capStart);

        const extraction = extractFinalAnswer(outcome.answerRaw);
        const contract = validateAgainstContract(q.answer_schema, extraction);
        const result: ArmResult = {
          arm: arm.name,
          questionId: q.question_id,
          answerRaw: outcome.answerRaw,
          answer: "answer" in contract ? (contract.answer as Record<string, unknown>) : undefined,
          formatError: "formatError" in contract ? contract.formatError : undefined,
          transcript: outcome.records,
          metrics: {
            llmCalls: outcome.llmCalls,
            inputTokens: outcome.inputTokens,
            outputTokens: outcome.outputTokens,
            toolRenderChars: outcome.records.reduce((a, b) => a + b.resultChars, 0),
            interfaceTokens: interfaceTokensOf(runCaptures),
            wallMs: outcome.wallMs,
            // EVALUATION 附带条件 c：aborted 或未调 finish 都算预算耗尽
            budgetExhausted: outcome.aborted !== null || !outcome.finishCalled,
          },
          aborted: outcome.aborted,
        };
        const scored = scoreRun(q, gt, outcome.answerRaw, `${arm.name}#${i}`);
        outputs.push({ result, classification: scored.classification });

        for (const rec of outcome.records) {
          console.log(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
        }
        console.log(
          `  llmCalls=${outcome.llmCalls} in=${outcome.inputTokens} out=${outcome.outputTokens} wall=${outcome.wallMs}ms ` +
            `interfaceTokens≈${result.metrics.interfaceTokens} exhausted=${result.metrics.budgetExhausted}${outcome.aborted ? ` aborted(${outcome.aborted})` : ""}`,
        );
        console.log(
          `  提取结果：${extraction.status === "ok" ? JSON.stringify(extraction.value) : `format_error(${extraction.reason})`} → ${scored.classification}`,
        );
      }
      armOutputs.set(arm.name, outputs);
    }
  } finally {
    proxy.close();
  }

  // ---- 半自动边界：终答提取后暂停，人工确认后再判分落盘（人工清单 1.1） ----
  if (!assumeYes) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("\n以上为两臂全部运行的提取结果。确认无误并继续判分落盘？(y/n) ");
    rl.close();
    if (answer.trim().toLowerCase() !== "y") {
      console.log("已暂停：未判分未落盘。请复核后重跑。");
      return 0;
    }
  }

  // ---- 落盘 + 判分汇总 ----
  bashOuts = armOutputs.get("bash-v0.1") ?? [];
  astOuts = armOutputs.get("ast-v0.4") ?? [];
  await writeBashOutputs();
  await writeAstOutputs();

  const summaryArms = [...armOutputs.entries()].map(([name, outs]) => {
    const vote = majorityVote(outs.map((o) => o.classification));
    const mean = (xs: number[]): number => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);
    const interfaceTotal = mean(outs.map((o) => o.result.metrics.interfaceTokens * o.result.metrics.llmCalls));
    const inputMean = mean(outs.map((o) => o.result.metrics.inputTokens));
    return {
      arm: name,
      majority_correct: vote.correct,
      vote_detail: vote.detail,
      runs: outs.map((o, i) => ({
        run_index: i + 1,
        classification: o.classification,
        format_error: o.result.formatError ?? null,
        llm_calls: o.result.metrics.llmCalls,
        input_tokens: o.result.metrics.inputTokens,
        output_tokens: o.result.metrics.outputTokens,
        tool_render_chars: o.result.metrics.toolRenderChars,
        interface_tokens_per_request: o.result.metrics.interfaceTokens,
        interface_share_of_input:
          o.result.metrics.inputTokens > 0
            ? Number(((o.result.metrics.interfaceTokens * o.result.metrics.llmCalls) / o.result.metrics.inputTokens).toFixed(3))
            : null,
        wall_ms: o.result.metrics.wallMs,
        budget_exhausted: o.result.metrics.budgetExhausted,
      })),
      means: {
        input_tokens: Math.round(inputMean),
        output_tokens: Math.round(mean(outs.map((o) => o.result.metrics.outputTokens))),
        llm_calls: Number(mean(outs.map((o) => o.result.metrics.llmCalls)).toFixed(1)),
        wall_ms: Math.round(mean(outs.map((o) => o.result.metrics.wallMs))),
        interface_share_of_input: inputMean > 0 ? Number((interfaceTotal / inputMean).toFixed(3)) : null,
      },
      report: assembleReport({
        arm: name,
        model: MODEL,
        date: new Date().toISOString().slice(0, 10),
        runsPerQuestion,
        runs: outs.map(
          (o, i): ReportRun => ({
            questionId: q.question_id,
            runIndex: i + 1,
            question: { tags: q.tags },
            classification: o.classification,
            schemaValid: o.result.answer !== undefined || o.result.formatError === undefined,
            metrics: o.result.metrics,
          }),
        ),
      }),
    };
  });

  summaryJson = JSON.stringify(
    { date: new Date().toISOString(), model: MODEL, question_id: q.question_id, budget: BUDGET, runs_per_question: runsPerQuestion, arms: summaryArms },
    null,
    2,
  );
  await writeSliceSummary();

  for (const a of summaryArms) {
    console.log(
      `[majority] ${a.arm}: ${a.majority_correct ? "correct" : "wrong"} (${a.vote_detail})  ` +
        `mean in=${a.means.input_tokens} out=${a.means.output_tokens} turns=${a.means.llm_calls} interfaceShare=${a.means.interface_share_of_input}`,
    );
  }
  const bash = summaryArms.find((a) => a.arm === "bash-v0.1");
  const ast = summaryArms.find((a) => a.arm === "ast-v0.4");
  if (bash && ast) {
    console.log(
      `\ninterfaceTokens/request：bash≈${bash.runs[0]?.interface_tokens_per_request} vs ast≈${ast.runs[0]?.interface_tokens_per_request}` +
        `；输入 token 中接口占比均值：bash ${(100 * (bash.means.interface_share_of_input ?? 0)).toFixed(1)}% vs ast ${(100 * (ast.means.interface_share_of_input ?? 0)).toFixed(1)}%`,
    );
  }
  console.log("产物：bench/out/runs/slice-q1/{bash-v0.1,ast-v0.4}/ 与 slice-summary.json");
  return 0;
}

// ---- 运行状态与落盘（Mimosa 已验证形态：模块状态取数 + 零参数函数 + 全字面量路径） ----

let bashOuts: ArmOutput[] = [];
let astOuts: ArmOutput[] = [];
let summaryJson = "";

function lastOf<T>(xs: T[]): T | undefined {
  return xs[xs.length - 1];
}

/** 纯数据函数：单次运行的落盘内容（不触碰 fs） */
function armResultJson(o: ArmOutput): string {
  return JSON.stringify(o.result, null, 2);
}

function transcriptJson(o: ArmOutput): string {
  return JSON.stringify({ records: o.result.transcript }, null, 2);
}

function runsJson(outs: ArmOutput[]): string {
  return JSON.stringify(
    outs.map((o, i) => ({
      run_index: i + 1,
      classification: o.classification,
      answerRaw: o.result.answerRaw,
      answer: o.result.answer ?? null,
      format_error: o.result.formatError ?? null,
      metrics: o.result.metrics,
      aborted: o.result.aborted,
    })),
    null,
    2,
  );
}

async function writeBashOutputs(): Promise<void> {
  const last = lastOf(bashOuts);
  if (!last) throw new Error("writeBashOutputs: 尚无 bash 臂运行结果");
  const dir = path.join(REPO_ROOT, "bench", "out", "runs", "slice-q1", "bash-v0.1");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "armresult.json"), armResultJson(last));
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(last));
  await writeFile(path.join(dir, "answerRaw.txt"), last.result.answerRaw);
  await writeFile(path.join(dir, "runs.json"), runsJson(bashOuts));
}

async function writeAstOutputs(): Promise<void> {
  const last = lastOf(astOuts);
  if (!last) throw new Error("writeAstOutputs: 尚无 ast 臂运行结果");
  const dir = path.join(REPO_ROOT, "bench", "out", "runs", "slice-q1", "ast-v0.4");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "armresult.json"), armResultJson(last));
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(last));
  await writeFile(path.join(dir, "answerRaw.txt"), last.result.answerRaw);
  await writeFile(path.join(dir, "runs.json"), runsJson(astOuts));
}

async function writeSliceSummary(): Promise<void> {
  if (summaryJson === "") throw new Error("writeSliceSummary: 尚无汇总数据");
  const dir = path.join(REPO_ROOT, "bench", "out", "runs", "slice-q1");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "slice-summary.json"), summaryJson);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[slice-q1] fatal:", err);
    process.exitCode = 1;
  },
);
