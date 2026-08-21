/**
 * 切片联跑 CLI（Prompt 5 验收入口）：q-web-001（重传计数）两臂各跑一次。
 *
 *   pnpm --filter bench slice-q1          # 半自动：终答提取后暂停等人工确认（清单 1.1）
 *   pnpm --filter bench slice-q1 -- --yes # 跳过交互确认（操作员已复核场景）
 *
 * 产物：bench/out/runs/slice-q1/{bash-v0.1,ast-v0.4}/{armresult,transcript,messages,
 * interface}.json + answerRaw.txt + slice-summary.json（含两臂 interfaceTokens 差异）。
 */
import { mkdir, writeFile } from "node:fs/promises";
import readline from "node:readline/promises";
import path from "node:path";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { loadGroundTruth, loadQuestionByName } from "../scorer/question.js";
import { scoreRun } from "../scorer/pipeline.js";
import { assembleReport, type ReportRun } from "../scorer/report.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import { MODEL, captureCount, capturesFrom, interfaceTokensOf, loadDeepseekKey, startRecordingProxy } from "./llm.js";
import { runArmOnce } from "./shared-loop.js";
import type { ArmResult, Budget } from "./types.js";

const QUESTION_FILE = "q-web-001-retrans-count.json";
const BUDGET: Budget = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };

async function main(): Promise<number> {
  const assumeYes = process.argv.includes("--yes");
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
  console.log(`[slice-q1] model=${MODEL} budget=${JSON.stringify(BUDGET)} question=${q.question_id}`);

  const results: ArmResult[] = [];
  try {
    for (const arm of [new BashArm(captureAbsPath), new AstArm(captureAbsPath)]) {
      console.log(`\n===== ${arm.name} =====`);
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
      results.push(result);

      if (arm.name === "bash-v0.1") {
        bashOut = { result, outcome, runCaptures };
        await writeBashOutputs();
      } else {
        astOut = { result, outcome, runCaptures };
        await writeAstOutputs();
      }

      for (const rec of outcome.records) {
        console.log(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
      }
      console.log(
        `  llmCalls=${outcome.llmCalls} in=${outcome.inputTokens} out=${outcome.outputTokens} wall=${outcome.wallMs}ms ` +
          `interfaceTokens≈${result.metrics.interfaceTokens} exhausted=${result.metrics.budgetExhausted}${outcome.aborted ? ` aborted(${outcome.aborted})` : ""}`,
      );
      console.log(`  提取结果：${extraction.status === "ok" ? JSON.stringify(extraction.value) : `format_error(${extraction.reason})`}`);
    }
  } finally {
    proxy.close();
  }

  // ---- 半自动边界：终答提取后暂停，人工确认后再判分（人工清单 1.1） ----
  if (!assumeYes) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("\n以上为两臂终答提取结果。确认无误并继续判分？(y/n) ");
    rl.close();
    if (answer.trim().toLowerCase() !== "y") {
      console.log("已暂停：transcript 已落盘，未判分。请复核后重跑或手动判分。");
      return 0;
    }
  }

  // ---- 判分 + 汇总 ----
  const scored = results.map((r) => ({
    result: r,
    run: scoreRun(q, gt, r.answerRaw, r.arm),
  }));
  for (const s of scored) {
    console.log(
      `[score] ${s.result.arm}: ${s.run.classification}` +
        (s.run.correctness ? ` fields=${JSON.stringify(s.run.correctness.fields.map((f) => [f.path, f.pass]))}` : "") +
        (s.run.formatError ? ` (${s.run.formatError})` : ""),
    );
  }

  const reportRuns: ReportRun[] = results.map((r, i) => {
    const s = scored[i]!;
    return {
      questionId: q.question_id,
      runIndex: i + 1,
      question: { tags: q.tags },
      classification: s.run.classification,
      schemaValid: s.run.schemaValid,
      evidence: s.run.evidence
        ? {
            coverage: s.run.evidence.coverage,
            macroPrecision: s.run.evidence.macroPrecision,
            macroRecall: s.run.evidence.macroRecall,
            allFieldsPass: s.run.evidence.fields.every((f) => f.pass),
            needsHumanReviewFields: s.run.evidence.fields.filter((f) => f.needsHumanReview).map((f) => f.path),
          }
        : undefined,
      hallucination: s.run.hallucination,
      metrics: r.metrics,
    };
  });

  const bash = results[0]!;
  const ast = results[1]!;
  summaryJson = JSON.stringify(
    {
      date: new Date().toISOString(),
      model: MODEL,
      question_id: q.question_id,
      budget: BUDGET,
      arms: results.map((r) => ({ ...r, transcript: undefined })),
      interface_tokens: {
        bash_v01: bash.metrics.interfaceTokens,
        ast_v04: ast.metrics.interfaceTokens,
        delta: ast.metrics.interfaceTokens - bash.metrics.interfaceTokens,
        note: "chars/4 启发式，记录代理实测首请求 system+tools 载荷（RFC-002 §10-I3 控制变量）",
      },
      reports: {
        bash: assembleReport({ arm: bash.arm, model: MODEL, date: new Date().toISOString().slice(0, 10), runsPerQuestion: 1, runs: [reportRuns[0]!] }),
        ast: assembleReport({ arm: ast.arm, model: MODEL, date: new Date().toISOString().slice(0, 10), runsPerQuestion: 1, runs: [reportRuns[1]!] }),
      },
    },
    null,
    2,
  );
  await writeSliceSummary();

  console.log(
    `\ninterfaceTokens：bash-v0.1≈${bash.metrics.interfaceTokens} vs ast-v0.4≈${ast.metrics.interfaceTokens}（Δ=${ast.metrics.interfaceTokens - bash.metrics.interfaceTokens}）`,
  );
  console.log("产物：bench/out/runs/slice-q1/{bash-v0.1,ast-v0.4}/ 与 slice-summary.json");
  return 0;
}

// ---- 运行状态与落盘（Mimosa 已验证形态：模块状态取数 + 零参数函数 + 全字面量路径） ----

interface ArmOutput {
  result: ArmResult;
  outcome: Awaited<ReturnType<typeof runArmOnce>>;
  runCaptures: ReturnType<typeof capturesFrom>;
}

let bashOut: ArmOutput | null = null;
let astOut: ArmOutput | null = null;
let summaryJson = "";

function armResultJson(o: ArmOutput): string {
  const { transcript, ...rest } = o.result;
  return JSON.stringify({ ...rest, transcript }, null, 2);
}

async function writeArmOutputs(dir: string, o: ArmOutput): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "armresult.json"), armResultJson(o));
  await writeFile(path.join(dir, "transcript.json"), JSON.stringify({ records: o.result.transcript }, null, 2));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(o.outcome.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), o.result.answerRaw);
  await writeFile(
    path.join(dir, "interface.json"),
    JSON.stringify(
      {
        estTokensFirstRequest: o.runCaptures[0]?.estTokens ?? 0,
        perRequest: o.runCaptures.map((c) => ({ systemChars: c.systemChars, toolsChars: c.toolsChars, estTokens: c.estTokens })),
        systemText: o.runCaptures[0]?.systemText ?? "",
        toolsJson: JSON.parse(o.runCaptures[0]?.toolsJson || "[]"),
      },
      null,
      2,
    ),
  );
}

async function writeBashOutputs(): Promise<void> {
  if (!bashOut) throw new Error("writeBashOutputs: 尚无 bash 臂运行结果");
  await writeArmOutputs(path.join(REPO_ROOT, "bench", "out", "runs", "slice-q1", "bash-v0.1"), bashOut);
}

async function writeAstOutputs(): Promise<void> {
  if (!astOut) throw new Error("writeAstOutputs: 尚无 ast 臂运行结果");
  await writeArmOutputs(path.join(REPO_ROOT, "bench", "out", "runs", "slice-q1", "ast-v0.4"), astOut);
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
