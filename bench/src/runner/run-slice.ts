/**
 * 通用切片联跑 CLI：对指定的已终审切片题运行两臂对照。
 *
 *   pnpm --filter bench slice-all              # 全部五道切片题，每臂 3 次
 *   pnpm --filter bench slice-q2               # 单题
 *   tsx src/runner/run-slice.ts q-web-002 --runs 3 --yes
 *
 * 默认题集 SLICE_QUESTION_IDS 为已终审的五道切片题；显式传其它 question_id 亦可，
 * 但批量稿（questions-auto）与待审起草题不应在终审前进入实验。
 *
 * 产物：bench/out/runs/<question_id>/{bash-v0.1,ast-v0.4}/{armresult,transcript,
 * messages,runs}.json + answerRaw.txt + slice-summary.json；
 * 汇总：bench/out/all-summary.json（入库的确定性聚合证据）。
 * 写盘边界：与 deriver 同构——字面量基目录 + 逐段白名单 + 解析后包含检查。
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import readline from "node:readline/promises";
import path from "node:path";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { loadGroundTruth, loadQuestionsDir, type Question } from "../scorer/question.js";
import { scoreRun, type RunClassification } from "../scorer/pipeline.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import { MODEL, captureCount, capturesFrom, interfaceTokensOf, loadDeepseekKey, startRecordingProxy } from "./llm.js";
import { runArmOnce } from "./shared-loop.js";
import type { ArmResult, Budget } from "./types.js";

/** 已终审的 E1 切片题（--all 的默认题集；顺序即任务书 Q1–Q5） */
const SLICE_QUESTION_IDS = [
  "q-web-001", // Q1 重传计数
  "q-web-002", // Q2 top3 会话（set）
  "q-edge-001", // Q3 零窗口存在性（enum）
  "q-web-003", // Q4 重传+握手耗时（record）
  "q-web-004", // Q5 DNS TTL（raw_query_only）
];
const ARMS = ["bash-v0.1", "ast-v0.4"] as const;
const BUDGET: Budget = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };

const OUT_RUNS_DIR = path.join(REPO_ROOT, "bench", "out", "runs");
const ALL_SUMMARY_PATH = path.join(REPO_ROOT, "bench", "out", "all-summary.json");

interface ArmOutput {
  result: ArmResult;
  classification: RunClassification;
  messageHistory: unknown[];
}

/** 逐段白名单 + 最终包含检查（写盘边界，模式同 deriver 的 containedIn） */
function containedPath(segments: string[]): string {
  let cur = OUT_RUNS_DIR;
  for (const seg of segments) {
    assertSafeBasename(seg, "输出路径段");
    cur = path.join(cur, seg);
  }
  const full = path.resolve(cur);
  if (!full.startsWith(OUT_RUNS_DIR + path.sep)) {
    throw new Error(`路径越出运行产物目录：${full}`);
  }
  return full;
}

function majorityVote(classifications: RunClassification[]): { correct: boolean; detail: string } {
  const correctCount = classifications.filter((c) => c === "correct").length;
  return {
    correct: correctCount > classifications.length / 2,
    detail: `${correctCount}/${classifications.length}`,
  };
}

const meanOf = (xs: number[]): number => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const assumeYes = argv.includes("--yes");
  const runsIdx = argv.indexOf("--runs");
  const runsPerQuestion = runsIdx >= 0 ? Math.max(1, Number(argv[runsIdx + 1]) || 3) : 3;
  const idArgs = argv.filter((a) => !a.startsWith("--") && a !== String(runsPerQuestion));
  const wantedIds = idArgs.length > 0 ? idArgs : SLICE_QUESTION_IDS;

  const all = loadQuestionsDir();
  const targets: Question[] = [];
  for (const id of wantedIds) {
    const q = all.find((x) => x.question_id === id);
    if (!q) {
      console.error(`[run-slice] 题库中不存在 ${id}`);
      return 2;
    }
    targets.push(q);
  }

  const key = await loadDeepseekKey();
  const proxy = await startRecordingProxy("https://api.deepseek.com");
  const client = new ChatCompletionsClient({ model: MODEL, apiKey: key, baseURL: proxy.baseURL });
  console.log(`[run-slice] model=${MODEL} budget=${JSON.stringify(BUDGET)} runs=${runsPerQuestion} questions=${targets.map((t) => t.question_id).join(",")}`);

  /** 每题的两臂产物，供确认后落盘与汇总 */
  const batch: Array<{
    q: Question;
    outputs: Map<string, ArmOutput[]>;
  }> = [];

  try {
    for (const q of targets) {
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

      console.log(`\n########## ${q.question_id} ##########`);
      const outputs = new Map<string, ArmOutput[]>();
      for (const armName of ARMS) {
        const arm = armName === "bash-v0.1" ? new BashArm(captureAbsPath) : new AstArm(captureAbsPath);
        const outs: ArmOutput[] = [];
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
              budgetExhausted: outcome.aborted !== null || !outcome.finishCalled,
            },
            aborted: outcome.aborted,
          };
          const scored = scoreRun(q, gt, outcome.answerRaw, `${arm.name}#${i}`);
          outs.push({ result, classification: scored.classification, messageHistory: outcome.messageHistory });

          for (const rec of outcome.records) {
            console.log(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
          }
          console.log(
            `  llmCalls=${outcome.llmCalls} in=${outcome.inputTokens} out=${outcome.outputTokens} wall=${outcome.wallMs}ms ` +
              `iface≈${result.metrics.interfaceTokens} exhausted=${result.metrics.budgetExhausted}${outcome.aborted ? ` aborted(${outcome.aborted})` : ""}`,
          );
          console.log(`  提取：${extraction.status === "ok" ? JSON.stringify(extraction.value) : `format_error(${extraction.reason})`} → ${scored.classification}`);
        }
        outputs.set(arm.name, outs);
      }
      batch.push({ q, outputs });
    }
  } finally {
    proxy.close();
  }

  // ---- 半自动边界：全部跑完后统一暂停确认（人工清单 1.1） ----
  if (!assumeYes) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("\n以上为全部运行的提取结果。确认无误并落盘判分？(y/n) ");
    rl.close();
    if (answer.trim().toLowerCase() !== "y") {
      console.log("已暂停：未落盘未汇总。");
      return 0;
    }
  }

  for (const { q, outputs } of batch) {
    await writeQuestionOutputs(q.question_id, outputs);
    await writeQuestionSummary(q, outputs);
  }
  await writeAllSummary(batch);

  console.log(`\n[run-slice] 完成：${batch.length} 题 × ${ARMS.length} 臂 × ${runsPerQuestion} 次；汇总见 bench/out/all-summary.json`);
  return 0;
}

// ---- 落盘（Mimosa 已验证形态：白名单段拼接 + 包含检查；纯数据函数不碰 fs） ----

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

async function writeArmOutputs(qid: string, armName: string, outs: ArmOutput[]): Promise<void> {
  const last = outs[outs.length - 1];
  if (!last) throw new Error(`writeArmOutputs: ${qid}/${armName} 无运行结果`);
  const dir = containedPath([qid, armName]);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "armresult.json"), armResultJson(last));
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(last));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(last.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), last.result.answerRaw);
  await writeFile(path.join(dir, "runs.json"), runsJson(outs));
}

async function writeQuestionOutputs(qid: string, outputs: Map<string, ArmOutput[]>): Promise<void> {
  for (const armName of ARMS) {
    await writeArmOutputs(qid, armName, outputs.get(armName) ?? []);
  }
}

function armSummary(name: string, outs: ArmOutput[]): Record<string, unknown> {
  const vote = majorityVote(outs.map((o) => o.classification));
  const mean = (f: (o: ArmOutput) => number): number =>
    Number(meanOf(outs.map(f)).toFixed(1));
  return {
    arm: name,
    majority_correct: vote.correct,
    vote_detail: `${vote.detail} correct (${outs.map((o) => o.classification).join(",")})`,
    runs: outs.map((o, i) => ({
      run_index: i + 1,
      classification: o.classification,
      format_error: o.result.formatError ?? null,
      llm_calls: o.result.metrics.llmCalls,
      input_tokens: o.result.metrics.inputTokens,
      output_tokens: o.result.metrics.outputTokens,
      tool_render_chars: o.result.metrics.toolRenderChars,
      interface_tokens_per_request: o.result.metrics.interfaceTokens,
      wall_ms: o.result.metrics.wallMs,
      budget_exhausted: o.result.metrics.budgetExhausted,
      aborted: o.result.aborted,
    })),
    means: {
      input_tokens: Math.round(meanOf(outs.map((o) => o.result.metrics.inputTokens))),
      output_tokens: Math.round(meanOf(outs.map((o) => o.result.metrics.outputTokens))),
      turns: mean((o) => o.result.metrics.llmCalls),
      tool_render_chars: Math.round(meanOf(outs.map((o) => o.result.metrics.toolRenderChars))),
      interface_tokens: Math.round(meanOf(outs.map((o) => o.result.metrics.interfaceTokens))),
      interface_share_of_input: Number(
        (
          meanOf(outs.map((o) => (o.result.metrics.interfaceTokens * o.result.metrics.llmCalls) / Math.max(1, o.result.metrics.inputTokens)))
        ).toFixed(3),
      ),
      wall_ms: Math.round(meanOf(outs.map((o) => o.result.metrics.wallMs))),
    },
  };
}

async function writeQuestionSummary(q: Question, outputs: Map<string, ArmOutput[]>): Promise<void> {
  const summary = {
    date: new Date().toISOString(),
    model: MODEL,
    question_id: q.question_id,
    budget: BUDGET,
    runs_per_question: (outputs.get("bash-v0.1") ?? []).length,
    arms: ARMS.map((name) => armSummary(name, outputs.get(name) ?? [])),
  };
  const dir = containedPath([q.question_id]);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "slice-summary.json"), JSON.stringify(summary, null, 2));
}

interface AllSummaryQuestion {
  question_id: string;
  bash: Record<string, unknown>;
  ast: Record<string, unknown>;
}

async function writeAllSummary(batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }>): Promise<void> {
  // 合并本批次与磁盘上已有的历次 slice-summary（按 question_id 去重，新覆盖旧）
  const byId = new Map<string, { question_id: string; arms: Array<Record<string, unknown>> }>();
  for (const { q, outputs } of batch) {
    byId.set(q.question_id, {
      question_id: q.question_id,
      arms: ARMS.map((name) => armSummary(name, outputs.get(name) ?? [])),
    });
  }
  for (const id of SLICE_QUESTION_IDS) {
    if (byId.has(id)) continue;
    try {
      const p = containedPath([id, "slice-summary.json"]);
      const prev = JSON.parse(await readFile(p, "utf8")) as { question_id: string; arms: Array<Record<string, unknown>> };
      byId.set(id, prev);
    } catch {
      /* 该题尚无历史数据，跳过 */
    }
  }

  const pick = (arms: Array<Record<string, unknown>>, arm: string): Record<string, unknown> => {
    const a = arms.find((x) => x.arm === arm) ?? {};
    const means = (a.means ?? {}) as Record<string, unknown>;
    return {
      majority_correct: a.majority_correct ?? null,
      vote_detail: a.vote_detail ?? null,
      avg_input_tokens: means.input_tokens ?? null,
      avg_turns: means.turns ?? null,
      avg_tool_render_chars: means.tool_render_chars ?? null,
      avg_interface_tokens: means.interface_tokens ?? null,
      interface_share_of_input: means.interface_share_of_input ?? null,
    };
  };

  const questions: AllSummaryQuestion[] = SLICE_QUESTION_IDS.filter((id) => byId.has(id)).map((id) => {
    const entry = byId.get(id)!;
    return { question_id: id, bash: pick(entry.arms, "bash-v0.1"), ast: pick(entry.arms, "ast-v0.4") };
  });

  const completed = questions.filter((x) => x.bash.majority_correct !== null && x.ast.majority_correct !== null);
  const avg = (xs: Array<number | null>): number | null => {
    const v = xs.filter((x): x is number => x !== null);
    return v.length === 0 ? null : Number(meanOf(v).toFixed(1));
  };
  const summary = {
    model: MODEL,
    budget: BUDGET,
    runs_per_question: 3,
    generated_at: new Date().toISOString(),
    questions,
    summary: {
      bash_overall_correct: `${completed.filter((x) => x.bash.majority_correct === true).length}/${completed.length}`,
      ast_overall_correct: `${completed.filter((x) => x.ast.majority_correct === true).length}/${completed.length}`,
      bash_avg_tokens: avg(completed.map((x) => x.bash.avg_input_tokens as number | null)),
      ast_avg_tokens: avg(completed.map((x) => x.ast.avg_input_tokens as number | null)),
      bash_avg_turns: avg(completed.map((x) => x.bash.avg_turns as number | null)),
      ast_avg_turns: avg(completed.map((x) => x.ast.avg_turns as number | null)),
      interface_tax_avg:
        completed.length === 0
          ? null
          : Number(
              (
                meanOf(completed.map((x) => (x.ast.avg_interface_tokens as number) / Math.max(1, x.bash.avg_interface_tokens as number)))
              ).toFixed(2),
            ),
      note: "interface_tax_avg = AST 臂接口注入 token 相对 bash 臂的倍数（每请求实测）；多数表决口径 ≥2/3",
    },
  };
  await writeFile(ALL_SUMMARY_PATH, `${JSON.stringify(summary, null, 2)}\n`);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[run-slice] fatal:", err);
    process.exitCode = 1;
  },
);
