/**
 * 通用切片联跑 CLI：对指定的已终审切片题运行两臂对照，支持多模型路由。
 *
 *   pnpm --filter bench slice-all                                # 基线模型（deepseek-v4-flash，DeepSeek 直连）
 *   pnpm --filter bench exec tsx src/runner/run-slice.ts --all --model glm-5.3 --yes
 *
 * 模型路由：deepseek-* 默认 DeepSeek 官方直连（与 E1 基线同路径）；其余模型默认
 * opengo 转发（https://opencode.ai/zen/go/v1）；--provider 可显式覆盖。
 * 非 --model 或 --model deepseek-v4-flash 时输出落在 bench/out/runs/（E1 兼容路径）；
 * 其它模型落在 bench/out/runs/model-<model>/，各自聚合 all-summary.json。
 *
 * 遥测分账（ρ_interface / ρ_render，口径：chars 为原始事实、tokens 为 chars/4 估计）：
 *   每轮上下文注入 = 接口固定开销（工具定义，记录代理逐请求实测）
 *                  + 内容投影（工具返回渲染，render chars 累计）
 *   详见 armSummary 的 rho_decomposition / interface_tax 块。
 *
 * F6 协议不合规分类（scorer/f6.ts）：format_error 细分为 no_finish_call /
 * finish_payload_invalid / no_tool_exploration，max_turns_exhausted 单列；
 * outcome 四分桶 + 双口径完成率（excluding_F6 为 ρ 测量主口径）。
 *
 * 写盘边界：字面量基目录 + 逐段白名单 + 解析后包含检查（deriver 同构）。
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import readline from "node:readline/promises";
import path from "node:path";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { extractFinalAnswer, validateAgainstContract } from "../scorer/answer-contract.js";
import { loadGroundTruth, loadQuestionsDir, type Question } from "../scorer/question.js";
import { scoreRun, type RunClassification } from "../scorer/pipeline.js";
import { classifyF6, completionRates, emptyBreakdown, outcomeBucket, type F6Subtypes, type OutcomeBucket } from "../scorer/f6.js";
import { BashArm } from "./bash-arm.js";
import { AstArm } from "./ast-tools.js";
import {
  DEFAULT_MODEL,
  captureCount,
  capturesFrom,
  interfaceCharsOf,
  interfaceTokensOf,
  loadApiKey,
  providerToolCallCount,
  providerToolCallsFrom,
  resolveProvider,
  startRecordingProxy,
  type InterfaceCapture,
  type ProviderToolCall,
} from "./llm.js";
import { runArmOnce } from "./shared-loop.js";
import { SLICE_QUESTION_IDS as SLICE_IDS, ARM_NAMES, PROTOCOL_VERSION } from "./run-slice-ids.js";
import { applyF7, detectF7, type CallLite, type F7Detection, type FinalBucket } from "../scorer/f7.js";
import type { ArmResult, Budget, ToolCallRecord } from "./types.js";

const SLICE_QUESTION_IDS = SLICE_IDS as unknown as string[];
const ARMS = ARM_NAMES;
/**
 * 预算裁定（终局实验参数，不做敏感性实验）：32 包量级的 fixture 下该预算已属宽裕，
 * 打满轮次/超时本身即 agent 侧低效的有效信号而非 harness 伪影。
 * 适用边界：此论证只在切片量级成立——更大 capture 的下钻深度天然更大，预算须按
 * 规模重新推导，不得沿用本值。数值溯源：Stirrup spike demo 默认值，经跨批次锁死
 * 冻结为设计选择。
 */
const BUDGET: Budget = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };

const OUT_RUNS_DIR = path.join(REPO_ROOT, "bench", "out", "runs");
/**
 * 当前批次的输出根目录与模型（默认 E1 兼容路径；--model 时切到 model-<model>/）。
 * v0.2 起汇总一律写 all-summary-v02.json——v0.1 的 all-summary.json 是不可变基线。
 */
let runsBaseDir = OUT_RUNS_DIR;
let allSummaryPath = path.join(REPO_ROOT, "bench", "out", "all-summary-v02.json");
let currentModel = DEFAULT_MODEL;

type FiveBuckets = Record<FinalBucket, number>;

function emptyFiveBuckets(): FiveBuckets {
  return {
    forensic_correct: 0,
    forensic_wrong: 0,
    protocol_noncompliance: 0,
    budget_exhausted: 0,
    tool_binding_failure: 0,
  };
}

interface ArmOutput {
  result: ArmResult;
  classification: RunClassification;
  messageHistory: unknown[];
  f6: F6Subtypes;
  f7: F7Detection;
  bucket: FinalBucket;
  runCaptures: InterfaceCapture[];
  providerToolCalls: ProviderToolCall[];
  turnUsage: Array<{ turn: number; inputTokens: number; outputTokens: number }>;
  turnMarks: number[];
}

/** 从工具调用记录提取 F7 判定所需的调用摘要 */
function callLitesOf(records: ToolCallRecord[]): CallLite[] {
  return records.map((r) => ({
    name: r.name,
    argsJson: typeof r.rawArgs === "string" && r.rawArgs !== "" ? r.rawArgs : JSON.stringify(r.args ?? null),
    ok: r.ok,
    emptyArrival: r.emptyArrival === true,
  }));
}

/** 逐段白名单 + 最终包含检查（写盘边界） */
function containedPath(segments: string[]): string {
  let cur = runsBaseDir;
  for (const seg of segments) {
    assertSafeBasename(seg, "输出路径段");
    cur = path.join(cur, seg);
  }
  const full = path.resolve(cur);
  if (!full.startsWith(path.resolve(runsBaseDir) + path.sep)) {
    throw new Error(`路径越出运行产物目录：${full}`);
  }
  return full;
}

function majorityVote(classifications: RunClassification[]): { correct: boolean; detail: string } {
  const correctCount = classifications.filter((c) => c === "correct").length;
  return { correct: correctCount > classifications.length / 2, detail: `${correctCount}/${classifications.length}` };
}

const meanOf = (xs: number[]): number => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);
const CHARS_PER_TOKEN = 4; // 与 E1 estTokens 同口径

/** 工具调用按时间归轮：marks[k] = 第 k 轮完成时刻，工具属于其开始前最后一个 mark 的下一轮 */
function turnOf(record: ToolCallRecord, marks: number[]): number {
  let t = 1;
  for (const m of marks) {
    if (m <= record.startedAtMs) t++;
  }
  return t;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const assumeYes = argv.includes("--yes");
  const runsIdx = argv.indexOf("--runs");
  const runsPerQuestion = runsIdx >= 0 ? Math.max(1, Number(argv[runsIdx + 1]) || 3) : 3;
  const modelIdx = argv.indexOf("--model");
  const model = modelIdx >= 0 ? (argv[modelIdx + 1] ?? DEFAULT_MODEL) : DEFAULT_MODEL;
  const providerIdx = argv.indexOf("--provider");
  const providerOverride = providerIdx >= 0 ? argv[providerIdx + 1] : undefined;
  const idArgs = argv.filter((a) => !a.startsWith("--") && a !== String(runsPerQuestion) && a !== model && a !== providerOverride);
  const wantedIds = idArgs.length > 0 ? idArgs : SLICE_QUESTION_IDS;

  // 输出目录按模型分开（基线模型保持 E1 兼容路径）
  currentModel = model;
  if (model !== DEFAULT_MODEL) {
    assertSafeBasename(model, "模型名");
    runsBaseDir = path.join(OUT_RUNS_DIR, `model-${model}`);
    allSummaryPath = path.join(runsBaseDir, "all-summary-v02.json");
  }

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

  const provider = resolveProvider(model, providerOverride);
  const key = await loadApiKey(provider);
  // 上游以字面量传入（与 ProviderConfig.upstream 断言一致），代理不做任意 URL 转发
  const UPSTREAMS: Record<string, string> = {
    deepseek: "https://api.deepseek.com",
    opengo: "https://opencode.ai/zen/go",
  };
  if (provider.upstream !== UPSTREAMS[provider.name]) {
    throw new Error(`provider ${provider.name} 的 upstream 与调用点字面量不一致`);
  }
  const proxy =
    provider.name === "deepseek"
      ? await startRecordingProxy("https://api.deepseek.com")
      : await startRecordingProxy("https://opencode.ai/zen/go");
  const client = new ChatCompletionsClient({ model, apiKey: key, baseURL: proxy.baseURL });
  console.log(
    `[run-slice] model=${model} provider=${provider.name} budget=${JSON.stringify(BUDGET)} runs=${runsPerQuestion} questions=${targets.map((t) => t.question_id).join(",")}`,
  );

  const batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }> = [];

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
        const arm = armName.startsWith("bash-") ? new BashArm(captureAbsPath) : new AstArm(captureAbsPath);
        const outs: ArmOutput[] = [];
        for (let i = 1; i <= runsPerQuestion; i++) {
          console.log(`\n===== ${arm.name} run ${i}/${runsPerQuestion} =====`);
          const capStart = captureCount();
          const providerArgsStart = providerToolCallCount();
          const outcome = await runArmOnce({ arm, task, budget: BUDGET, client });
          const runCaptures = capturesFrom(capStart);
          const providerToolCalls = providerToolCallsFrom(providerArgsStart);

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
          const f6 = classifyF6({
            classification: scored.classification,
            answerRaw: outcome.answerRaw,
            toolCallCount: outcome.records.length,
            llmCalls: outcome.llmCalls,
            maxTurns: BUDGET.maxTurns,
          });
          // v0.2：F7 工具绑定失败（arrival-side 遥测）；失败 run 优先级 F7 > budget
          const f7 = detectF7(callLitesOf(outcome.records));
          const runCompleted = scored.classification !== "format_error";
          const bucket = applyF7(outcomeBucket(scored.classification, f6), f7, runCompleted);
          outs.push({
            result,
            classification: scored.classification,
            messageHistory: outcome.messageHistory,
            f6,
            f7,
            bucket,
            runCaptures,
            providerToolCalls,
            turnUsage: outcome.turnUsage,
            turnMarks: outcome.turnMarks,
          });

          for (const rec of outcome.records) {
            console.log(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
          }
          console.log(
            `  llmCalls=${outcome.llmCalls} in=${outcome.inputTokens} out=${outcome.outputTokens} wall=${outcome.wallMs}ms ` +
              `iface≈${result.metrics.interfaceTokens} exhausted=${result.metrics.budgetExhausted}${outcome.aborted ? ` aborted(${outcome.aborted})` : ""}`,
          );
          console.log(
            `  提取：${extraction.status === "ok" ? JSON.stringify(extraction.value) : `format_error(${extraction.reason})`} → ${scored.classification}` +
              (scored.classification === "format_error" ? ` [F6: ${JSON.stringify(f6)}]` : ""),
          );
          if (f7.binding) {
            console.log(`  [F7] ${f7.evidence}${bucket === "tool_binding_failure" ? " → tool_binding_failure" : "（完成态，仅记诊断）"}`);
          }
        }
        outputs.set(armName, outs);
      }
      batch.push({ q, outputs });
    }
  } finally {
    proxy.close();
  }

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
  await writeAllSummary(model, batch);

  console.log(`\n[run-slice] 完成：${batch.length} 题 × ${ARMS.length} 臂 × ${runsPerQuestion} 次；汇总见 ${allSummaryPath}`);
  return 0;
}

// ---- 落盘与汇总 ----

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
      f6: o.f6,
      f7: o.f7,
      binding_failures_count: o.f7.emptyArrivalCount,
      outcome_bucket: o.bucket,
      answerRaw: o.result.answerRaw,
      answer: o.result.answer ?? null,
      format_error: o.result.formatError ?? null,
      metrics: o.result.metrics,
      aborted: o.result.aborted,
      // v0.2：调用级摘要（F7 复判与错误形态分析用；完整记录见 transcript.json）
      calls: callLitesOf(o.result.transcript).map((c, j) => {
        const rec = o.result.transcript[j]!;
        return {
          seq: rec.seq,
          name: c.name,
          ok: c.ok,
          emptyArrival: c.emptyArrival,
          rawArgs: rec.rawArgs ?? null,
          rawArgsTruncated: rec.rawArgsTruncated === true,
          resultChars: rec.resultChars,
        };
      }),
      // v0.2：provider 响应体里的原始 tool_calls 参数串（H-harness vs H-model 证据）
      provider_raw_tool_calls: o.providerToolCalls,
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

/** ρ 分账（口径：chars 原始事实 / tokens=chars÷4 估计，与 E1 estTokens 同源） */
function rhoOf(outs: ArmOutput[]): Record<string, unknown> {
  const ifaceCharsPerReq = meanOf(outs.map((o) => interfaceCharsOf(o.runCaptures).totalChars));
  const ifaceTokensPerReq = meanOf(outs.map((o) => o.result.metrics.interfaceTokens));
  const turns = meanOf(outs.map((o) => o.result.metrics.llmCalls));
  const renderChars = meanOf(outs.map((o) => o.result.metrics.toolRenderChars));
  const renderPerTurn = turns > 0 ? renderChars / turns : 0;
  const inputTotal = meanOf(outs.map((o) => o.result.metrics.inputTokens));
  const ifaceTotal = ifaceTokensPerReq * turns;
  const renderTotal = renderChars / CHARS_PER_TOKEN;
  return {
    interface: {
      per_request_chars: Math.round(ifaceCharsPerReq),
      per_request_tokens_est: Math.round(ifaceTokensPerReq),
      total_avg_tokens_est: Math.round(ifaceTotal),
      input_share_pct: inputTotal > 0 ? Number(((100 * ifaceTotal) / inputTotal).toFixed(1)) : null,
    },
    render: {
      per_turn_chars: Math.round(renderPerTurn),
      per_turn_tokens_est: Math.round(renderPerTurn / CHARS_PER_TOKEN),
      total_avg_chars: Math.round(renderChars),
      total_avg_tokens_est: Math.round(renderTotal),
      input_share_pct: inputTotal > 0 ? Number(((100 * renderTotal) / inputTotal).toFixed(1)) : null,
    },
    unit_note: "chars=原始事实；tokens=chars/4 估计（与 E1 estTokens 同口径，跨模型不做 tokenizer 精确对齐）",
  };
}

function armSummary(name: string, outs: ArmOutput[]): Record<string, unknown> {
  const vote = majorityVote(outs.map((o) => o.classification));
  const breakdown = emptyFiveBuckets();
  for (const o of outs) breakdown[o.bucket]++;
  // 双口径：excluding 口径只含 forensic_*（F6 协议失败与 F7 绑定失败均不污染完成率）
  const forensic = breakdown.forensic_correct + breakdown.forensic_wrong;
  const total = forensic + breakdown.protocol_noncompliance + breakdown.budget_exhausted + breakdown.tool_binding_failure;
  const rates = {
    completion_rate_excluding_F6: forensic === 0 ? "0/0" : `${breakdown.forensic_correct}/${forensic}`,
    completion_rate_raw: total === 0 ? "0/0" : `${breakdown.forensic_correct}/${total}`,
  };
  // 每轮明细：turn 序 → 该轮 input/output + 该轮工具渲染 chars（按时间归轮）
  const perTurn = outs.map((o, runIdx) => {
    const renderByTurn = new Map<number, number>();
    for (const rec of o.result.transcript) {
      const t = turnOf(rec, o.turnMarks);
      renderByTurn.set(t, (renderByTurn.get(t) ?? 0) + rec.resultChars);
    }
    return {
      run_index: runIdx + 1,
      turns: o.turnUsage.map((u) => ({
        turn: u.turn,
        input_tokens: u.inputTokens,
        output_tokens: u.outputTokens,
        render_chars: renderByTurn.get(u.turn) ?? 0,
        interface_chars: interfaceCharsOf(o.runCaptures).totalChars,
      })),
    };
  });
  return {
    arm: name,
    majority_correct: vote.correct,
    vote_detail: `${vote.detail} correct (${outs.map((o) => o.classification).join(",")})`,
    outcome_breakdown: breakdown,
    completion_rate_excluding_F6: rates.completion_rate_excluding_F6,
    completion_rate_raw: rates.completion_rate_raw,
    rho_decomposition: rhoOf(outs),
    per_turn_telemetry: perTurn,
    runs: outs.map((o, i) => ({
      run_index: i + 1,
      classification: o.classification,
      f6: o.f6,
      f7: o.f7,
      binding_failures_count: o.f7.emptyArrivalCount,
      outcome_bucket: o.bucket,
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
      turns: Number(meanOf(outs.map((o) => o.result.metrics.llmCalls)).toFixed(1)),
      tool_render_chars: Math.round(meanOf(outs.map((o) => o.result.metrics.toolRenderChars))),
      interface_tokens: Math.round(meanOf(outs.map((o) => o.result.metrics.interfaceTokens))),
      wall_ms: Math.round(meanOf(outs.map((o) => o.result.metrics.wallMs))),
    },
  };
}

function interfaceTaxOf(armSummaries: Array<Record<string, unknown>>): Record<string, unknown> {
  const bash = armSummaries.find((a) => a.arm === "bash-v0.1");
  const ast = armSummaries.find((a) => a.arm === "ast-v0.4");
  const iface = (a?: Record<string, unknown>) => (a?.rho_decomposition as { interface?: { per_request_tokens_est?: number; total_avg_tokens_est?: number } })?.interface;
  const b = iface(bash);
  const s = iface(ast);
  const per = b?.per_request_tokens_est && s?.per_request_tokens_est ? Number((s.per_request_tokens_est / b.per_request_tokens_est).toFixed(2)) : null;
  const total = b?.total_avg_tokens_est && s?.total_avg_tokens_est ? Number((s.total_avg_tokens_est / b.total_avg_tokens_est).toFixed(2)) : null;
  return { per_request_ratio: per, total_ratio: total, note: "total_ratio 随两臂轮次差变化（接口税×轮次的复合）" };
}

async function writeQuestionSummary(q: Question, outputs: Map<string, ArmOutput[]>): Promise<void> {
  const armSummaries = ARMS.map((name) => armSummary(name, outputs.get(name) ?? []));
  const summary = {
    date: new Date().toISOString(),
    protocol_version: PROTOCOL_VERSION,
    model: currentModel,
    question_id: q.question_id,
    budget: BUDGET,
    runs_per_question: (outputs.get(ARM_NAMES[0]) ?? []).length,
    arms: armSummaries,
    interface_tax: interfaceTaxOf(armSummaries),
  };
  const dir = containedPath([q.question_id]);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "slice-summary.json"), JSON.stringify(summary, null, 2));
}

async function writeAllSummary(model: string, batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }>): Promise<void> {
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
      outcome_breakdown: a.outcome_breakdown ?? null,
      completion_rate_excluding_F6: a.completion_rate_excluding_F6 ?? null,
      avg_input_tokens: means.input_tokens ?? null,
      avg_turns: means.turns ?? null,
      avg_tool_render_chars: means.tool_render_chars ?? null,
      avg_interface_tokens: means.interface_tokens ?? null,
    };
  };

  const questions = SLICE_QUESTION_IDS.filter((id) => byId.has(id)).map((id) => {
    const entry = byId.get(id)!;
    return { question_id: id, bash: pick(entry.arms, "bash-v0.1"), ast: pick(entry.arms, "ast-v0.4") };
  });

  const completed = questions.filter((x) => x.bash.majority_correct !== null && x.ast.majority_correct !== null);
  const avg = (xs: Array<number | null>): number | null => {
    const v = xs.filter((x): x is number => x !== null);
    return v.length === 0 ? null : Number(meanOf(v).toFixed(1));
  };
  const ifaceRatio = (armKey: "bash" | "ast"): number | null => {
    const perQ = completed
      .map((x) => (x[armKey].avg_interface_tokens as number | null))
      .filter((x): x is number => x !== null);
    const bashPerQ = completed.map((x) => x.bash.avg_interface_tokens as number | null).filter((x): x is number => x !== null);
    if (perQ.length === 0 || bashPerQ.length === 0) return null;
    return Number((meanOf(perQ) / meanOf(bashPerQ)).toFixed(2));
  };

  const summary = {
    protocol_version: PROTOCOL_VERSION,
    model,
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
      interface_tax_avg: ifaceRatio("ast"),
      note: "interface_tax_avg = AST 臂接口注入 token 相对 bash 臂的倍数（每请求实测 chars/4）；多数表决口径 ≥2/3",
    },
  };
  await writeFile(allSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
}

void (async () => {
  process.env.RUN_SLICE_MODEL = process.env.RUN_SLICE_MODEL ?? DEFAULT_MODEL;
})();

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[run-slice] fatal:", err);
    process.exitCode = 1;
  },
);
