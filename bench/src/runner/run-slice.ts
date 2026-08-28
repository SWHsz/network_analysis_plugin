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
import { readFileSync } from "node:fs";
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
import { isInstanceFixture, instancePcapPath } from "../bridge/instances.js";
import { loadInstanceQuestion } from "../scorer/question.js";
import {
  DEFAULT_MODEL,
  captureCount,
  pingProvider,
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
 * 规模重新推导（--budget-sweep 标定批即此推导的实测入口），不得沿用本值。
 * 数值溯源：Stirrup spike demo 默认值，经跨批次锁死冻结为设计选择。
 */
const BUDGET: Budget = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };
/** sweep 角点的 timeout 基准：与 BUDGET 同源，按 maxTurns 等比放大（8→180s） */
const BUDGET_TIMEOUT_PER_TURN_MS = BUDGET.timeoutMs / BUDGET.maxTurns;

/**
 * 预算梯度扫描角点（S3 标定批）：--budget-sweep "8x4000,16x8000,32x16000"，
 * maxTurns×maxTokens 角点，逗号分隔；timeout 按角点等比放大（报告标注）。
 * 角点先粗后细：本批只扫 3 角点，不许顺手扩大矩阵。
 */
interface SweepCorner {
  /** 角点目录标签（assertSafeBasename 兼容），如 t08-tok4000；非 sweep 批为 null */
  label: string | null;
  budget: Budget;
}

function parseBudgetSweep(spec: string, runsIdxHint: never = undefined as never): SweepCorner[] {
  void runsIdxHint;
  const corners: SweepCorner[] = [];
  for (const seg of spec.split(",")) {
    const m = /^(\d+)x(\d+)$/.exec(seg.trim());
    if (!m) {
      throw new Error(`--budget-sweep 角点格式非法："${seg}"（应为 <maxTurns>x<maxTokens>，如 8x4000）`);
    }
    const maxTurns = Number(m[1]);
    const maxTokens = Number(m[2]);
    if (maxTurns < 1 || maxTokens < 256) {
      throw new Error(`--budget-sweep 角点数值非法：${seg}`);
    }
    corners.push({
      label: `t${String(maxTurns).padStart(2, "0")}-tok${maxTokens}`,
      budget: {
        maxTurns,
        maxTokens,
        timeoutMs: Math.round(BUDGET_TIMEOUT_PER_TURN_MS * maxTurns),
      },
    });
  }
  if (corners.length === 0) throw new Error("--budget-sweep 为空");
  return corners;
}

const OUT_RUNS_DIR = path.join(REPO_ROOT, "bench", "out", "runs");
/**
 * 当前批次的输出根目录与模型（默认 E1 兼容路径；--model 时切到 model-<model>/）。
 * v0.2 起汇总一律写 all-summary-v02.json——v0.1 的 all-summary.json 是不可变基线。
 */
let runsBaseDir = OUT_RUNS_DIR;
let allSummaryPath = path.join(REPO_ROOT, "bench", "out", "all-summary-v02.json");
let currentModel = DEFAULT_MODEL;
/** 当前生效预算：非 sweep 批恒为 BUDGET（冻结值）；sweep 批逐角点重绑 */
let activeBudget: Budget = BUDGET;

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

/** --resume 判定：该题该臂的 runs.json 已存在且 run 数足量（中途崩溃只补缺题） */
function questionAlreadyOnDisk(qid: string, armName: string, runsPerQuestion: number): boolean {
  try {
    const p = containedPath([qid, armName, "runs.json"]);
    const runs = JSON.parse(readFileSync(p, "utf8")) as Array<{ query_schema?: string }>;
    return (
      Array.isArray(runs) &&
      runs.length >= runsPerQuestion &&
      runs.every((r) => r?.query_schema === "explicit-v1")
    );
  } catch {
    return false;
  }
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
  const armIdx = argv.indexOf("--arm");
  const armFilter = armIdx >= 0 ? (argv[armIdx + 1] ?? "") : "";
  const resume = argv.includes("--resume");
  const budgetHint = argv.includes("--budget-hint");
  const sweepIdx = argv.indexOf("--budget-sweep");
  const sweepSpec = sweepIdx >= 0 ? argv[sweepIdx + 1] : undefined;
  const corners: SweepCorner[] = sweepSpec ? parseBudgetSweep(sweepSpec) : [{ label: null, budget: BUDGET }];
  const activeArms = armFilter === "" ? (ARMS as readonly string[]) : ARMS.filter((a) => a.startsWith(armFilter));
  if (activeArms.length === 0) {
    console.error(`[run-slice] --arm ${armFilter} 无匹配臂（可用：${ARMS.join("/")}）`);
    return 2;
  }
  // 位置参数 = 题 id（排除一切值型 flag 的取值与裸 flag，替代旧的按值反查过滤）
  const VALUE_FLAGS = new Set(["--runs", "--model", "--provider", "--arm", "--budget-sweep"]);
  const wantedIds: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (VALUE_FLAGS.has(a)) {
      i++;
      continue;
    }
    if (a.startsWith("--")) continue;
    wantedIds.push(a);
  }
  if (wantedIds.length === 0) wantedIds.push(...SLICE_QUESTION_IDS);

  // 输出目录按模型分开（基线模型保持 E1 兼容路径）；sweep 批再叠一层角点目录
  currentModel = model;
  const modelDirSuffix = model !== DEFAULT_MODEL ? `model-${model}${budgetHint ? "-hint" : ""}` : "";
  if (modelDirSuffix !== "") assertSafeBasename(model, "模型名");

  // 题目解析：题库（bench/questions，冻结）优先；未命中且 fixture 是实例命名
  // （<card>-i<seed>-r<tier>）时从实例注册表加载（bench-question.json）
  const all = loadQuestionsDir();
  const targets: Question[] = [];
  for (const id of wantedIds) {
    const q = all.find((x) => x.question_id === id) ?? loadInstanceQuestion(id);
    if (!q) {
      console.error(`[run-slice] 题库与实例注册表中均不存在 ${id}`);
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
    opengo2: "https://opencode.ai/zen/go",
  };
  if (provider.upstream !== UPSTREAMS[provider.name]) {
    throw new Error(`provider ${provider.name} 的 upstream 与调用点字面量不一致`);
  }
  const proxy =
    provider.name === "deepseek"
      ? await startRecordingProxy("https://api.deepseek.com")
      : await startRecordingProxy("https://opencode.ai/zen/go");
  const client = new ChatCompletionsClient({ model, apiKey: key, baseURL: proxy.baseURL });
  const ping = await pingProvider(provider, key, model);
  if (ping) {
    console.error(`[run-slice] 预检失败，批次未启动（防中途作废）：${ping}`);
    proxy.close();
    return 3;
  }
  console.log(
    `[run-slice] model=${model} provider=${provider.name} runs=${runsPerQuestion} ` +
      (sweepSpec
        ? `sweep=${sweepSpec}（timeout 按 maxTurns 等比放大：${corners.map((c) => `${c.label}=${Math.round(c.budget.timeoutMs / 1000)}s`).join(" ")}）`
        : `budget=${JSON.stringify(BUDGET)}`) +
      ` questions=${targets.map((t) => t.question_id).join(",")}`,
  );

  const cornerBatches: Array<{ corner: SweepCorner; batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }> }> = [];

  try {
    for (const corner of corners) {
      activeBudget = corner.budget;
      // 输出根：sweep 批 = runs/budget-sweep/<角点>[/<模型目录>]；非 sweep 保持 E1 兼容路径
      runsBaseDir =
        corner.label !== null
          ? path.join(OUT_RUNS_DIR, "budget-sweep", corner.label, modelDirSuffix)
          : modelDirSuffix !== ""
            ? path.join(OUT_RUNS_DIR, modelDirSuffix)
            : OUT_RUNS_DIR;
      allSummaryPath = path.join(runsBaseDir, "all-summary-v02.json");

      const batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }> = [];
      for (const q of targets) {
        const gt = loadGroundTruth(q);
        const captureAbsPath = isInstanceFixture(q.capture.fixture)
          ? instancePcapPath(q.capture.fixture)
          : path.join(REPO_ROOT, "fixtures", `${q.capture.fixture}.pcap`);
        const task = [
          `Question (${q.question_id}): ${q.question}`,
          "",
          "Answer schema (the fenced block must conform to it):",
          JSON.stringify(q.answer_schema, null, 2),
          "",
          'Reminder: finish reason contains exactly one ```json block; every factual node carries {"value", "evidence":[frames]}.',
        ].join("\n");

        console.log(`\n########## [${corner.label ?? "base"}] ${q.question_id} ##########`);

        // --resume：全部目标臂的 runs.json 已有足量 run 时跳过执行（断点续跑，省配额）
        if (resume && activeArms.every((a) => questionAlreadyOnDisk(q.question_id, a, runsPerQuestion))) {
          console.log(`  [resume] ${q.question_id} 已有落盘数据，跳过`);
          continue;
        }

        const outputs = new Map<string, ArmOutput[]>();
        for (const armName of activeArms) {
          const armOpts = budgetHint ? { budgetHintMaxTurns: activeBudget.maxTurns } : {};
          const arm = armName.startsWith("bash-") ? new BashArm(captureAbsPath, armOpts) : new AstArm(captureAbsPath, armOpts);
          const outs: ArmOutput[] = [];
          for (let i = 1; i <= runsPerQuestion; i++) {
            console.log(`\n===== ${arm.name} run ${i}/${runsPerQuestion} =====`);
            const capStart = captureCount();
            const providerArgsStart = providerToolCallCount();
            const outcome = await runArmOnce({ arm, task, budget: activeBudget, client });
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
            maxTurns: activeBudget.maxTurns,
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
      // 逐题即时落盘：任何中途崩溃只损失在途的一题，已完成题目已在盘上（--resume 可续）
      await writeQuestionOutputs(q.question_id, outputs, activeArms, budgetHint);
      await writeQuestionSummary(q, outputs, activeArms);
      console.log(`  [persisted] ${q.question_id} → ${path.relative(OUT_RUNS_DIR, path.join(runsBaseDir, q.question_id))}/ 已落盘`);
      batch.push({ q, outputs });
      }
      cornerBatches.push({ corner, batch });
    }
  } finally {
    proxy.close();
  }

  if (!assumeYes) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("\n以上为全部运行的提取结果。确认汇总落盘？(y/n) ");
    rl.close();
    if (answer.trim().toLowerCase() !== "y") {
      console.log("已暂停：题目级数据已落盘，未聚合。");
      return 0;
    }
  }

  for (const { corner, batch } of cornerBatches) {
    // 汇总落盘前恢复该角点的写盘根（containedPath/allSummaryPath 绑定模块级变量）
    activeBudget = corner.budget;
    runsBaseDir =
      corner.label !== null
        ? path.join(OUT_RUNS_DIR, "budget-sweep", corner.label, modelDirSuffix)
        : modelDirSuffix !== ""
          ? path.join(OUT_RUNS_DIR, modelDirSuffix)
          : OUT_RUNS_DIR;
    allSummaryPath = path.join(runsBaseDir, "all-summary-v02.json");
    for (const { q, outputs } of batch) {
      await writeQuestionOutputs(q.question_id, outputs, activeArms, budgetHint);
      await writeQuestionSummary(q, outputs, activeArms);
    }
    if (armFilter !== "") {
      // 单臂模式不写全量汇总（另一臂数据缺位会覆盖既有 all-summary-v02 的双臂口径）
      console.log(`[run-slice] [${corner.label ?? "base"}] 单臂模式：跳过 all-summary 聚合`);
    } else {
      await writeAllSummary(model, batch, runsPerQuestion);
    }
  }

  console.log(
    `\n[run-slice] 完成：${cornerBatches.length} 角点 × ${targets.length} 题 × ${activeArms.length} 臂 × ${runsPerQuestion} 次` +
      ` = ${cornerBatches.length * targets.length * activeArms.length * runsPerQuestion} run；汇总见 ${allSummaryPath}`,
  );
  return 0;
}

// ---- 落盘与汇总 ----

function armResultJson(o: ArmOutput): string {
  return JSON.stringify(o.result, null, 2);
}

function transcriptJson(o: ArmOutput): string {
  return JSON.stringify({ records: o.result.transcript }, null, 2);
}

function runsJson(outs: ArmOutput[], budgetHint: boolean): string {
  return JSON.stringify(
    outs.map((o, i) => ({
      run_index: i + 1,
      // 本文件产自哪个接口版本（--resume 的防陈旧标记：旧文件无此字段即判不可续）
      query_schema: "explicit-v1",
      budget_hint: budgetHint,
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

async function writeArmOutputs(qid: string, armName: string, outs: ArmOutput[], budgetHint: boolean): Promise<void> {
  const last = outs[outs.length - 1];
  if (!last) throw new Error(`writeArmOutputs: ${qid}/${armName} 无运行结果`);
  const dir = containedPath([qid, armName]);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "armresult.json"), armResultJson(last));
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(last));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(last.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), last.result.answerRaw);
  await writeFile(path.join(dir, "runs.json"), runsJson(outs, budgetHint));
}

async function writeQuestionOutputs(qid: string, outputs: Map<string, ArmOutput[]>, activeArms: readonly string[], budgetHint: boolean): Promise<void> {
  for (const armName of activeArms) {
    await writeArmOutputs(qid, armName, outputs.get(armName) ?? [], budgetHint);
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
  // 臂名按前缀匹配（bash-*/ast-*）：v0.1 与 v0.2 臂名通吃（E1 遗留：曾硬编码 v0.1 名）
  const bash = armSummaries.find((a) => String(a.arm).startsWith("bash-"));
  const ast = armSummaries.find((a) => String(a.arm).startsWith("ast-"));
  const iface = (a?: Record<string, unknown>) => (a?.rho_decomposition as { interface?: { per_request_tokens_est?: number; total_avg_tokens_est?: number } })?.interface;
  const b = iface(bash);
  const s = iface(ast);
  const per = b?.per_request_tokens_est && s?.per_request_tokens_est ? Number((s.per_request_tokens_est / b.per_request_tokens_est).toFixed(2)) : null;
  const total = b?.total_avg_tokens_est && s?.total_avg_tokens_est ? Number((s.total_avg_tokens_est / b.total_avg_tokens_est).toFixed(2)) : null;
  return { per_request_ratio: per, total_ratio: total, note: "total_ratio 随两臂轮次差变化（接口税×轮次的复合）" };
}

async function writeQuestionSummary(q: Question, outputs: Map<string, ArmOutput[]>, activeArms: readonly string[]): Promise<void> {
  const armSummaries = activeArms.map((name) => armSummary(name, outputs.get(name) ?? []));
  const tax = activeArms.length === ARMS.length ? interfaceTaxOf(armSummaries) : null;
  const summary = {
    date: new Date().toISOString(),
    protocol_version: PROTOCOL_VERSION,
    model: currentModel,
    question_id: q.question_id,
    budget: activeBudget,
    runs_per_question: (outputs.get(activeArms[0] ?? "") ?? []).length,
    arms: armSummaries,
    interface_tax: tax,
    note: activeArms.length < ARMS.length ? `单臂模式（--arm）：仅含 ${activeArms.join("/")}，interface_tax 需双臂` : undefined,
  };
  const dir = containedPath([q.question_id]);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "slice-summary.json"), JSON.stringify(summary, null, 2));
}

async function writeAllSummary(
  model: string,
  batch: Array<{ q: Question; outputs: Map<string, ArmOutput[]> }>,
  runsPerQuestion = 3,
): Promise<void> {
  const byId = new Map<string, { question_id: string; arms: Array<Record<string, unknown>> }>();
  for (const { q, outputs } of batch) {
    byId.set(q.question_id, {
      question_id: q.question_id,
      arms: ARMS.map((name) => armSummary(name, outputs.get(name) ?? [])),
    });
  }
  // 历史回填仅限默认切片题集批次；实例题/sweep 批只含本次目标，不做 SLICE 全集回填
  const isDefaultSet = batch.every((b) => (SLICE_QUESTION_IDS as readonly string[]).includes(b.q.question_id));
  if (isDefaultSet) {
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
  }

  // 臂名按前缀匹配（bash-*/ast-*）：v0.1 与 v0.2 臂名通吃
  const pick = (arms: Array<Record<string, unknown>>, armPrefix: string): Record<string, unknown> => {
    const a = arms.find((x) => String(x.arm).startsWith(armPrefix)) ?? {};
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

  const questions = [...byId.values()].map((entry) => {
    return { question_id: entry.question_id, bash: pick(entry.arms, "bash-"), ast: pick(entry.arms, "ast-") };
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
    budget: activeBudget,
    runs_per_question: runsPerQuestion,
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
