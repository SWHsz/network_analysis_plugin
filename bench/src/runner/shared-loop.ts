/**
 * SharedLoop：两臂共享的最小 agent loop（RFC-002 §5.2 v1.1，Stirrup 选型落地）。
 * 唯一变量是 arm.buildTools() 给出的工具面；LLM/题面/预算/循环全部一致。
 *
 * 预算口径（EVALUATION.md 附带条件 c）：
 * - maxTurns 原生；timeoutMs = AbortController + setTimeout；
 * - maxTokens 为输出预算：turn:complete 累计超限即 abort（Stirrup 无原生输出预算）；
 * - budgetExhausted = aborted !== null || finishParams === undefined（与"纯文本收尾"同判，
 *   transcript 可辨二者）。
 */
import { rm } from "node:fs/promises";
import { Agent, CacheManager } from "@stirrup/stirrup";
import type { AgentRunResult } from "@stirrup/stirrup";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import { FINISH_TOOL_V02 } from "./finish-tool.js";
import type { Arm, Budget, ToolCallRecord } from "./types.js";

export interface RunOutcome {
  records: ToolCallRecord[];
  messageHistory: unknown[];
  llmCalls: number;
  inputTokens: number;
  outputTokens: number;
  wallMs: number;
  /** finish reason 原文；未调 finish 时为 "" */
  answerRaw: string;
  finishCalled: boolean;
  aborted: string | null;
  /** 每轮 token usage（turn:complete 实测，1-based） */
  turnUsage: Array<{ turn: number; inputTokens: number; outputTokens: number }>;
  /** 各轮完成时刻（wall ms），用于把工具调用按时间归轮 */
  turnMarks: number[];
}

/** 跑前清 Stirrup 任务缓存，避免上一轮 state.json 串跑（EVALUATION 风险 #3） */
async function clearStirrupCache(task: string): Promise<void> {
  const cache = new CacheManager([{ role: "user", content: task }]);
  await rm(cache.getCacheDir(), { recursive: true, force: true });
}

export async function runArmOnce(opts: {
  arm: Arm;
  task: string;
  budget: Budget;
  client: ChatCompletionsClient;
}): Promise<RunOutcome> {
  const { arm, task, budget, client } = opts;
  await clearStirrupCache(task);

  const records: ToolCallRecord[] = [];
  const turnUsage: Array<{ turn: number; inputTokens: number; outputTokens: number }> = [];
  const turnMarks: number[] = [];
  let llmCalls = 0;
  let inputTokens = 0;
  let outputTokens = 0;

  const agent = new Agent({
    client,
    // Stirrup 要求名字仅字母数字/_/-；臂名（如 bash-v0.1）里的点替换掉
    name: `bench-${arm.name.replace(/[^a-zA-Z0-9_-]/g, "-")}`,
    maxTurns: budget.maxTurns,
    systemPrompt: arm.systemPrompt,
    tools: arm.buildTools(records),
    finishTool: FINISH_TOOL_V02,
  });

  const ac = new AbortController();
  agent.on("turn:complete", (d) => {
    llmCalls++;
    inputTokens += d.tokenUsage?.input ?? 0;
    outputTokens += d.tokenUsage?.output ?? 0;
    turnUsage.push({ turn: llmCalls, inputTokens: d.tokenUsage?.input ?? 0, outputTokens: d.tokenUsage?.output ?? 0 });
    turnMarks.push(Date.now());
    if (outputTokens > budget.maxTokens) {
      ac.abort(new Error(`output token budget exceeded: ${outputTokens} > ${budget.maxTokens}`));
    }
  });
  const timer = setTimeout(() => ac.abort(new Error(`timeout after ${budget.timeoutMs}ms`)), budget.timeoutMs);

  agent.session({ noLogger: true });
  const t0 = Date.now();
  let result: AgentRunResult<{ reason?: string }> | null = null;
  let aborted: string | null = null;
  try {
    result = await agent.run(task, { signal: ac.signal });
  } catch (err) {
    aborted = err instanceof Error ? err.message : String(err);
  } finally {
    clearTimeout(timer);
  }
  const wallMs = Date.now() - t0;

  return {
    records,
    messageHistory: result?.messageHistory ?? [],
    llmCalls,
    inputTokens,
    outputTokens,
    wallMs,
    answerRaw: (result?.finishParams as { reason?: string } | undefined)?.reason ?? "",
    finishCalled: result !== null && result.finishParams !== undefined,
    aborted,
    turnUsage,
    turnMarks,
  };
}
