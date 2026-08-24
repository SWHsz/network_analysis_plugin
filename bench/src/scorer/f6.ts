/**
 * F6 协议不合规分类（harness 交互失败 vs 取证能力失败的分离）。
 *
 * 口径（E1 follow-up 任务书）：
 * - no_finish_call        a) 不调 finish、纯文本收尾（answerRaw 为空）
 * - finish_payload_invalid b) 调了 finish 但 payload 判分器 parse 失败（answerRaw 非空 + format_error）
 * - no_tool_exploration   c) 全程未调用任何工具（不探索直接放弃）
 * - max_turns_exhausted   附注：打满轮次（可能能力问题也可能协议问题，单独记录不归类）
 *
 * outcome 四分桶（budget_exhausted 单列，可能与 F6 共存）：
 *   forensic_correct / forensic_wrong / protocol_noncompliance / budget_exhausted
 * 主口径 completion_rate_excluding_F6 只含 forensic_*——F6 反映 agent-harness
 * 协议交互能力，不反映抽取层质量，混算会污染 ρ 与完成率的函数关系。
 */
import type { RunClassification } from "./pipeline.js";

export interface F6Subtypes {
  no_finish_call: boolean;
  finish_payload_invalid: boolean;
  no_tool_exploration: boolean;
  max_turns_exhausted: boolean;
}

export type OutcomeBucket = "forensic_correct" | "forensic_wrong" | "protocol_noncompliance" | "budget_exhausted";

export function classifyF6(input: {
  classification: RunClassification;
  answerRaw: string;
  toolCallCount: number;
  llmCalls: number;
  maxTurns: number;
}): F6Subtypes {
  const isFormatError = input.classification === "format_error";
  return {
    // a) 空 answerRaw = 没有任何 finish reason（纯文本收尾或未收尾）
    no_finish_call: isFormatError && input.answerRaw.trim() === "",
    // b) 有 finish reason 但提取/校验失败 = payload 坏
    finish_payload_invalid: isFormatError && input.answerRaw.trim() !== "",
    // c) 全程零工具调用（toolRenderChars===0 可作旧数据代理）
    no_tool_exploration: input.toolCallCount === 0,
    max_turns_exhausted: input.llmCalls >= input.maxTurns,
  };
}

export function outcomeBucket(classification: RunClassification, f6: F6Subtypes): OutcomeBucket {
  if (classification === "format_error") {
    // 打满轮次导致的失败单列（可能能力/协议兼有）；未打满的格式失败归 F6
    return f6.max_turns_exhausted ? "budget_exhausted" : "protocol_noncompliance";
  }
  return classification === "correct" ? "forensic_correct" : "forensic_wrong";
}

export interface OutcomeBreakdown {
  forensic_correct: number;
  forensic_wrong: number;
  protocol_noncompliance: number;
  budget_exhausted: number;
}

export function emptyBreakdown(): OutcomeBreakdown {
  return { forensic_correct: 0, forensic_wrong: 0, protocol_noncompliance: 0, budget_exhausted: 0 };
}

/** 双口径完成率：excluding_F6 为 ρ 测量主口径 */
export function completionRates(breakdown: OutcomeBreakdown): {
  completion_rate_excluding_F6: string;
  completion_rate_raw: string;
} {
  const forensic = breakdown.forensic_correct + breakdown.forensic_wrong;
  const total = forensic + breakdown.protocol_noncompliance + breakdown.budget_exhausted;
  return {
    completion_rate_excluding_F6: forensic === 0 ? "0/0" : `${breakdown.forensic_correct}/${forensic}`,
    completion_rate_raw: total === 0 ? "0/0" : `${breakdown.forensic_correct}/${total}`,
  };
}
