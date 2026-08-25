/**
 * Arm 抽象与遥测类型（RFC-002 §5.1，含 v1.1 的 interfaceTokens 控制变量）。
 * 两臂共享同一最小 agent loop（SharedLoop），唯一变量是工具面（§5.2 v1.1）。
 */
import type { Tool } from "@stirrup/stirrup";

/** 运行预算：maxTurns 原生；maxTokens 为输出预算（turn:complete 累计超限即 abort）；timeoutMs 全局墙钟 */
export interface Budget {
  maxTurns: number;
  maxTokens: number;
  timeoutMs: number;
}

/** 单次工具调用记录（RFC-002 §5.1 transcript 硬需求） */
export interface ToolCallRecord {
  seq: number;
  name: string;
  args: unknown;
  ok: boolean;
  durationMs: number;
  /** 模型可见字符数：AST 臂为渲染文本，bash 臂为 stdout+stderr */
  resultChars: number;
  startedAtMs: number;
  /** v0.2 诊断遥测：解析前的原始参数串（provider→harness 链路的工具侧观测） */
  rawArgs?: string;
  rawArgsWasObject?: boolean;
  rawArgsTruncated?: boolean;
  argsParseError?: string | null;
  /** v0.2：该调用的参数校验错误含「空到达」标注（必要参数到达为空/缺失） */
  emptyArrival?: boolean;
}

export interface ArmMetrics {
  llmCalls: number;
  inputTokens: number;
  outputTokens: number;
  toolRenderChars: number;
  /** 工具描述/schema 注入的 token（chars/4 启发式，记录代理实测）——§10-I3 控制变量 */
  interfaceTokens: number;
  wallMs: number;
  budgetExhausted: boolean;
}

export interface ArmResult {
  arm: string;
  questionId: string;
  /** 终答原文（finish reason） */
  answerRaw: string;
  /** 提取+契约校验后的答案对象；undefined ⇒ format_error */
  answer?: Record<string, unknown>;
  formatError?: string;
  transcript: ToolCallRecord[];
  metrics: ArmMetrics;
  /** abort 原因（超时/输出预算）；null = 正常结束 */
  aborted: string | null;
}

/** 臂接口：名字、系统提示、工具面工厂（§5.1） */
/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
export interface Arm {
  readonly name: string;
  readonly systemPrompt: string;
  buildTools(records: ToolCallRecord[]): Array<Tool<any, any>>;
}
