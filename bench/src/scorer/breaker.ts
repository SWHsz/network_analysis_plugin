/**
 * T1.2 熔断器模块（单一事实源）。
 *
 * 两条机械规则（C 方案，2026-09-01 拍板）：
 * - R1 调用循环：同工具 + 同参数（rawArgs 字节级一致）连续语义失败 ≥K 次 → 触发
 * - R2 空转循环：连续 N 轮零工具调用（纯文本响应）→ 触发
 *
 * 失败分桶：
 * - 语义类（熔断目标）：参数校验失败 / 空到达 / schema 错误 → ok=false 且非 infra
 * - infra 类（单独报告）：timeout / 5xx / 429 → ok=false 且 aborted 含 infra 关键词
 *
 * 本模块是 F7 签名的唯一实现点——scorer 与 runner import 同一模块（08-28 教训）。
 */

// ---- 事件流类型 ----

export interface TurnEvent {
  /** 轮次号（1-based） */
  turn: number;
  /** 该轮的工具调用（空数组 = 纯文本轮 / R2 候选） */
  calls: Array<{
    name: string;
    rawArgs: string;
    ok: boolean;
    /** 参数校验失败含"空到达"标注 */
    emptyArrival?: boolean;
    /** 错误内容（用于 infra/语义分桶） */
    errorContent?: string;
  }>;
}

export type BreakerRule = "R1_call_loop" | "R2_idle_loop";

export interface BreakerSignal {
  rule: BreakerRule;
  turnIndex: number;
  detail: string;
  /** R1 附带：命中的工具名与参数 */
  toolName?: string;
  rawArgs?: string;
  /** R1 附带：错误类型分桶 */
  errorBucket?: "semantic" | "infra";
}

export interface BreakerParams {
  /** R1：同参连续语义失败触发阈值 */
  k: number;
  /** R2：连续零调用轮触发阈值 */
  n: number;
}

export const DEFAULT_PARAMS: BreakerParams = { k: 3, n: 5 };

// ---- infra/语义分桶 ----

const INFRA_PATTERNS = [
  /timeout/i, /timed?\s*out/i, /ETIMEDOUT/i,
  /\b5\d{2}\b/, /internal\s*server/i,
  /\b429\b/, /rate\s*limit/i, /quota/i, /insufficient\s*balance/i,
  /ECONNRESET/i, /ECONNREFUSED/i, /socket\s*hang\s*up/i,
];

export function classifyError(ok: boolean, errorContent?: string): "semantic" | "infra" | "success" {
  if (ok) return "success";
  const text = errorContent ?? "";
  if (INFRA_PATTERNS.some((p) => p.test(text))) return "infra";
  return "semantic";
}

// ---- R1：同参循环检测 ----

interface R1State {
  toolName: string;
  rawArgs: string;
  consecutiveFails: number;
  errorBucket: "semantic" | "infra";
}

/**
 * 对一个 run 的完整调用序列检测 R1。
 * 返回触发信号（或 null）。参数化 K。
 */
export function detectR1(
  events: TurnEvent[],
  k: number,
): BreakerSignal | null {
  let state: R1State | null = null;
  let lastTurn = 0;

  for (const ev of events) {
    for (const call of ev.calls) {
      const bucket = classifyError(call.ok, call.errorContent);
      const isSameCall = state !== null && state.toolName === call.name && state.rawArgs === call.rawArgs;

      if (!call.ok && bucket === "semantic") {
        if (isSameCall) {
          state!.consecutiveFails++;
        } else {
          state = {
            toolName: call.name,
            rawArgs: call.rawArgs,
            consecutiveFails: 1,
            errorBucket: bucket,
          };
        }
        if (state.consecutiveFails >= k) {
          return {
            rule: "R1_call_loop",
            turnIndex: ev.turn,
            detail: `同工具同参数语义失败 ${state.consecutiveFails} 次（≥K=${k}）：${state.toolName}`,
            toolName: state.toolName,
            rawArgs: state.rawArgs.slice(0, 200),
            errorBucket: state.errorBucket,
          };
        }
      } else {
        // 成功、infra 失败、或换了参数 → 重置计数
        state = null;
      }
    }
    lastTurn = ev.turn;
  }
  void lastTurn;
  return null;
}

// ---- R2：空转循环检测 ----

/**
 * 对一个 run 的轮次序列检测 R2。
 * 连续 N 轮零工具调用（纯文本响应）→ 触发。
 * 轮内有 ≥1 次调用（无论成败）即非零轮。
 */
export function detectR2(
  events: TurnEvent[],
  n: number,
): BreakerSignal | null {
  let consecutiveIdle = 0;
  for (const ev of events) {
    if (ev.calls.length === 0) {
      consecutiveIdle++;
      if (consecutiveIdle >= n) {
        return {
          rule: "R2_idle_loop",
          turnIndex: ev.turn,
          detail: `连续 ${consecutiveIdle} 轮零工具调用（≥N=${n}）`,
        };
      }
    } else {
      consecutiveIdle = 0;
    }
  }
  return null;
}

// ---- 组合检测 ----

export function detectBreaker(
  events: TurnEvent[],
  params: BreakerParams = DEFAULT_PARAMS,
): BreakerSignal | null {
  return detectR1(events, params.k) ?? detectR2(events, params.n);
}

// ---- F7 兼容接口（单一事实源：scorer 的 F7 判定 import 这里） ----

/**
 * 从 TurnEvent[] 提取 F7 判定所需的调用摘要。
 * scorer/f7.ts 的 detectF7 在有 TurnEvent 数据时应使用此函数（而非重复实现）。
 */
export function f7FromEvents(events: TurnEvent[]): {
  binding: boolean;
  emptyArrivalCount: number;
  longestSameArgsStreak: number;
  evidence: string;
} {
  let emptyArrival = 0;
  let longest = 0;
  let cur = 0;
  let curKey = "";
  for (const ev of events) {
    for (const c of ev.calls) {
      if (c.emptyArrival && !c.ok) emptyArrival++;
      const key = `${c.name}|${c.rawArgs}`;
      if (!c.ok && key === curKey) {
        cur++;
        longest = Math.max(longest, cur);
      } else if (!c.ok) {
        curKey = key;
        cur = 1;
        longest = Math.max(longest, cur);
      } else {
        curKey = "";
        cur = 0;
      }
    }
  }
  return {
    binding: emptyArrival >= 3 || longest >= 3,
    emptyArrivalCount: emptyArrival,
    longestSameArgsStreak: longest,
    evidence: `空到达失败 ${emptyArrival} 次；最长同参连败 ${longest} 次`,
  };
}
