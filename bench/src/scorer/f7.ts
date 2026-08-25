/**
 * F7 工具绑定失败分类（tool_binding_failure）——v0.2 协议新增，与 f6.ts 平行。
 *
 * 背景：kimi-k3/ast 出现参数绑定死循环（29/29 次 traffic_query 调用全部以 {} 或
 * 缺失到达工具端，模型连续重试同参数直至打满轮次），v0.1 被误分类为
 * budget_exhausted。F7 只依赖 arrival-side 遥测判定，不对模型意图做假设：
 *
 *   主判据：必要参数到达为空/缺失且该调用校验失败，run 内 ≥3 次
 *   辅判据：同工具同参数（规范化后）连续失败 ≥3 次
 *
 * 优先级 F7 > budget_exhausted（绑定死循环烧完轮次归 F7）；只重新分类失败 run
 * （budget_exhausted / no_finish_call 类），完成态 run 保持原分类并记
 * binding_failures_count 诊断字段。五分桶：forensic_correct / forensic_wrong /
 * protocol_noncompliance / budget_exhausted / tool_binding_failure。
 */
import type { OutcomeBucket } from "./f6.js";

export type FinalBucket = OutcomeBucket | "tool_binding_failure";

export interface CallLite {
  name: string;
  /** 规范化参数串（JSON.stringify，键序原样即可——同一模型重复调用逐字节相同） */
  argsJson: string;
  ok: boolean;
  /** 该调用校验错误含「空到达」标注（必要参数到达为空/缺失） */
  emptyArrival?: boolean;
}

export interface F7Detection {
  binding: boolean;
  emptyArrivalCount: number;
  longestSameArgsStreak: number;
  evidence: string;
}

/** run 内调用序列 → F7 判定（主判据 ≥3 次空到达失败；辅判据同参连败 ≥3 次） */
export function detectF7(calls: CallLite[]): F7Detection {
  const emptyFails = calls.filter((c) => c.emptyArrival === true && !c.ok);
  let longest = 0;
  let cur = 0;
  let curKey = "";
  for (const c of calls) {
    const key = `${c.name}|${c.argsJson}`;
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
  const mainHit = emptyFails.length >= 3;
  const subHit = longest >= 3;
  return {
    binding: mainHit || subHit,
    emptyArrivalCount: emptyFails.length,
    longestSameArgsStreak: longest,
    evidence: `空到达失败 ${emptyFails.length} 次；最长同参连败 ${longest} 次`,
  };
}

/** 失败 run 的桶归属：F7 优先于 budget_exhausted；完成态不重分类 */
export function applyF7(bucket: OutcomeBucket, detection: F7Detection, runCompleted: boolean): FinalBucket {
  if (runCompleted) return bucket;
  if (detection.binding && (bucket === "budget_exhausted" || bucket === "protocol_noncompliance")) {
    return "tool_binding_failure";
  }
  return bucket;
}

/** v0.1 旧数据无 arrival 遥测时的代理判据（重分类用，须附臂级证据） */
export function detectF7FromProxy(input: {
  bucket: OutcomeBucket;
  armToolFailureRate: number; // 臂级该工具调用失败率（如 kimi/ast 29/29 → 1.0）
  proxyThreshold?: number;
}): boolean {
  const threshold = input.proxyThreshold ?? 0.9;
  return input.bucket === "budget_exhausted" && input.armToolFailureRate >= threshold;
}
