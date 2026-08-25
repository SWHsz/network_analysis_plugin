/**
 * 参数校验错误四段式回显（v0.2 协议）：修复反馈环断裂——错误必须告诉模型
 * "收到了什么、什么没到、期望什么形状"，模型才有自纠的信息。
 *
 * 格式（总长 ≤300 chars，渲染预算敏感）：
 *   [tool] 参数校验失败：<问题>
 *   收到参数：<回显 parsed args，截断 200 chars>
 *   空到达：<必要参数名>（必要参数到达为空/缺失时显式标注——F7 的可观测信号）
 *   期望形状：<一级字段摘要>
 */

const EMPTY_ARRIVAL_MARKER = "空到达：";

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}…`;
}

export function paramValidationError(input: {
  tool: string;
  problem: string;
  received: unknown;
  /** 到达为空/缺失的必要参数名列表 */
  emptyArrivals?: string[];
  expectedShape: string;
}): string {
  const receivedText =
    input.received === undefined
      ? "(undefined)"
      : truncate(JSON.stringify(input.received) ?? String(input.received), 200);
  const lines = [
    `[${input.tool}] 参数校验失败：${input.problem}`,
    `收到参数：${receivedText}`,
  ];
  if (input.emptyArrivals && input.emptyArrivals.length > 0) {
    lines.push(`${EMPTY_ARRIVAL_MARKER}${input.emptyArrivals.join("、")}（必要参数到达为空/缺失）`);
  }
  lines.push(`期望形状：${input.expectedShape}`);
  return truncate(lines.join("\n"), 300);
}

/** withTiming 用：错误内容是否携带「空到达」标注 */
export function marksEmptyArrival(content: string): boolean {
  return content.includes(EMPTY_ARRIVAL_MARKER);
}
