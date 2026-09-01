/** T3 熔断器单测（T1.2 模块验证） */
import { describe, expect, it } from "vitest";
import { classifyError, detectBreaker, detectR1, detectR2, f7FromEvents, type TurnEvent } from "../src/scorer/breaker.js";

const call = (name: string, args: string, ok: boolean, opts?: { emptyArrival?: boolean; errorContent?: string }) => ({
  name, rawArgs: args, ok, emptyArrival: opts?.emptyArrival, errorContent: opts?.errorContent,
});
const turn = (n: number, ...calls: ReturnType<typeof call>[]): TurnEvent => ({ turn: n, calls });

describe("classifyError", () => {
  it("ok=true → success", () => expect(classifyError(true)).toBe("success"));
  it("timeout → infra", () => expect(classifyError(false, "timeout after 180000ms")).toBe("infra"));
  it("429 → infra", () => expect(classifyError(false, "429 rate limit reached")).toBe("infra"));
  it("500 → infra", () => expect(classifyError(false, "HTTP 500: Internal server error")).toBe("infra"));
  it("参数校验失败 → semantic", () => expect(classifyError(false, "参数校验失败：query 必须为非空 AST 对象")).toBe("semantic"));
  it("空到达 → semantic", () => expect(classifyError(false, "空到达：query 为空对象")).toBe("semantic"));
  it("无错误内容 → semantic（默认）", () => expect(classifyError(false)).toBe("semantic"));
});

describe("R1 同参循环", () => {
  it("连续 3 次同工具同参语义失败 → R1 触发（K=3）", () => {
    const events = [
      turn(1, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
      turn(2, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
      turn(3, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
    ];
    const sig = detectR1(events, 3);
    expect(sig).not.toBeNull();
    expect(sig!.rule).toBe("R1_call_loop");
    expect(sig!.turnIndex).toBe(3);
    expect(sig!.toolName).toBe("traffic_query");
    expect(sig!.errorBucket).toBe("semantic");
  });

  it("同参失败 2 次 → 换参数成功 → 不触发（K=3）", () => {
    const events = [
      turn(1, call("traffic_query", '{"query":{}}', false)),
      turn(2, call("traffic_query", '{"query":{}}', false)),
      turn(3, call("traffic_query", '{"query":{"scope":"conversation"}}', true)), // 换参数成功
      turn(4, call("traffic_overview", '{"capture_id":"cap_1"}', true)),
    ];
    expect(detectR1(events, 3)).toBeNull();
  });

  it("K=4 时 3 次连败不触发", () => {
    const events = [
      turn(1, call("shell", "ls -la", false)),
      turn(2, call("shell", "ls -la", false)),
      turn(3, call("shell", "ls -la", false)),
    ];
    expect(detectR1(events, 4)).toBeNull();
  });

  it("infra 超时同参重试 ×3 → 不触发 R1（非语义失败）", () => {
    const events = [
      turn(1, call("traffic_query", '{"query":{}}', false, { errorContent: "timeout after 180000ms" })),
      turn(2, call("traffic_query", '{"query":{}}', false, { errorContent: "timeout after 180000ms" })),
      turn(3, call("traffic_query", '{"query":{}}', false, { errorContent: "timeout after 180000ms" })),
    ];
    const sig = detectR1(events, 3);
    expect(sig).toBeNull(); // infra 失败不触发 R1
  });

  it("不同工具的失败不累积", () => {
    const events = [
      turn(1, call("traffic_query", '{"query":{}}', false)),
      turn(2, call("traffic_inspect", '{"capture_id":"cap_1"}', false)),
      turn(3, call("traffic_query", '{"query":{}}', false)),
    ];
    expect(detectR1(events, 3)).toBeNull();
  });
});

describe("R2 空转循环", () => {
  it("连续 N 轮零工具调用 → R2 触发（N=5）", () => {
    const events = [turn(1), turn(2), turn(3), turn(4), turn(5)]; // 5 轮全零调用
    const sig = detectR2(events, 5);
    expect(sig).not.toBeNull();
    expect(sig!.rule).toBe("R2_idle_loop");
    expect(sig!.turnIndex).toBe(5);
  });

  it("文本+调用混合轮 → 不触发 R2", () => {
    const events = [
      turn(1), turn(2), turn(3),
      turn(4, call("traffic_query", '{"query":{}}', true)), // 第 4 轮有调用
      turn(5), // 第 5 轮又空
    ];
    expect(detectR2(events, 5)).toBeNull(); // 只有 2 连续空轮
  });

  it("N=8 时 5 轮空转不触发", () => {
    const events = [turn(1), turn(2), turn(3), turn(4), turn(5)];
    expect(detectR2(events, 8)).toBeNull();
  });
});

describe("组合检测", () => {
  it("R1 优先于 R2", () => {
    const events = [
      turn(1, call("t", "{}", false)),
      turn(2, call("t", "{}", false)),
      turn(3, call("t", "{}", false)),
      turn(4), turn(5), turn(6), turn(7), turn(8),
    ];
    const sig = detectBreaker(events, { k: 3, n: 5 });
    expect(sig!.rule).toBe("R1_call_loop"); // R1 在第 3 轮先触发
  });
});

describe("f7FromEvents（F7 单一事实源）", () => {
  it("与 detectF7 语义一致", () => {
    const events = [
      turn(1, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
      turn(2, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
      turn(3, call("traffic_query", '{"query":{}}', false, { emptyArrival: true })),
    ];
    const f7 = f7FromEvents(events);
    expect(f7.binding).toBe(true);
    expect(f7.emptyArrivalCount).toBe(3);
    expect(f7.longestSameArgsStreak).toBe(3);
  });
});
