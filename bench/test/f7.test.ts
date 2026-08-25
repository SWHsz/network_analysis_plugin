/** F7 工具绑定失败分类（scorer/f7.ts）：主/辅判据、优先级、旧数据代理判据 */
import { describe, expect, it } from "vitest";
import { applyF7, detectF7, detectF7FromProxy } from "../src/scorer/f7.js";
import type { CallLite } from "../src/scorer/f7.js";

const call = (name: string, argsJson: string, ok: boolean, emptyArrival = false): CallLite => ({
  name,
  argsJson,
  ok,
  emptyArrival,
});

describe("detectF7", () => {
  it("主判据：空到达失败 ≥3 次 → binding", () => {
    const calls = [
      call("traffic_query", '{"query":{}}', false, true),
      call("traffic_query", '{"query":{}}', false, true),
      call("traffic_query", '{"query":{}}', false, true),
    ];
    const d = detectF7(calls);
    expect(d.binding).toBe(true);
    expect(d.emptyArrivalCount).toBe(3);
    expect(d.longestSameArgsStreak).toBe(3);
  });

  it("kimi 特征合成用例：正常调用 + 连续空参死循环 + 正常失败混合", () => {
    const calls = [
      call("traffic_open", '{"path":"/x.pcap"}', true),
      call("traffic_overview", '{"capture_id":"cap_1"}', true),
      call("traffic_inspect", '{"capture_id":"cap_1","conversation_id":"conv:tcp:0"}', true),
      // 连续 5 次完全相同的空参 traffic_query（kimi q-web-002 run1 实测形态）
      ...Array.from({ length: 5 }, () => call("traffic_query", '{"query":{}}', false, true)),
      // 正常失败（参数不空、不连败）：不计入
      call("traffic_evidence", '{"capture_id":"cap_1","frames":[99]}', false, false),
      call("traffic_inspect", '{"capture_id":"cap_1","conversation_id":"conv:tcp:9"}', false, false),
    ];
    const d = detectF7(calls);
    expect(d.binding).toBe(true);
    expect(d.emptyArrivalCount).toBe(5);
    expect(d.longestSameArgsStreak).toBe(5);
  });

  it("零星失败（<3 次、无连败）不判 binding", () => {
    const calls = [
      call("traffic_query", '{"query":{}}', false, true),
      call("traffic_query", '{"query":{"scope":"bad"}}', false, false),
      call("traffic_query", '{"query":{"scope":"event"}}', true),
    ];
    expect(detectF7(calls).binding).toBe(false);
  });

  it("同参连败 ≥3 但非空到达（辅判据）也判 binding", () => {
    const calls = Array.from({ length: 4 }, () =>
      call("traffic_query", '{"query":{"scope":"nope"}}', false, false),
    );
    const d = detectF7(calls);
    expect(d.binding).toBe(true);
    expect(d.emptyArrivalCount).toBe(0);
    expect(d.longestSameArgsStreak).toBe(4);
  });

  it("成功调用打断连败计数", () => {
    const calls = [
      call("t", "{}", false, true),
      call("t", "{}", false, true),
      call("t", "{}", true),
      call("t", "{}", false, true),
    ];
    const d = detectF7(calls);
    expect(d.emptyArrivalCount).toBe(3);
    expect(d.longestSameArgsStreak).toBe(2);
  });
});

describe("applyF7 优先级", () => {
  const binding = { binding: true, emptyArrivalCount: 5, longestSameArgsStreak: 5, evidence: "" };

  it("F7 > budget_exhausted：绑定死循环烧完轮次归 F7", () => {
    expect(applyF7("budget_exhausted", binding, false)).toBe("tool_binding_failure");
  });

  it("no_finish_call 类（protocol_noncompliance）失败 run 也归 F7", () => {
    expect(applyF7("protocol_noncompliance", binding, false)).toBe("tool_binding_failure");
  });

  it("完成态 run 不重分类（即使有绑定失败史）", () => {
    expect(applyF7("forensic_correct", binding, true)).toBe("forensic_correct");
    expect(applyF7("forensic_wrong", binding, true)).toBe("forensic_wrong");
  });

  it("无 binding 证据时桶不变", () => {
    const none = { binding: false, emptyArrivalCount: 1, longestSameArgsStreak: 1, evidence: "" };
    expect(applyF7("budget_exhausted", none, false)).toBe("budget_exhausted");
    expect(applyF7("protocol_noncompliance", none, false)).toBe("protocol_noncompliance");
  });
});

describe("v0.1 旧数据代理判据", () => {
  it("臂级失败率 ≥0.9 的 budget run → F7；低失败率不误伤", () => {
    expect(detectF7FromProxy({ bucket: "budget_exhausted", armToolFailureRate: 29 / 29 })).toBe(true);
    expect(detectF7FromProxy({ bucket: "budget_exhausted", armToolFailureRate: 8 / 11 })).toBe(false);
    expect(detectF7FromProxy({ bucket: "forensic_correct", armToolFailureRate: 1.0 })).toBe(false);
  });
});
