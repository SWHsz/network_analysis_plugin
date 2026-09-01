/** T2 合成答案测试：M3 簇等价档全部判例（零 LLM） */
import { describe, expect, it } from "vitest";
import { assertE1Invariance, buildClusterInput, scoreM3Cluster } from "../src/scorer/m3-cluster.js";

// 构造一个典型攻击场景的 cluster input（模拟 gold.json）
const gold = {
  evidence_frames: [100001, 100002, 100003, 100025, 100026, 100027], // 6 帧采样
  attack_chain: [
    { stage: "recon", frames: [100001, 100002, 100003, 100004, 100005, 100006, 100007, 100008] },
    { stage: "successful_read", frames: [100025, 100026, 100027, 100028, 100029, 100030] },
  ],
  distractor_frame_set: [100033, 100034, 100035],
};
const input = buildClusterInput(gold);
const clusterSorted = [...input.attackCluster].sort((a, b) => a - b);

const node = (value: unknown, evidence: number[]) => ({ value, evidence });

describe("M3 簇等价档：buildClusterInput", () => {
  it("簇 = evidence ∪ chain 全部帧（不含 distractor）", () => {
    expect(clusterSorted).toEqual([100001, 100002, 100003, 100004, 100005, 100006, 100007, 100008, 100025, 100026, 100027, 100028, 100029, 100030]);
    expect(input.goldSample).toEqual(gold.evidence_frames);
    expect(input.distractorFrames).toEqual([100033, 100034, 100035]);
  });

  it("stage 分解：cluster = 该 stage frames，gold_sample = evidence ∩ 该 stage", () => {
    expect(input.stages).toHaveLength(2);
    expect(input.stages[0]!.stage).toBe("recon");
    expect(input.stages[0]!.clusterFrames).toEqual([100001, 100002, 100003, 100004, 100005, 100006, 100007, 100008]);
    expect(input.stages[0]!.goldSample).toEqual([100001, 100002, 100003]);
    expect(input.stages[1]!.stage).toBe("successful_read");
    expect(input.stages[1]!.goldSample).toEqual([100025, 100026, 100027]);
  });
});

describe("M3 簇等价档：scoreM3Cluster 判例", () => {
  it("喷洒（全 14 簇帧正确分 stage）→ P=1.0 / R=1.0", () => {
    const answer = {
      attack_type: node("path_traversal", [...clusterSorted]),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002, 100003, 100004, 100005, 100006, 100007, 100008]),
        node({ stage: "successful_read" }, [100025, 100026, 100027, 100028, 100029, 100030]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    expect(r.overall.precisionCluster).toBe(1.0);
    expect(r.overall.recallSample).toBe(1.0);
    expect(r.overall.precisionNaive).toBeCloseTo(6 / 14); // 朴素口径只认 6 采样帧
    for (const s of r.stages) {
      expect(s.precisionCluster).toBe(1.0);
      expect(s.recallSample).toBe(1.0);
    }
  });

  it("极简（恰好引 6 采样帧）→ 三口径一致", () => {
    const answer = {
      attack_type: node("path_traversal", gold.evidence_frames),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002, 100003]),
        node({ stage: "successful_read" }, [100025, 100026, 100027]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    expect(r.overall.precisionCluster).toBe(1.0);
    expect(r.overall.recallSample).toBe(1.0);
    expect(r.overall.precisionNaive).toBe(1.0);
  });

  it("在簇但漏采样关键帧 → P=1.0 / R<1", () => {
    const answer = {
      attack_type: node("path_traversal", [100001, 100002, 100003, 100004, 100005, 100026, 100027]),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002, 100003, 100004, 100005]),
        node({ stage: "successful_read" }, [100026, 100027]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    expect(r.overall.precisionCluster).toBe(1.0);
    expect(r.overall.recallSample).toBeCloseTo(5 / 6); // 漏 100025
  });

  it("引背景帧（非攻击帧）→ 簇 P<1", () => {
    // 唯一引用帧：{100001,100002,500001,100025}——500001 是背景帧不在簇内
    const answer = {
      attack_type: node("path_traversal", [100001, 100002, 500001]),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002]),
        node({ stage: "successful_read" }, [100025]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    expect(r.overall.precisionCluster).toBeCloseTo(3 / 4); // 3/4 唯一帧在簇
    expect(r.overall.recallSample).toBeCloseTo(3 / 6);
  });

  it("引 distractor 帧 → 簇 P<1", () => {
    // 唯一引用帧：{100001,100002,100003,100033,100025,100026,100027}——100033 是 distractor
    const answer = {
      attack_type: node("path_traversal", [100001, 100002, 100003, 100033]),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002, 100003, 100033]),
        node({ stage: "successful_read" }, [100025, 100026, 100027]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    expect(r.overall.precisionCluster).toBeCloseTo(6 / 7); // 6/7 唯一帧在簇
    expect(r.overall.recallSample).toBe(1.0);
  });

  it("张冠李戴（帧对 stage 错）→ 该 stage 簇 P<1", () => {
    // 100025 是 read 帧放进 recon evidence
    const answer = {
      attack_type: node("path_traversal", [100001, 100002, 100003]),
      attack_chain: [
        node({ stage: "recon" }, [100001, 100002, 100003, 100025]),
        node({ stage: "successful_read" }, [100026, 100027]),
      ],
    };
    const r = scoreM3Cluster(answer, input);
    // 全局：100025 在簇内 → P_cluster = 1.0
    expect(r.overall.precisionCluster).toBe(1.0);
    // stage 级：recon 的簇不含 100025
    const recon = r.stages.find((s) => s.stage === "recon")!;
    expect(recon.precisionCluster).toBeCloseTo(3 / 4);
    // read stage 漏了 100025
    const read = r.stages.find((s) => s.stage === "successful_read")!;
    expect(read.recallSample).toBeCloseTo(2 / 3);
  });
});

describe("E1 不变性回归", () => {
  it("cited ⊆ gold ⊆ cluster ⇒ 两 precision 口径同值", () => {
    const goldSample = [8, 11, 14];
    const cluster = [8, 11, 14, 100, 200];
    expect(assertE1Invariance([8, 11, 14], goldSample, cluster)).toBe(true);
    expect(assertE1Invariance([8, 11], goldSample, cluster)).toBe(true);
    expect(assertE1Invariance([8], goldSample, cluster)).toBe(true);
  });

  it("cited 超出 gold 但在 cluster 内 ⇒ 簇 P ≠ 朴素 P（新口径生效）", () => {
    const goldSample = [8, 11, 14];
    const cluster = [8, 11, 14, 100, 200];
    expect(assertE1Invariance([8, 11, 14, 100], goldSample, cluster)).toBe(false);
  });
});
