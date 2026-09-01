/**
 * M3 簇等价档（T2，bench v3）：precision 与 recall 解耦锚定。
 *
 * 裁决（选项 b，2026-08-28 拍板）：
 * - precision 簇锚定：|cited ∩ attack_cluster| / |cited|
 *   attack_cluster = evidence_frames ∪ attack_chain 全部帧（不含 distractor_frame_set）
 * - recall 采样锚定：|cited ∩ gold_sample| / |gold_sample|
 *   gold_sample = evidence_frames（RFC-002 采样即"必找关键帧"定义）
 * - 按 stage 分解：每 stage 的 cited 帧对"该 stage 的簇"与"该 stage 的 gold 采样"分别计
 *
 * 不改既有题型路径：本模块是独立函数，不侵入 evidence.ts 的 E1 路径。
 * E1 历史不变性：cited ⊆ gold ⊆ cluster ⇒ 三口径（朴素 / 簇锚定 / 采样锚定）同值。
 */

export interface StageCluster {
  stage: string;
  clusterFrames: number[]; // 该 stage 的全部攻击帧
  goldSample: number[]; // 该 stage 的采样关键帧
}

export interface ClusterInput {
  /** 全局攻击簇 = evidence_frames ∪ attack_chain 全部帧 */
  attackCluster: number[];
  /** 全局 gold 采样 */
  goldSample: number[];
  /** distractor 帧（不在簇内——引用照常扣 precision） */
  distractorFrames: number[];
  /** 按 stage 分解 */
  stages: StageCluster[];
}

export interface ClusterPR {
  precisionCluster: number;
  recallSample: number;
  /** 朴素口径（对比用，不作为主指标） */
  precisionNaive: number;
}

export interface M3ClusterResult {
  /** 字段级（attack_type 等标量字段的证据） */
  fields: Record<string, ClusterPR & { citedCount: number }>;
  /** attack_chain 的 stage 级分解 */
  stages: Array<ClusterPR & { stage: string; citedCount: number }>;
  /** 整体聚合（所有字段 cited 并集 vs 全局簇/采样） */
  overall: ClusterPR;
}

/**
 * 从 builder gold.json 构建 ClusterInput（gold.json 的 attack_chain 只含采样帧——
 * 全簇需从 bench-gt.json 的 frame kind 构建）。
 */
export function buildClusterInput(gold: {
  evidence_frames?: number[];
  attack_chain?: Array<{ stage: string; frames: number[] }>;
  distractor_frame_set?: number[];
}): ClusterInput {
  const chain = gold.attack_chain ?? [];
  const clusterSet = new Set<number>(gold.evidence_frames ?? []);
  for (const s of chain) for (const f of s.frames) clusterSet.add(f);
  const goldSample = gold.evidence_frames ?? [];
  const distractor = gold.distractor_frame_set ?? [];

  const stages: StageCluster[] = chain.map((s) => ({
    stage: s.stage,
    clusterFrames: s.frames,
    goldSample: goldSample.filter((f) => s.frames.includes(f)),
  }));

  return {
    attackCluster: [...clusterSet],
    goldSample,
    distractorFrames: distractor,
    stages,
  };
}

/**
 * 从 bench-gt.json 的 frame kind 构建完整 ClusterInput（推荐——含全量攻击帧）。
 * frame kind 词表：gold_evidence（采样关键帧）/ attack（非采样攻击帧）/ distractor。
 */
export function buildClusterFromBenchGt(benchGt: {
  frames?: Array<{ frame: number; kind: string; conv?: string | null }>;
}): ClusterInput & { clusterSize: number } {
  const frames = benchGt.frames ?? [];
  const cluster: number[] = [];
  const goldSample: number[] = [];
  const distractor: number[] = [];
  for (const f of frames) {
    if (f.kind === "gold_evidence") {
      goldSample.push(f.frame);
      cluster.push(f.frame);
    } else if (f.kind === "attack") {
      cluster.push(f.frame);
    } else if (f.kind === "distractor") {
      distractor.push(f.frame);
    }
  }
  return {
    attackCluster: cluster,
    goldSample,
    distractorFrames: distractor,
    stages: [], // bench-gt 无逐帧 stage 标签——stage 级需 gold.json attack_chain 补充
    clusterSize: cluster.length,
  };
}

function prOf(cited: number[], cluster: number[], goldSample: number[]): ClusterPR {
  const c = new Set(cited);
  const clusterSet = new Set(cluster);
  const goldSet = new Set(goldSample);
  let inCluster = 0;
  for (const f of c) if (clusterSet.has(f)) inCluster++;
  let inGold = 0;
  for (const f of c) if (goldSet.has(f)) inGold++;
  const precisionNaive = c.size === 0 ? 0 : inGold / c.size; // 朴素口径 = 对 gold 采样的 precision
  return {
    precisionCluster: c.size === 0 ? 0 : inCluster / c.size,
    recallSample: goldSet.size === 0 ? 0 : inGold / goldSet.size,
    precisionNaive,
  };
}

/**
 * 对一个 run 的 answer 计算簇锚定 M3。
 * answer 形如 bench-question 的标准答案对象（字段 → {value, evidence}），
 * attack_chain 字段为 stage 数组（每元素 {value:{stage}, evidence:[frames]}）。
 */
export function scoreM3Cluster(
  answer: Record<string, unknown>,
  input: ClusterInput,
  attackChainField = "attack_chain",
): M3ClusterResult {
  const fields: M3ClusterResult["fields"] = {};
  const allCited: number[] = [];

  for (const [field, node] of Object.entries(answer)) {
    const n = node as { value?: unknown; evidence?: unknown } | null;
    if (!n || typeof n !== "object") continue;
    const cited = Array.isArray(n.evidence) ? (n.evidence as number[]) : [];
    if (field === attackChainField) {
      // attack_chain：stage 级分解（在 stages 路径处理）
      continue;
    }
    allCited.push(...cited);
    const pr = prOf(cited, input.attackCluster, input.goldSample);
    fields[field] = { ...pr, citedCount: cited.length };
  }

  // attack_chain stage 级：set 题的 answer 字段直接是 {value, evidence} 节点数组
  const chainArray = Array.isArray(answer[attackChainField])
    ? (answer[attackChainField] as Array<{ evidence?: number[] }>)
    : [];
  const stageResults: M3ClusterResult["stages"] = [];
  for (let i = 0; i < chainArray.length && i < input.stages.length; i++) {
    const el = chainArray[i];
    const stageInfo = input.stages[i]!;
    const cited = Array.isArray(el?.evidence) ? el!.evidence! : [];
    allCited.push(...cited);
    const pr = prOf(cited, stageInfo.clusterFrames, stageInfo.goldSample);
    stageResults.push({ stage: stageInfo.stage, ...pr, citedCount: cited.length });
  }

  const overall = prOf(allCited, input.attackCluster, input.goldSample);
  return { fields, stages: stageResults, overall };
}

/**
 * E1 不变性断言：cited ⊆ gold ⊆ cluster 时两个 precision 口径同值（=1）。
 * （R_sample 是独立维度，不参与此断言——cited ⊂ gold 时 R<1 是合法的。）
 */
export function assertE1Invariance(cited: number[], goldSample: number[], cluster: number[]): boolean {
  const pr = prOf(cited, cluster, goldSample);
  return pr.precisionCluster === pr.precisionNaive;
}
