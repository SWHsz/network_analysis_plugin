/**
 * 大包实例（pcap_builder 题卡实例化产物）的路径解析与 fixture 白名单扩展。
 *
 * S3 批（首卡大包标定）引入的第二类 capture：题卡实例按
 *   fixture = <card_id>-i<seed>-r<ρ档>   （如 s01-i1-r2）
 * 命名，全部产物自包含于 bench/fixtures/instances/<card_id>/i<seed>/<ρ档>/：
 *   benchmark.pcap            原始捕获（pcap_builder build_from_card 产物）
 *   benchmark_gt.json         三层 GT（pcap_builder 侧，私有）
 *   gold.json                 build gold（pcap_builder 侧，私有）
 *   questions.json            卡面题面（pcap_builder 侧，私有）
 *   bench-question.json       bench 信封（from-card.ts 桥接产物）
 *   bench-gt.json             bench GroundTruth 切片（from-card.ts 桥接产物，私有）
 *   meta.json                 桥接元数据（构建帧数/share/SHA/耗时）
 *
 * 边界口径与 paths.ts 一致：字面量目录段 + basename 白名单 + 解析后包含检查。
 * 实例目录整体位于 gitignore 覆盖路径（gt/gold 不入公开仓库，私有归档裁决）。
 */
import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";

/** 大包实例 fixture 命名：<card_id>-i<seed>-r<tier>，全小写字母数字段 */
export const INSTANCE_FIXTURE_RE = /^([a-z][a-z0-9]*)-i(\d+)-r(\d+)$/;

export function isInstanceFixture(fixture: string): boolean {
  return INSTANCE_FIXTURE_RE.test(fixture);
}

/** 实例目录根：bench/fixtures/instances（gitignore 覆盖，gt/gold 私有） */
export function instancesRoot(): string {
  return path.join(REPO_ROOT, "bench", "fixtures", "instances");
}

/** fixture → 实例目录（不存在或命名不合法返回 null） */
export function instanceDirOf(fixture: string): string | null {
  const m = INSTANCE_FIXTURE_RE.exec(fixture);
  if (!m) return null;
  const card = m[1]!;
  const seed = m[2]!;
  const tier = m[3]!;
  for (const seg of [card, `i${seed}`, `r${tier}`]) assertSafeBasename(seg, "实例路径段");
  const dir = path.join(instancesRoot(), card, `i${seed}`, `r${tier}`);
  return fs.existsSync(dir) ? dir : null;
}

/** 实例的 bench GroundTruth 绝对路径（存在性由调用方判定） */
export function instanceGtPath(fixture: string): string | null {
  const dir = instanceDirOf(fixture);
  return dir ? path.join(dir, "bench-gt.json") : null;
}

/** 实例的 pcap 绝对路径 */
export function instancePcapPath(fixture: string): string {
  const dir = instanceDirOf(fixture);
  if (!dir) throw new Error(`未知大包实例 fixture：${fixture}（实例目录不存在）`);
  return path.join(dir, "benchmark.pcap");
}

/** 实例的 bench 信封题目绝ut路径 */
export function instanceQuestionPath(fixture: string): string | null {
  const dir = instanceDirOf(fixture);
  return dir ? path.join(dir, "bench-question.json") : null;
}

/** 扫描实例注册表：现有全部 fixture 名（字典序） */
export function listInstanceFixtures(): string[] {
  const root = instancesRoot();
  const out: string[] = [];
  if (!fs.existsSync(root)) return out;
  for (const card of fs.readdirSync(root)) {
    const cardDir = path.join(root, card);
    for (const seed of fs.readdirSync(cardDir)) {
      const seedDir = path.join(cardDir, seed);
      for (const tier of fs.readdirSync(seedDir)) {
        const fixture = `${card}-${seed}-${tier}`;
        if (isInstanceFixture(fixture) && fs.existsSync(path.join(seedDir, tier, "bench-question.json"))) {
          out.push(fixture);
        }
      }
    }
  }
  return out.sort();
}
