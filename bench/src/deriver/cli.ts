/**
 * 模板派生 CLI：从 4 个 fixture 的 gt.json 派生批量题，写入 bench/questions-auto/。
 *
 *   pnpm --filter bench derive
 *
 * 写盘边界：目录全字面量拼接；文件名过 basename 白名单 + 解析后包含检查
 * （与 bench/src/scorer/question.ts 的读侧 containedIn 同构）。
 * 每题写入前先跑 canary 元评测——声明与判分器不一致的题目拒绝落盘。
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import { loadGroundTruth, type GroundTruth } from "../scorer/question.js";
import { metaEvalQuestion } from "../scorer/canary.js";
import { deriveAll } from "./templates.js";

const AUTO_DIR = path.join(REPO_ROOT, "bench", "questions-auto");
const FIXTURES = ["web-session", "mid-capture", "edge-cases", "tls-cert"] as const;

function loadGtByName(fixture: string): GroundTruth {
  assertSafeBasename(fixture, "fixture 名");
  const full = path.join(REPO_ROOT, "ground_truth", `${fixture}.gt.json`);
  return JSON.parse(readFileSync(full, "utf8")) as GroundTruth;
}

// node:fs 同步读放在顶部 import；此处单独引入以保持函数自洽
import { readFileSync } from "node:fs";

function containedIn(dir: string, fileName: string): string {
  assertSafeBasename(fileName, "题目文件名");
  const full = path.resolve(dir, fileName);
  if (!full.startsWith(dir + path.sep)) {
    throw new Error(`路径越出输出目录：${fileName}`);
  }
  return full;
}

async function main(): Promise<number> {
  const gtByCapture: Record<string, GroundTruth> = {};
  for (const f of FIXTURES) gtByCapture[f] = loadGtByName(f);

  const derived = deriveAll(gtByCapture);
  console.log(`[derive] 派生 ${derived.length} 题`);

  await mkdir(AUTO_DIR, { recursive: true });
  let written = 0;
  for (const { fileName, question } of derived) {
    // 落盘前门禁：canary 元评测必须一致（声明性 expect vs 判分器实跑）
    const problems = metaEvalQuestion(question);
    if (problems.some((c) => !c.match)) {
      console.error(`✗ ${fileName}: canary 元评测不一致，拒绝落盘`);
      for (const c of problems.filter((x) => !x.match)) {
        console.error(`    ${c.side}: expect=${JSON.stringify(c.expect)} actual=${JSON.stringify(c.actual)}`);
      }
      continue;
    }
    const target = containedIn(AUTO_DIR, fileName);
    await writeFile(target, `${JSON.stringify(question, null, 2)}\n`, "utf8");
    written++;
    console.log(`  ✓ ${fileName}`);
  }

  if (written !== derived.length) {
    console.error(`[derive] ${derived.length - written} 题未通过元评测门禁，已跳过`);
    return 1;
  }
  console.log(`[derive] 全部 ${written} 题写入 bench/questions-auto/（批量稿，待人审）`);
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[derive] fatal:", err);
    process.exitCode = 1;
  },
);
