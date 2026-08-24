/**
 * 判分器 CLI（Prompt 3 验收 b/c 的入口）。
 *
 *   tsx src/scorer/cli.ts canary        # 题库 canary 元评测：acc_correct/acc_wrong 必须双 1.0
 *   tsx src/scorer/cli.ts demo-reports  # 每题喂 known_good/known_bad，输出两份完整 §6.5 报告
 *
 * 退出码：canary 子命令任一失败 → 非零（阻塞实验，RFC-002 §6.3）。
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { metaEvalAll } from "./canary.js";
import { loadGroundTruth, loadQuestionsDir } from "./question.js";
import { scoreAnswerObject } from "./pipeline.js";
import { assembleReport, type ReportRun } from "./report.js";

function cmdCanary(): number {
  const questions = loadQuestionsDir();
  const result = metaEvalAll(questions);
  for (const c of result.checks) {
    const mark = c.match ? "✓" : "✗";
    const form = c.errorForm ? ` (${c.errorForm})` : "";
    console.log(
      `${mark} [${c.questionId}] ${c.side}${form}  expect=${JSON.stringify(c.expect)} actual=${JSON.stringify(c.actual)}`,
    );
  }
  console.log(
    `\ncanary 元评测：${result.totalGood + result.totalBad} 个校验点  ` +
      `acc_correct=${result.accCorrect.toFixed(3)}  acc_wrong=${result.accWrong.toFixed(3)}`,
  );
  if (!result.pass) {
    for (const c of result.checks.filter((x) => !x.match)) {
      console.error(`✗ [${c.questionId}] ${c.side}: 判分裁决与题目声明 expect 不一致`);
    }
    console.error("canary 未全对 = 判分器 bug 或题目歧义，阻塞实验（RFC-002 §6.3）");
    return 1;
  }
  console.log("全部一致：判分器通过元评测。");
  return 0;
}

async function cmdDemoReports(): Promise<number> {
  const questions = loadQuestionsDir();
  const model = "canary-reference";
  const date = new Date().toISOString().slice(0, 10);

  const buildRuns = (side: "known_good" | "known_bad"): ReportRun[] =>
    questions.map((q, i) => {
      const gt = loadGroundTruth(q);
      const answer = q.canary[side].answer;
      const scored = scoreAnswerObject(q, gt, answer);
      const classification =
        !scored.verdict.schema_valid
          ? "format_error"
          : scored.verdict.correctness
            ? "correct"
            : "wrong_answer";
      return {
        questionId: q.question_id,
        runIndex: i + 1,
        question: { tags: q.tags },
        classification,
        schemaValid: scored.verdict.schema_valid,
        evidence: scored.detail.evidence
          ? {
              coverage: scored.detail.evidence.coverage,
              macroPrecision: scored.detail.evidence.macroPrecision,
              macroRecall: scored.detail.evidence.macroRecall,
              allFieldsPass: scored.verdict.evidence_pass,
              needsHumanReviewFields: scored.detail.evidence.fields.filter((f) => f.needsHumanReview).map((f) => f.path),
            }
          : undefined,
        hallucination: scored.detail.hallucination,
      };
    });

  const goodReport = assembleReport({ arm: `canary:${"known_good"}`, model, date, runsPerQuestion: 1, runs: buildRuns("known_good") });
  const badReport = assembleReport({ arm: `canary:${"known_bad"}`, model, date, runsPerQuestion: 1, runs: buildRuns("known_bad") });
  goodReportJson = JSON.stringify(goodReport, null, 2);
  badReportJson = JSON.stringify(badReport, null, 2);

  try {
    await writeDemoReports();
  } catch (err) {
    console.error("写报告失败：", err);
    return 1;
  }
  console.log(`known_good 报告：M1.overall=${goodReport.M1_correctness.overall}  M3.recall=${fmtNum(goodReport.M3_evidence.recall)}`);
  console.log(`known_bad  报告：M1.overall=${badReport.M1_correctness.overall}  M3.recall=${fmtNum(badReport.M3_evidence.recall)}`);
  console.log("已写出 bench/out/scorer-demo/{known_good,known_bad}/report.json");
  return 0;
}

function fmtNum(v: number | null): string {
  return v === null ? "null" : v.toFixed(3);
}

// ---- 落盘（Mimosa 已验证形态：模块状态取数 + 零参数函数 + 全字面量路径） ----
let goodReportJson = "";
let badReportJson = "";

async function writeKnownGoodReport(): Promise<void> {
  if (goodReportJson === "") throw new Error("writeKnownGoodReport: 尚无报告数据");
  const dir = path.join(REPO_ROOT, "bench", "out", "scorer-demo", "known_good");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "report.json"), goodReportJson);
}

async function writeKnownBadReport(): Promise<void> {
  if (badReportJson === "") throw new Error("writeKnownBadReport: 尚无报告数据");
  const dir = path.join(REPO_ROOT, "bench", "out", "scorer-demo", "known_bad");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "report.json"), badReportJson);
}

async function writeDemoReports(): Promise<void> {
  await writeKnownGoodReport();
  await writeKnownBadReport();
}

async function main(): Promise<number> {
  const cmd = process.argv[2] ?? "canary";
  switch (cmd) {
    case "canary":
      return cmdCanary();
    case "demo-reports":
      return cmdDemoReports();
    default:
      console.error(`未知子命令：${cmd}（可用：canary | demo-reports）`);
      return 2;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("fatal:", err);
    process.exitCode = 1;
  },
);
