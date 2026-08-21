#!/usr/bin/env node
// 题库自校验 CLI（垂直切片验收 a）：node bench/src/schema/validate-questions.mjs
// 检查项：
//   1) 每题信封字段/枚举/结构（RFC-002 §3 + 扩展字段）
//   2) gold 合成答案通过 answer_schema；gold_evidence 帧号 ∈ [1, gt.packet_count]（交叉加载 gt.json）
//   3) canary 元评测（RFC-002 §6.3）：判分器对 known_good/known_bad 的裁决必须与题目声明 expect 完全一致
//   4) 全库断言：question_id 唯一、canary 错误形态 ≥3 种、题目数/canary 数符合切片预期
// 退出码：0 全绿；1 存在任何失败。

import fs from "node:fs";
import path from "node:path";
import {
  REPO_ROOT,
  validateEnvelope,
  metaEvalCanary,
  scoreAnswer,
} from "./question-schema.mjs";

const questionsDir = path.join(REPO_ROOT, "bench", "questions");
// 切片 5 题（2026-08-19）+ S9 两题 + D3 关联链一题（2026-08-21，AI 起草稿待人审）
const EXPECTED_QUESTION_COUNT = 8;

function main() {
  const files = fs.readdirSync(questionsDir).filter(f => f.endsWith(".json")).sort();
  if (files.length === 0) {
    console.error(`题库为空：${questionsDir}`);
    process.exit(1);
  }

  const gtCache = new Map();
  const loadGt = (rel) => {
    if (!gtCache.has(rel)) {
      const p = path.join(REPO_ROOT, rel);
      gtCache.set(rel, fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null);
    }
    return gtCache.get(rel);
  };

  let totalFailures = 0;
  let totalCanaries = 0;
  const ids = new Set();
  const errorFormCounts = {};
  const summaries = [];

  for (const f of files) {
    const q = JSON.parse(fs.readFileSync(path.join(questionsDir, f), "utf8"));
    const gt = q.capture?.gt ? loadGt(q.capture.gt) : null;
    const failures = [];

    if (!gt) failures.push(`无法加载 gt：${q.capture?.gt}`);

    failures.push(...validateEnvelope(q, gt));
    failures.push(...metaEvalCanary(q).map(m => `[${q.question_id}] canary 元评测不一致：${m}`));

    if (!ids.has(q.question_id)) ids.add(q.question_id);
    else failures.push(`[${q.question_id}] question_id 重复`);

    // 汇报用：判分明细
    const good = q.canary?.known_good ? scoreAnswer(q, q.canary.known_good.answer) : null;
    const bad = q.canary?.known_bad ? scoreAnswer(q, q.canary.known_bad.answer) : null;
    const kb = q.canary?.known_bad;
    if (kb?.error_form) errorFormCounts[kb.error_form] = (errorFormCounts[kb.error_form] ?? 0) + 1;
    totalCanaries += [good, bad].filter(Boolean).length;

    summaries.push({ f, q, good, bad, kb, failures });
  }

  // ---- 报告 ----
  console.log(`题库目录：${questionsDir}`);
  console.log(`题目数：${summaries.length}（切片预期 ${EXPECTED_QUESTION_COUNT}）；canary 判分校验点：${totalCanaries}\n`);

  for (const s of summaries) {
    const status = s.failures.length === 0 ? "PASS" : "FAIL";
    if (status === "FAIL") totalFailures += s.failures.length;
    console.log(`[${s.q.question_id}] ${status}  ${s.f}`);
    console.log(`  type=${s.q.type}  tags=${s.q.tags.skill.join("+")}×${s.q.tags.difficulty_label}  ir=${s.q.tags.ir_coverage}  pack=${s.q.tags.scenario_pack}`);
    if (s.good) {
      console.log(`  canary known_good : schema=${fmt(s.good.schema_valid)} correctness=${fmt(s.good.correctness)} evidence=${fmt(s.good.evidence_pass)}`);
    }
    if (s.bad && s.kb) {
      const extra = s.bad.schema_errors?.length ? `（schema 错误：${s.bad.schema_errors[0]}）` : "";
      console.log(`  canary known_bad  : form=${s.kb.error_form} schema=${fmt(s.bad.schema_valid)} correctness=${fmt(s.bad.correctness)} evidence=${fmt(s.bad.evidence_pass)}${extra}`);
    }
    for (const msg of s.failures) console.log(`    ✗ ${msg}`);
    console.log("");
  }

  const distinctForms = Object.keys(errorFormCounts).length;
  console.log(`canary 错误形态覆盖：${distinctForms}/3 种  ${JSON.stringify(errorFormCounts)}`);
  if (distinctForms < 3) {
    console.log("  ✗ 错误形态须至少覆盖三种（值错/证据帧错/格式错），不许全是值错");
    totalFailures += 1;
  }
  if (summaries.length !== EXPECTED_QUESTION_COUNT) {
    console.log(`  ✗ 垂直切片预期 ${EXPECTED_QUESTION_COUNT} 题，实际 ${summaries.length} 题`);
    totalFailures += 1;
  }
  if (totalCanaries !== EXPECTED_QUESTION_COUNT * 2) {
    console.log(`  ✗ 预期 ${EXPECTED_QUESTION_COUNT * 2} 个 canary 判分校验点，实际 ${totalCanaries}`);
    totalFailures += 1;
  }

  console.log(totalFailures === 0
    ? `\n全部通过：${summaries.length} 题 + ${totalCanaries} canary（acc_correct=1.0, acc_wrong=1.0，RFC-002 §6.3）`
    : `\n失败 ${totalFailures} 项`);
  process.exit(totalFailures === 0 ? 0 : 1);
}

function fmt(b) {
  return b ? "✓" : "✗";
}

main();
