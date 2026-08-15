#!/usr/bin/env node
/**
 * promotion-report —— 数据驱动的 IR 升级路线图。
 *
 * 挖掘历史会话（*.jsonl / dsh-session-*.zip 内的 session.jsonl）里的
 * traffic_raw_query 调用，统计字段名与 display_filter 的出现频次：
 * 同一组字段被反复查询 = 应提升进 IR（事件/指标/白名单）的信号。
 *
 * 用法：node scripts/promotion-report.mjs [session 文件或目录 ...]
 * 默认扫描当前目录与 dsh-session-*.zip。
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

async function* sessionFiles(args) {
  const targets = args.length > 0 ? args : ["."];
  for (const t of targets) {
    const stat = await readFile(t).then(
      () => "file",
      () => "other",
    ).catch(() => "other");
    let st;
    try {
      st = await import("node:fs/promises").then((f) => f.stat(t));
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      for (const name of await readdir(t)) {
        if (name.endsWith(".jsonl") || name.endsWith(".zip")) yield path.join(t, name);
      }
    } else {
      yield t;
    }
  }
}

function extractRawCalls(recs) {
  const calls = new Map(); // callId -> {fields, filter}
  for (const r of recs) {
    if (r.type !== "tool/call") continue;
    const d = r.data ?? {};
    if (d.name !== "traffic_raw_query") continue;
    let args = {};
    try {
      args = JSON.parse(d.arguments ?? "{}");
    } catch {
      /* ignore */
    }
    calls.set(d.callId, { fields: args.fields ?? [], filter: args.display_filter ?? "" });
  }
  return calls;
}

const fieldCount = new Map();
const filterTokenCount = new Map();
const errorCount = new Map();
let sessions = 0;
let rawCalls = 0;

for await (const file of sessionFiles(process.argv.slice(2))) {
  let text;
  try {
    if (file.endsWith(".zip")) {
      const { readFile: rf } = await import("node:fs/promises");
      const buf = await rf(file);
      const JSZip = null; // zip 解包用系统 unzip，避免依赖
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const { stdout } = await promisify(execFile)("unzip", ["-p", file]);
      text = stdout;
    } else {
      text = await readFile(file, "utf8");
    }
  } catch {
    continue;
  }
  const recs = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      recs.push(JSON.parse(line));
    } catch {
      /* skip */
    }
  }
  if (recs.length === 0 || !recs.some((r) => r.type === "tool/call")) continue;
  sessions += 1;
  const calls = extractRawCalls(recs);
  rawCalls += calls.size;
  for (const { fields, filter } of calls.values()) {
    for (const f of fields) {
      if (f === "frame.number") continue; // 我们强制附加的
      fieldCount.set(f, (fieldCount.get(f) ?? 0) + 1);
    }
    for (const tok of filter.match(/[a-z0-9_]+(?:\.[a-z0-9_]+)+/g) ?? []) {
      filterTokenCount.set(tok, (filterTokenCount.get(tok) ?? 0) + 1);
    }
  }
  // 自纠成本：raw_query 的 ERROR 结果数
  const errCalls = new Map();
  for (const r of recs) {
    if (r.type !== "tool/result") continue;
    const m = r.data?.message;
    const cid = m?.source?.callId;
    if (!calls.has(cid)) continue;
    for (const c of m?.content ?? []) {
      if (c?.type !== "tool-result") continue;
        for (const part of c.content ?? []) {
          if (part?.type === "text" && part.text?.startsWith("ERROR")) errCalls.set(cid, part.text);
        }
    }
  }
  for (const txt of errCalls.values()) {
    for (const m of txt.matchAll(/unknown tshark field\(s\): ([^\n.]+)/g)) {
      for (const f of m[1].split(",").map((s) => s.trim().split(" ")[0])) {
        if (f) errorCount.set(f, (errorCount.get(f) ?? 0) + 1);
      }
    }
  }
}

const top = (map, n = 15) =>
  [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

console.log(`sessions scanned: ${sessions}, traffic_raw_query calls: ${rawCalls}\n`);
console.log("== 字段频次（提升进 IR 的候选信号）==");
for (const [f, c] of top(fieldCount)) console.log(`${String(c).padStart(3)}  ${f}`);
console.log("\n== display_filter 中出现的字段 ==");
for (const [f, c] of top(filterTokenCount)) console.log(`${String(c).padStart(3)}  ${f}`);
console.log("\n== 猜错被拒的字段（命名困难点）==");
for (const [f, c] of top(errorCount)) console.log(`${String(c).padStart(3)}  ${f}`);
