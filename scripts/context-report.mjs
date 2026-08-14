#!/usr/bin/env node
/**
 * 上下文开销对比报告：v0.2 工具链 vs v0.1 会话中的 bash 转储路径。
 *
 * 对给定 pcap 走一遍 v0.2 典型分析链，用与 dsh-plugin 相同的渲染函数统计
 * 每步的模型可见字符数；若同目录存在 session.jsonl（v0.1 真实会话），
 * 额外统计其中 bash 工具输出的字符量作对照。
 *
 * 用法：node scripts/context-report.mjs [path/to/pcap]
 */
import path from "node:path";
import { stat } from "node:fs/promises";
import {
  TrafficSession,
  renderEnvelope,
  renderRows,
  applyRenderBudget,
} from "../packages/traffic-core/dist/index.js";

const pcap = path.resolve(process.argv[2] ?? "23.pcap");
try {
  await stat(pcap);
} catch {
  console.error(`capture not found: ${pcap}`);
  process.exit(1);
}

const rows = [];
const session = await TrafficSession.open(pcap, { cacheDir: "/tmp/ctx-report-cache", autoDownload: false });

const renderQueryLike = (result) =>
  applyRenderBudget(renderEnvelope(result), renderRows(result.items).split("\n"), "").text.length;

await (async () => {
  rows.push({ tool: "traffic_open", chars: JSON.stringify(session.capture).length });
  await session.ensureIndex();
})();

{
  const o = await session.overview();
  const convs = renderRows(
    o.top_conversations_by_bytes.map((c) => ({ a: c.endpoint_a, b: c.endpoint_b, frames: c.frames_a_to_b + c.frames_b_to_a })),
  );
  rows.push({ tool: "traffic_overview", chars: convs.length + 400 });
}
let topConv;
{
  const q = await session.query({
    scope: "conversation",
    order_by: [{ field: "bytes_total", direction: "desc" }],
    limit: 5,
  });
  topConv = q.result.items[0]?.conversation_id;
  rows.push({ tool: "traffic_query(conversations)", chars: renderQueryLike(q.result) });
}
{
  const i = await session.inspect(topConv);
  const tl = renderRows(
    i.timeline.items.map((e) => ({ t: e.time_ms, type: e.type, frame: e.evidence.kind === "frame" ? e.evidence.frame_number : null })),
  );
  rows.push({ tool: "traffic_inspect", chars: tl.length + 600 });
}
{
  const q = await session.query({
    scope: "event",
    where: [{ field: "conversation_id", op: "eq", value: topConv }],
    limit: 50,
  });
  rows.push({ tool: "traffic_query(events)", chars: renderQueryLike(q.result) });
}
{
  const ts = await session.timeseries(topConv, "bytes", 100);
  const body = ts.bins.map((b) => `${b.t_start_ms} ${b.forward ?? "-"} ${b.reverse ?? "-"}`).join("\n");
  rows.push({ tool: "traffic_timeseries(bytes)", chars: body.length + 120 });
}
{
  const ts = await session.timeseries(topConv, "rtt", 100);
  const body = ts.bins.map((b) => `${b.t_start_ms} ${b.forward ?? "-"} ${b.reverse ?? "-"}`).join("\n");
  rows.push({ tool: "traffic_timeseries(rtt)", chars: body.length + 120 });
}
{
  const evts = (await session.ensureExtraction()).events.filter((e) => e.conversation_id === topConv);
  const frames = evts.slice(0, 20).map((e) => (e.evidence.kind === "frame" ? e.evidence.frame_number : 0));
  const ev = await session.evidence({ frames });
  const body = renderRows(
    ev.frames.map((f) => ({ frame: f.frame_number, t: f.time_ms, seq: f.tcp_seq_raw, ack: f.tcp_ack_raw, len: f.tcp_len, flags: f.tcp_flags, an: f.analysis.join("|") })),
  );
  rows.push({ tool: "traffic_evidence(20 frames)", chars: body.length + 120 });
}

console.log(`capture: ${path.basename(pcap)} (${session.capture.capture_id}, ${session.capture.packet_count} packets)`);
console.log("");
for (const r of rows) console.log(`${r.tool.padEnd(34)} ${String(r.chars).padStart(8)} chars`);
const total = rows.reduce((a, b) => a + b.chars, 0);
console.log("-".repeat(44));
console.log(`${"TOTAL(v0.2 tools)".padEnd(34)} ${String(total).padStart(8)} chars`);

// v0.1 会话对照（可选）
try {
  const fs = await import("node:fs/promises");
  const lines = (await fs.readFile("session.jsonl", "utf8")).split("\n").filter(Boolean);
  let bashChars = 0;
  let bashCalls = 0;
  const calls = new Map();
  for (const line of lines) {
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    if (rec.type !== "tool/call") continue;
    const d = rec.data ?? {};
    if (d.name !== "bash") continue;
    calls.set(d.callId, true);
  }
  for (const line of lines) {
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    if (rec.type !== "tool/result") continue;
    const m = rec.data?.message;
    const cid = m?.source?.callId;
    if (!calls.has(cid)) continue;
    for (const c of m?.content ?? []) {
      if (c?.type !== "tool-result") continue;
      for (const part of c.content ?? []) {
        if (part?.type === "text" && part.text) {
          bashChars += part.text.length;
          bashCalls += 1;
          break;
        }
      }
    }
  }
  if (bashCalls > 0) {
    console.log("");
    console.log(`v0.1 session (session.jsonl): ${bashCalls} bash tool outputs, ${bashChars} chars visible to the model`);
    console.log(`v0.2 total is ~${(bashChars / Math.max(1, total)).toFixed(1)}x smaller for the equivalent analysis depth`);
  }
} catch {
  console.log("\n(session.jsonl not found — skipping v0.1 comparison)");
}
