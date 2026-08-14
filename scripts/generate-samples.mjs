#!/usr/bin/env node
/**
 * 生成 docs/samples/ —— 「样例即规范」的端到端转录。
 * 用 traffic-core 走一遍完整 agent loop（open → overview → query → inspect → event），
 * 每轮输入输出定稿为 JSON，作为 IR/DSL/工具行为的对照规范与回归基线。
 *
 * 用法：node scripts/generate-samples.mjs [path/to/pcap]
 */
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TrafficSession } from "../packages/traffic-core/dist/index.js";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pcap = process.argv[2] ?? path.join(repoRoot, "fixtures/web-session.pcap");
const outDir = path.join(repoRoot, "docs/samples");
const cacheDir = path.join(repoRoot, "node_modules/.cache/sample-gen");

const steps = [];

function record(tool, input, output) {
  steps.push({ tool, input, output });
}

await rm(cacheDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

const session = await TrafficSession.open(pcap, { cacheDir, autoDownload: false });

// Round 1 —— 建立 Capture Identity
record("traffic_open", { path: pcap }, { capture: session.capture });

// Round 2 —— 概览（轻索引）
const overview = await session.overview();
record("traffic_overview", { capture_id: session.capture.capture_id }, overview);

// Round 3 —— 找出有时延/重传特征的会话
const slowQ = await session.query({
  scope: "conversation",
  where: [{ field: "retransmission_count", op: "gt", value: 0 }],
  select: [
    "conversation_id",
    "transport",
    "initiator_ip",
    "responder_ip",
    "duration_ms",
    "retransmission_count",
    "tcp_handshake_ms",
    "tls_handshake_ms",
  ],
  order_by: [{ field: "retransmission_count", direction: "desc" }],
});
record("traffic_query(conversations with retransmissions)", { capture_id: session.capture.capture_id, query: {
  scope: "conversation",
  where: [{ field: "retransmission_count", op: "gt", value: 0 }],
  order_by: [{ field: "retransmission_count", direction: "desc" }],
} }, slowQ);

// Round 4 —— 下钻最可疑的会话
const topConv = slowQ.result.items[0]?.conversation_id ?? "conv:tcp:0";
const inspect = await session.inspect(topConv);
record("traffic_inspect", { capture_id: session.capture.capture_id, conversation_id: topConv }, inspect);

// Round 5 —— 事件级证据（frame numbers）
const evQ = await session.query({
  scope: "event",
  where: [
    { field: "conversation_id", op: "eq", value: topConv },
    { field: "type", op: "eq", value: "tcp_retransmission" },
  ],
  select: ["event_id", "time_ms", "direction", "frame_number"],
  order_by: [{ field: "time_ms", direction: "asc" }],
});
record("traffic_query(retransmission events)", { capture_id: session.capture.capture_id, query: {
  scope: "event",
  where: [
    { field: "conversation_id", op: "eq", value: topConv },
    { field: "type", op: "eq", value: "tcp_retransmission" },
  ],
} }, evQ);

// Round 6 —— 长尾组合查询示例：NXDOMAIN 的 DNS 应答
const nxdomain = await session.query({
  scope: "event",
  where: [{ field: "type", op: "eq", value: "dns_response" }],
  select: ["event_id", "time_ms", "frame_number"],
  order_by: [{ field: "time_ms", direction: "asc" }],
});
record("traffic_query(dns responses)", { capture_id: session.capture.capture_id, query: {
  scope: "event",
  where: [{ field: "type", op: "eq", value: "dns_response" }],
} }, nxdomain);


// Round 7 —— attr.* 查询：NXDOMAIN 的 DNS 应答
const nxd = await session.query({
  scope: "event",
  where: [
    { field: "type", op: "eq", value: "dns_response" },
    { field: "attr.rcode_num", op: "eq", value: 3 },
  ],
  select: ["event_id", "time_ms", "frame_number"],
});
record("traffic_query(attr.rcode_num=3 NXDOMAIN)", { capture_id: session.capture.capture_id, query: { scope: "event", where: [{ field: "type", op: "eq", value: "dns_response" }, { field: "attr.rcode_num", op: "eq", value: 3 }] } }, nxd);

// Round 8 —— 帧级证据复核（固定字段集原始记录）
const evd = await session.evidence({ frames: [8, 11, 14] });
record("traffic_evidence", { capture_id: session.capture.capture_id, frames: [8, 11, 14] }, evd);

// Round 9 —— 时序聚合（双向吞吐分箱）
const tsr = await session.timeseries("conv:tcp:0", "bytes", 100);
record("traffic_timeseries", { capture_id: session.capture.capture_id, conversation_id: "conv:tcp:0", metric: "bytes", bin_ms: 100 }, tsr);

// 索引一并落盘（供 ir-schema 文档引用）
const index = await session.ensureIndex();
const extraction = await session.ensureExtraction();

for (const [i, step] of steps.entries()) {
  const file = path.join(outDir, `${String(i + 1).padStart(2, "0")}-${step.tool.replace(/[^\w.]+/g, "-")}.json`);
  await writeFile(file, JSON.stringify(step, null, 2) + "\n", "utf8");
  console.log(`wrote ${path.relative(repoRoot, file)}`);
}
await writeFile(path.join(outDir, "light-index.json"), JSON.stringify(index, null, 2) + "\n");
await writeFile(
  path.join(outDir, "extraction-summary.json"),
  JSON.stringify(
    {
      conversations: extraction.conversations,
      events: extraction.events,
      note: "events carry evidence.frame_number; attributes are tshark heuristic projections (see detection)",
    },
    null,
    2,
  ) + "\n",
);
console.log(`\ncapture_id=${session.capture.capture_id} conversations=${extraction.conversations.length} events=${extraction.events.length}`);
