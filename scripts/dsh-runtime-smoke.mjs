#!/usr/bin/env node
/**
 * DSH 运行时冒烟驱动（不依赖 LLM）：
 * 用真实安装的 @deepseek-ai/{cordis,schemastery,dsh-tools}（~/node_modules，
 * 即 DSH 宿主解析到的同一份）加载插件 dist，执行 apply() 并直接调用工具。
 *
 * 覆盖：模块加载（peer 依赖解析）、Config schema（真实 schemastery 校验）、
 * defineTool 严格 schema 编译、四个工具的 execute + render 全链路（真实 tshark）。
 *
 * 用法：node scripts/dsh-runtime-smoke.mjs
 */
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const home = process.env.HOME;
// 与 DSH 宿主相同的解析起点：从 HOME 的 node_modules 取真实运行时
const realCordis = require.resolve("@deepseek-ai/cordis", { paths: [home] });
const realSchemastery = require.resolve("@deepseek-ai/schemastery", { paths: [home] });
const realDshTools = require.resolve("@deepseek-ai/dsh-tools", { paths: [home] });
console.log("[runtime] cordis:", require("node:fs").realpathSync(realCordis).replace("/lib/index.js", "").split("node_modules/")[1]);
console.log("[runtime] schemastery + dsh-tools: resolved from ~/node_modules");

const plugin = await import(new URL("../packages/dsh-plugin/dist/index.js", import.meta.url).href);

// 1) Config schema：真实 schemastery 实例化 + 默认值填充
const config = plugin.Config(undefined);
console.log("[config] validated:", JSON.stringify(config));
if (config.autoDownload !== true) throw new Error("Config default autoDownload should be true");
const config2 = plugin.Config({ autoDownload: false, tsharkPath: "/usr/local/bin/tshark" });
console.log("[config] user values:", JSON.stringify(config2));

// 2) apply()：模拟 cordis loader 的调用（inject: ['tools'] 由宿主保证）
const registered = [];
const ctx = {
  tools: { register: (t) => registered.push(t) },
  effect: () => {},
};
plugin.apply(ctx, config);
const names = registered.map((t) => t.name ?? t?.definition?.name).filter(Boolean);
console.log("[apply] registered tools:", names.join(", "));
if (names.length !== 10) throw new Error(`expected 10 tools, got ${names.length}: ${names}`);

// 3) 直接执行工具（defineTool 的返回对象结构探测 + 调用）
const unwrap = (t) => (t.execute ? t : (t.definition ?? t.tool ?? t));
const open = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_open"));
const overview = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_overview"));
const query = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_query"));
const inspect = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_inspect"));
const evidence = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_evidence"));
const timeseries = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_timeseries"));
const raw = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_raw_query"));
const httpTimeline = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_http_timeline"));
const sqlTool = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_sql"));
const schemaTool = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_schema"));

const render = (tool, args, value) => {
  const out = tool.output?.render ?? tool?.definition?.output?.render;
  return out ? out(args, value).map((c) => c.text).join("\n") : "(no render)";
};

const fixture = path.resolve("fixtures/web-session.pcap");

console.log("\n=== traffic_open ===");
const openRes = await open.execute({ path: fixture });
if (openRes.error) throw new Error(`traffic_open failed: ${openRes.error}`);
const captureId = openRes.capture.capture_id;
console.log(render(open, { path: fixture }, openRes));

console.log("\n=== traffic_overview ===");
const ovRes = await overview.execute({ capture_id: captureId });
if (ovRes.error) throw new Error(`traffic_overview failed: ${ovRes.error}`);
console.log(render(overview, { capture_id: captureId }, ovRes).slice(0, 600));

console.log("\n=== traffic_query (conversations with retransmissions) ===");
const qRes = await query.execute({
  capture_id: captureId,
  query: {
    scope: "conversation",
    where: [{ field: "retransmission_count", op: "gt", value: 0 }],
    order_by: [{ field: "retransmission_count", direction: "desc" }],
    select: ["conversation_id", "retransmission_count", "tcp_handshake_ms", "tls_handshake_ms"],
  },
});
if (qRes.error) throw new Error(`traffic_query failed: ${qRes.error}`);
console.log(render(query, { capture_id: captureId, query: {} }, qRes));

console.log("\n=== traffic_inspect (conv:tcp:0) ===");
const insRes = await inspect.execute({ capture_id: captureId, conversation_id: "conv:tcp:0" });
if (insRes.error) throw new Error(`traffic_inspect failed: ${insRes.error}`);
console.log(render(inspect, { capture_id: captureId, conversation_id: "conv:tcp:0" }, insRes));

console.log("\n=== traffic_query (event drill-down, 错误路径验证) ===");
const badRes = await query.execute({
  capture_id: captureId,
  query: { scope: "conversation", where: [{ field: "tcp.stream", op: "eq", value: 1 }] },
});
console.log(render(query, { capture_id: captureId, query: {} }, badRes).slice(0, 300));


console.log("\n=== traffic_evidence (retransmission frames) ===");
const evRes = await evidence.execute({ capture_id: captureId, frames: [8, 11, 14] });
if (evRes.error) throw new Error(`traffic_evidence failed: ${evRes.error}`);
console.log(render(evidence, {}, evRes).slice(0, 500));

console.log("\n=== traffic_timeseries (bytes, conv:tcp:0) ===");
const tsRes = await timeseries.execute({ capture_id: captureId, conversation_id: "conv:tcp:0", metric: "bytes", bin_ms: 100 });
if (tsRes.error) throw new Error(`traffic_timeseries failed: ${tsRes.error}`);
console.log(render(timeseries, {}, tsRes).slice(0, 400));

console.log("\n=== traffic_raw_query (escape hatch) ===");
const rawRes = await raw.execute({ capture_id: captureId, display_filter: "dns.flags.rcode==3", fields: ["dns.qry.name", "dns.flags.rcode"] });
if (rawRes.error) throw new Error(`traffic_raw_query failed: ${rawRes.error}`);
console.log(render(raw, {}, rawRes).slice(0, 300));

console.log("\n=== traffic_http_timeline (edge-cases HTTP) ===");
{
  // 打开第二个 capture（edge-cases.pcap 含 HTTP 事务）
  const open2 = unwrap(registered.find((t) => (t.name ?? t?.definition?.name) === "traffic_open"));
  const r2 = await open2.execute({ path: "fixtures/edge-cases.pcap" });
  if (r2.error) throw new Error(`open2 failed: ${r2.error}`);
  const tl = await httpTimeline.execute({ capture_id: r2.capture.capture_id });
  if (tl.error) throw new Error(`http_timeline failed: ${tl.error}`);
  console.log(render(httpTimeline, {}, tl).slice(0, 400));
}

console.log("\n=== traffic_sql + traffic_schema (S1, duckdb in-process) ===");
{
  const sch = await schemaTool.execute({ capture_id: captureId });
  if (sch.error) throw new Error(`traffic_schema failed: ${sch.error}`);
  console.log(render(schemaTool, {}, sch).slice(0, 300));
  const r = await sqlTool.execute({ capture_id: captureId, sql: "SELECT conversation_id, retransmission_count FROM conversations ORDER BY retransmission_count DESC LIMIT 2" });
  if (r.error) throw new Error(`traffic_sql failed: ${r.error}`);
  console.log(render(sqlTool, {}, r).slice(0, 300));
  const bad = await sqlTool.execute({ capture_id: captureId, sql: "SELECT * FROM read_csv('/etc/hosts')" });
  console.log("security reject:", render(sqlTool, {}, bad).slice(0, 120));
}

console.log("\nOK — plugin loaded and executed against real DSH runtime libs.");
