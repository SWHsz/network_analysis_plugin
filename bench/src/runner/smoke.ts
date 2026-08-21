/**
 * 工具面冒烟（无 LLM）：直接调用 AstArm 八工具的 executor，验证接线与渲染，
 * 在花真金白银跑 agent 前抓低级错误。用法：tsx src/runner/smoke.ts
 * （bash 臂的 shell 工具是薄封装：argv 形式 spawn + 输出上限；tshark 可用性由
 *   环境自检覆盖，不在此处执行命令。）
 */
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { AstArm } from "./ast-tools.js";

async function main(): Promise<void> {
  const capture = path.join(REPO_ROOT, "fixtures", "web-session.pcap");
  const records = [];
  const astArm = new AstArm(capture);
  const tools = new Map(astArm.buildTools(records).map((t) => [t.name, t]));
  const call = async (name: string, params: unknown): Promise<unknown> => {
    const t = tools.get(name);
    if (!t) {
      console.log(`[${name}] MISSING`);
      return null;
    }
    const out = await t.executor(params as never);
    console.log(`[${name}] success=${out.success}\n${String(out.content).slice(0, 260)}`);
    return out.content;
  };

  await call("traffic_open", { path: "/nonexistent.pcap" }); // 先验证报错路径
  const openOut = await call("traffic_open", { path: capture });
  const captureId = extractCaptureId(openOut);
  console.log(`[smoke] capture_id=${captureId}`);
  await call("traffic_overview", { capture_id: captureId });
  await call("traffic_query", {
    capture_id: captureId,
    query: { scope: "conversation", where: [{ field: "retransmission_count", op: "gt", value: 0 }], order_by: [{ field: "retransmission_count", direction: "desc" }], limit: 5 },
  });
  await call("traffic_inspect", { capture_id: captureId, conversation_id: "conv:tcp:0" });
  await call("traffic_evidence", { capture_id: captureId, frames: [8, 11, 14] });
  await call("traffic_timeseries", { capture_id: captureId, conversation_id: "conv:tcp:0", metric: "bytes", bin_ms: 100 });
  await call("traffic_http_timeline", { capture_id: captureId });
  await call("traffic_raw_query", { capture_id: captureId, fields: ["dns.resp.ttl"], display_filter: "dns.flags.response==1" });

  console.log(`\n[smoke] ast records=${records.length}`);
}

function extractCaptureId(content: unknown): string {
  const text = String(content ?? "");
  // 渲染首行形如 "capture cap_xxx: pcap, ..."
  const marker = "capture ";
  const start = text.indexOf(marker);
  if (start < 0) return "";
  const rest = text.slice(start + marker.length);
  const end = rest.indexOf(":");
  return end < 0 ? "" : rest.slice(0, end);
}

main().then(
  () => {},
  (err) => {
    console.error("[smoke] fatal:", err);
    process.exitCode = 1;
  },
);
