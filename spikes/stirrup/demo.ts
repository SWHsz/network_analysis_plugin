#!/usr/bin/env node
/**
 * Stirrup (StirrupJS) 选型 spike demo —— RFC-002 §5.2 v1.1。
 *
 * 验证四件事：
 *  1) 挂载自定义工具：traffic_open / traffic_query（直接 import packages/traffic-core）；
 *  2) 逐次工具调用日志：executor 计时 wrapper + tool:start/complete 事件 + messageHistory 落盘；
 *  3) TS 版 import traffic-core：相对路径 ESM 导入（dist 已构建）；
 *  4) 预算控制（maxTurns / AbortSignal timeout / 输出 token 预算）与缓存恢复（--resume-probe）。
 *
 * LLM：DeepSeek（key 运行时读 ~/.dsh/.credentials.yaml，只存内存、绝不落盘），
 *      经本地记录代理转发 —— 代理捕获每次请求的 system prompt + tools JSON（interfaceTokens 实证）。
 *
 * 用法：
 *   npx tsx demo.ts                # 常规跑（maxTurns=8）
 *   npx tsx demo.ts --resume-probe # maxTurns=1 触发缓存 → resume:true 续跑 → 验证缓存清除
 * 输出固定写 spikes/stirrup/out/{demo,probe}/（重跑覆盖）。
 */
import http from "node:http";
import { existsSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { Agent, SIMPLE_FINISH_TOOL, CacheManager } from "@stirrup/stirrup";
import type { AgentRunResult, Tool } from "@stirrup/stirrup";
import { ChatCompletionsClient } from "@stirrup/stirrup/clients/openai";
import {
  TrafficSession,
  renderEnvelope,
  renderRows,
  applyRenderBudget,
} from "../../packages/traffic-core/dist/index.js";
import type { Capture, TrafficQuery } from "../../packages/traffic-core/dist/index.js";

// 从本文件所在目录向上找仓库根（以 pnpm-workspace.yaml 为标记）
function findRepoRoot(start: string): string {
  let dir = start;
  for (;;) {
    if (existsSync(path.join(dir, "pnpm-workspace.yaml"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`repo root not found above ${start}`);
    dir = parent;
  }
}
const repoRoot = findRepoRoot(path.dirname(fileURLToPath(import.meta.url)));
const fixture = path.join(repoRoot, "fixtures", "web-session.pcap");
const MODEL = "deepseek-v4-flash";
const BUDGET = { maxTurns: 8, maxTokens: 4000, timeoutMs: 180_000 };

// ---------------------------------------------------------------------------
// 凭证（只读内存，绝不写入 out/）
// ---------------------------------------------------------------------------
async function loadDeepseekKey(): Promise<string> {
  const credPath = path.join(os.homedir(), ".dsh", ".credentials.yaml");
  const raw = await readFile(credPath, "utf8");
  const m = raw.match(/^\s*DEEPSEEK_API_KEY:\s*["']?([^"'\r\n]+?)["']?\s*$/m);
  if (!m) throw new Error(`DEEPSEEK_API_KEY not found in ${credPath}`);
  return m[1];
}

// ---------------------------------------------------------------------------
// 记录代理：只转发 POST /v1/chat/completions，捕获实际下发的 system prompt +
// tools JSON（interfaceTokens 的 ground truth）。其余路径一律 404。
// ---------------------------------------------------------------------------
interface InterfaceCapture {
  systemChars: number;
  toolsChars: number;
  estTokens: number; // chars/4 启发式
  systemText: string;
  toolsJson: string;
}
const captures: InterfaceCapture[] = [];

function startRecordingProxy(upstream: string): Promise<{ baseURL: string; close: () => void }> {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
      res.writeHead(404);
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);
    try {
      const json = JSON.parse(body.toString("utf8"));
      const systemMsg = Array.isArray(json.messages)
        ? json.messages.find((m: { role: string }) => m.role === "system")
        : undefined;
      const systemText: string = typeof systemMsg?.content === "string" ? systemMsg.content : "";
      const toolsJson: string = json.tools ? JSON.stringify(json.tools) : "";
      captures.push({
        systemChars: systemText.length,
        toolsChars: toolsJson.length,
        estTokens: Math.ceil((systemText.length + toolsJson.length) / 4),
        systemText,
        toolsJson,
      });
    } catch {
      /* 非 JSON 请求体，跳过记录 */
    }
    const up = await fetch(`${upstream}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: req.headers.accept ?? "application/json",
        authorization: req.headers.authorization ?? "",
      },
      body,
    });
    const respBuf = Buffer.from(await up.arrayBuffer());
    res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
    res.end(respBuf);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ baseURL: `http://127.0.0.1:${port}/v1`, close: () => server.close() });
    });
  });
}

// ---------------------------------------------------------------------------
// 自定义工具：traffic_open / traffic_query（复刻 dsh-plugin 语义与渲染）
// ---------------------------------------------------------------------------
const sessions = new Map<string, TrafficSession>(); // 跨 runOnce 存活（resume-probe 两阶段共用）

function renderCapture(c: Capture): string {
  return (
    `capture ${c.capture_id}: ${c.format}, ${c.packet_count} packets, ${(c.duration_ms / 1000).toFixed(2)}s, ` +
    `${(c.size_bytes / 1048576).toFixed(1)}MB\n` +
    `backend ${JSON.stringify(c.backend)}\n` +
    `next: traffic_query(capture_id="${c.capture_id}", {scope:"conversation",order_by:[{field:"retransmission_count",direction:"desc"}],limit:5})`
  );
}

// traffic_open 的路径面：仅接受绝对路径的 .pcap/.pcapng（与插件工具契约一致）
function validCapturePath(raw: string): string | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const resolved = path.resolve(raw);
  if (!path.isAbsolute(resolved)) return null;
  if (!/\.(pcap|pcapng)$/i.test(resolved)) return null;
  if (resolved.includes("\0")) return null;
  return resolved;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
const openTool: Tool<any, any> = {
  name: "traffic_open",
  description:
    "Open a pcap/pcapng capture and establish its identity (fingerprint, duration, packet count). " +
    "Returns capture_id used by all other traffic_* tools. Does NOT parse packets yet.",
  parameters: z.object({
    path: z.string().describe("Absolute path to the .pcap/.pcapng file"),
  }),
  executor: async (params: { path: string }) => {
    const p = validCapturePath(params?.path);
    if (!p) {
      return { content: "ERROR: path must be an absolute path ending in .pcap or .pcapng", success: false };
    }
    try {
      const session = await TrafficSession.open(p, {
        cacheDir: path.join(os.tmpdir(), "stirrup-spike-cache"),
        autoDownload: false,
      });
      sessions.set(session.capture.capture_id, session);
      return { content: renderCapture(session.capture), success: true };
    } catch (err) {
      return { content: `ERROR: ${(err as Error).message}`, success: false };
    }
  },
};

// traffic_query 接收结构化查询 AST（TrafficQuery），不是 SQL 文本；
// 字段白名单 / AND-only / 投影限制由 traffic-core 查询引擎内部强制。
const QUERY_SCOPES = new Set(["conversation", "event", "frame", "stream"]);
function asTrafficQuery(raw: unknown): TrafficQuery | null {
  if (typeof raw !== "object" || raw === null) return null;
  const q = raw as Record<string, unknown>;
  if (typeof q.scope !== "string" || !QUERY_SCOPES.has(q.scope)) return null;
  if (q.where !== undefined && !Array.isArray(q.where)) return null;
  if (q.select !== undefined && !Array.isArray(q.select)) return null;
  if (q.order_by !== undefined && !Array.isArray(q.order_by)) return null;
  if (q.limit !== undefined && typeof q.limit !== "number") return null;
  if (q.offset !== undefined && typeof q.offset !== "number") return null;
  return raw as TrafficQuery;
}

const queryTool: Tool<any, any> = {
  name: "traffic_query",
  description:
    'Run a bounded query over the Traffic Observation IR. scope: "conversation" | "event". ' +
    "where: conditions ({field,op,value}) combined with AND; ops: eq/ne/gt/gte/lt/lte/in/contains. " +
    "Conversation metrics include retransmission_count, rtt_median_ms, throughput_bps, missing_segment_count, " +
    "http_txn_count, duration_ms, bytes_total... Event fields: type, conversation_id, time_ms, direction, " +
    "frame_number, plus typed attributes like attr.qname/attr.rcode_num/attr.status_code. " +
    "select/order_by/limit/offset supported; default projection is compact.",
  parameters: z.object({
    capture_id: z.string().describe("capture_id from traffic_open"),
    query: z
      .object({})
      .passthrough()
      .describe(
        'Query AST, e.g. {"scope":"conversation","where":[{"field":"retransmission_count","op":"gt","value":0}],' +
          '"order_by":[{"field":"retransmission_count","direction":"desc"}],"limit":20}',
      ),
  }),
  executor: async (params: { capture_id: string; query: unknown }) => {
    const session = sessions.get(params?.capture_id);
    if (!session) {
      return { content: "ERROR: unknown capture_id; call traffic_open first", success: false };
    }
    const ast = asTrafficQuery(params?.query);
    if (!ast) {
      return {
        content:
          'ERROR: query must be an AST object like {"scope":"conversation","where":[...],"order_by":[...],"limit":20}',
        success: false,
      };
    }
    try {
      const runTrafficQuery = session.query.bind(session); // AST 查询引擎，非 SQL 文本拼接
      const { result, audit } = await runTrafficQuery(ast);
      const text = applyRenderBudget(renderEnvelope(result), renderRows(result.items).split("\n"), "").text;
      audit.render_chars = text.length;
      return { content: text, success: true };
    } catch (err) {
      return {
        content:
          `ERROR: ${(err as Error).message}\n` +
          "Fix the query: conditions are AND-only, fields are whitelisted per scope, attr.* fields need a type condition.",
        success: false,
      };
    }
  },
};
/* eslint-enable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------
// 逐次工具调用记录（补 Stirrup 缺的单次耗时；ToolCallRecord 即 RFC-002 §5.1 形态）
// ---------------------------------------------------------------------------
interface ToolCallRecord {
  seq: number;
  name: string;
  args: unknown;
  ok: boolean;
  durationMs: number;
  resultChars: number; // 模型可见字符（traffic_* 工具的渲染文本即返回内容）
  startedAtMs: number;
}

function withTiming(tool: Tool<any, any>, records: ToolCallRecord[]): Tool<any, any> {
  const inner = tool.executor;
  return {
    ...tool,
    executor: async (params: unknown) => {
      const startedAtMs = Date.now();
      const rec: ToolCallRecord = {
        seq: records.length,
        name: tool.name,
        args: params,
        ok: false,
        durationMs: 0,
        resultChars: 0,
        startedAtMs,
      };
      records.push(rec);
      try {
        const out = await inner(params);
        rec.ok = out.success !== false;
        rec.resultChars = typeof out.content === "string" ? out.content.length : JSON.stringify(out.content).length;
        return out;
      } finally {
        rec.durationMs = Date.now() - startedAtMs;
      }
    },
  };
}

// ---------------------------------------------------------------------------
// 一次 agent run（预算控制 + 指标采集）
// ---------------------------------------------------------------------------
interface RunOutcome {
  records: ToolCallRecord[];
  events: unknown[];
  messageHistory: unknown[];
  speedStats: unknown;
  llmCalls: number;
  inputTokens: number;
  outputTokens: number;
  wallMs: number;
  answerRaw: string;
  budgetExhausted: boolean;
  aborted: string | null;
}

let sharedClient: ChatCompletionsClient | null = null;

async function runOnce(label: string, maxTurns: number, resume: boolean, task: string): Promise<RunOutcome> {
  if (!sharedClient) throw new Error("client not initialized");
  const records: ToolCallRecord[] = [];
  const events: unknown[] = [];
  let llmCalls = 0;
  let inputTokens = 0;
  let outputTokens = 0;

  const agent = new Agent({
    client: sharedClient,
    name: `traffic-spike-${label}`,
    maxTurns,
    tools: [withTiming(openTool, records), withTiming(queryTool, records)],
    finishTool: SIMPLE_FINISH_TOOL,
  });

  agent.on("tool:start", (d) => events.push({ t: Date.now(), ev: "tool:start", name: d.name }));
  agent.on("tool:complete", (d) =>
    events.push({ t: Date.now(), ev: "tool:complete", name: d.name, success: d.success, resultChars: d.result.length }),
  );
  agent.on("tool:error", (d) => events.push({ t: Date.now(), ev: "tool:error", name: d.name, error: String(d.error) }));
  agent.on("turn:complete", (d) => {
    llmCalls++;
    inputTokens += d.tokenUsage?.input ?? 0;
    outputTokens += d.tokenUsage?.output ?? 0;
    events.push({ t: Date.now(), ev: "turn:complete", turn: d.turn, input: d.tokenUsage?.input, output: d.tokenUsage?.output });
    // Budget.maxTokens 绕行实现：累计输出 token 超限即 abort（Stirrup 无原生输出预算）
    if (outputTokens > BUDGET.maxTokens) {
      ac.abort(new Error(`output token budget exceeded: ${outputTokens} > ${BUDGET.maxTokens}`));
    }
  });

  // Budget.timeoutMs 绕行实现：AbortController + setTimeout（Stirrup 官方推荐姿势）
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error(`timeout after ${BUDGET.timeoutMs}ms`)), BUDGET.timeoutMs);

  agent.session({ noLogger: true, resume });
  const t0 = Date.now();
  let result: AgentRunResult<any> | null = null;
  let aborted: string | null = null;
  try {
    result = await agent.run(task, { signal: ac.signal });
  } catch (err) {
    aborted = err instanceof Error ? err.message : String(err);
  } finally {
    clearTimeout(timer);
  }
  const wallMs = Date.now() - t0;
  return {
    records,
    events,
    messageHistory: result?.messageHistory ?? [],
    speedStats: result?.speedStats ?? null,
    llmCalls,
    inputTokens,
    outputTokens,
    wallMs,
    answerRaw: (result?.finishParams as { reason?: string } | undefined)?.reason ?? "",
    budgetExhausted: result ? result.finishParams === undefined : true,
    aborted,
  };
}

// ---------------------------------------------------------------------------
// 落盘（每个输出目录一个专用函数：路径全字面量拼接，不接收任何路径参数）
// ---------------------------------------------------------------------------
function transcriptJson(r: RunOutcome): string {
  return JSON.stringify({ records: r.records, events: r.events }, null, 2);
}

function metricsJson(label: string, r: RunOutcome): string {
  return JSON.stringify(
    {
      label,
      budget: BUDGET,
      llmCalls: r.llmCalls,
      inputTokens: r.inputTokens,
      outputTokens: r.outputTokens,
      toolCalls: r.records.length,
      toolRenderChars: r.records.filter((x) => x.name.startsWith("traffic_")).reduce((a, b) => a + b.resultChars, 0),
      wallMs: r.wallMs,
      budgetExhausted: r.budgetExhausted,
      aborted: r.aborted,
      answerRaw: r.answerRaw,
    },
    null,
    2,
  );
}

// runOnce 的最近一次结果：落盘函数从模块状态取数（零参数，无外部数据入口，与 captures 同模式）
let lastRun: RunOutcome | null = null;

async function writeDemoOutputs(): Promise<void> {
  if (!lastRun) throw new Error("writeDemoOutputs: 尚无 runOnce 结果");
  const r = lastRun;
  const dir = path.join(repoRoot, "spikes", "stirrup", "out", "demo");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(r));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(r.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), r.answerRaw);
  await writeFile(path.join(dir, "metrics.json"), metricsJson("demo", r));
}

async function writeProbeAOutputs(): Promise<void> {
  if (!lastRun) throw new Error("writeProbeAOutputs: 尚无 runOnce 结果");
  const r = lastRun;
  const dir = path.join(repoRoot, "spikes", "stirrup", "out", "probe", "phase-a");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(r));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(r.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), r.answerRaw);
  await writeFile(path.join(dir, "metrics.json"), metricsJson("probe-a", r));
}

async function writeProbeBOutputs(): Promise<void> {
  if (!lastRun) throw new Error("writeProbeBOutputs: 尚无 runOnce 结果");
  const r = lastRun;
  const dir = path.join(repoRoot, "spikes", "stirrup", "out", "probe", "phase-b");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "transcript.json"), transcriptJson(r));
  await writeFile(path.join(dir, "messages.json"), JSON.stringify(r.messageHistory, null, 2));
  await writeFile(path.join(dir, "answerRaw.txt"), r.answerRaw);
  await writeFile(path.join(dir, "metrics.json"), metricsJson("probe-b", r));
}

function interfaceJson(): string {
  return JSON.stringify(
    {
      model: MODEL,
      perRequest: captures.map((c) => ({ systemChars: c.systemChars, toolsChars: c.toolsChars, estTokens: c.estTokens })),
      firstSystemText: captures[0].systemText,
      firstToolsJson: JSON.parse(captures[0].toolsJson || "[]"),
    },
    null,
    2,
  );
}

function logInterfacePayload(): void {
  console.log(
    `[spike] interface payload: system=${captures[0].systemChars} chars, tools=${captures[0].toolsChars} chars, estTokens≈${captures[0].estTokens} (chars/4)`,
  );
}

async function writeDemoInterfaceCapture(): Promise<void> {
  if (captures.length === 0) return;
  const dir = path.join(repoRoot, "spikes", "stirrup", "out", "demo");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "interface.json"), interfaceJson());
  logInterfacePayload();
}

async function writeProbeInterfaceCapture(): Promise<void> {
  if (captures.length === 0) return;
  const dir = path.join(repoRoot, "spikes", "stirrup", "out", "probe");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "interface.json"), interfaceJson());
  logInterfacePayload();
}

function printSummary(label: string, r: RunOutcome): void {
  console.log(`\n===== ${label} =====`);
  for (const rec of r.records) {
    console.log(`  [tool] #${rec.seq} ${rec.name} ok=${rec.ok} ${rec.durationMs}ms chars=${rec.resultChars}`);
  }
  console.log(
    `  llmCalls=${r.llmCalls} in=${r.inputTokens} out=${r.outputTokens} wall=${r.wallMs}ms exhausted=${r.budgetExhausted}${r.aborted ? ` aborted(${r.aborted})` : ""}`,
  );
  console.log(`  answerRaw: ${r.answerRaw.slice(0, 200).replace(/\n/g, " ")}`);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const task = [
    "You are analyzing a network packet capture.",
    `First open the capture at ${fixture} with traffic_open.`,
    "Then use traffic_query to find the conversation with the highest retransmission_count, and read its tcp_handshake_ms.",
    "When done, call the finish tool. Its reason must contain exactly one ```json fenced block:",
    '{"conversation_id": "...", "retransmission_count": 0, "tcp_handshake_ms": 0}',
    "Only use traffic_open and traffic_query. Do not read the filesystem.",
  ].join("\n");

  const probe = process.argv.includes("--resume-probe");
  const key = await loadDeepseekKey();
  const proxy = await startRecordingProxy("https://api.deepseek.com");
  sharedClient = new ChatCompletionsClient({ model: MODEL, apiKey: key, baseURL: proxy.baseURL });
  console.log(`[spike] model=${MODEL} via recording proxy ${proxy.baseURL} (upstream api.deepseek.com)`);

  try {
    if (!probe) {
      const r = await runOnce("demo", BUDGET.maxTurns, false, task);
      lastRun = r;
      await writeDemoOutputs();
      printSummary("demo", r);
      await writeDemoInterfaceCapture();
    } else {
      // 缓存探测用 Stirrup 自己的 CacheManager（与 Agent 相同的 key 计算）
      const cache = new CacheManager([{ role: "user", content: task }]);

      // 阶段 A：maxTurns=1 → 预期未完成 → Stirrup 自动写缓存
      const a = await runOnce("probe-a", 1, false, task);
      lastRun = a;
      await writeProbeAOutputs();
      printSummary("probe-a (maxTurns=1)", a);
      const cachedAfterA = await cache.hasCachedState();
      console.log(`[probe] cache dir ${cache.getCacheDir()} hasState=${cachedAfterA}`);

      // 阶段 B：同一 task、resume:true → 从缓存续跑（sessions Map 跨阶段存活）
      const b = await runOnce("probe-b", BUDGET.maxTurns, true, task);
      lastRun = b;
      await writeProbeBOutputs();
      printSummary("probe-b (resume)", b);
      const cachedAfterB = await cache.hasCachedState();
      console.log(`[probe] cache hasState after resume-run (expect false on success): ${cachedAfterB}`);
      await writeProbeInterfaceCapture();
    }
  } finally {
    proxy.close();
  }
}

main().catch((err) => {
  console.error("[spike] fatal:", err);
  process.exitCode = 1;
});
