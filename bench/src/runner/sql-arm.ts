/**
 * sql-v0.1 工具面（T3）：DuckDB over IR 导出，E2 第三臂。
 *
 * 设计纪律：
 * - D5 裁决取 ①：默认视图过滤为双向（与 AST/IR 一致）——q-web-002 语义唯一解
 * - schema 显式（kimi 教训红线）：全部参数显式 zod schema，禁 z.object({}).passthrough()
 * - 工具 description 带已填示例（示例禁含真实答案/gold 帧号）
 * - 接口税遥测 day one 接入（rawArgs + provider 侧原始参数双侧观测）
 * - 渲染预算与 ast 臂一致（applyRenderBudget 有界表格）
 */
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { Tool } from "@stirrup/stirrup";
import { TrafficSession, renderRows, applyRenderBudget, type SqlResult } from "traffic-core";
import { withTiming } from "./bash-arm.js";
import { paramValidationError } from "./tool-errors.js";
import { buildSystemPrompt } from "./prompts.js";
import type { Arm, ToolCallRecord } from "./types.js";

const sessions = new Map<string, TrafficSession>();
const MAX_SESSIONS = 4;

function getSession(captureId: string): TrafficSession {
  const s = sessions.get(captureId);
  if (!s) throw new Error(`capture '${captureId}' not open. Call traffic_open first.`);
  return s;
}

type ToolResult = { content: string; success: boolean };
const ok = (c: string): ToolResult => ({ content: c, success: true });
const fail = (c: string): ToolResult => ({ content: c, success: false });

async function errText(fn: () => Promise<string>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (e) {
    return fail(`ERROR: ${(e as Error).message}`);
  }
}

function renderSql(r: SqlResult): string {
  const head = `sql: ${r.returned} rows${r.truncated ? " [TRUNCATED]" : ""} (${r.elapsed_ms}ms)`;
  const rows = r.rows.map((row) => r.columns.map((c) => String(row[c] ?? "null")).join("\t"));
  return applyRenderBudget(head, rows, "events carry frame_number; join frame_refs for evidence chains").text;
}

function renderSqlSchema(s: { tables: unknown[]; rowCounts: Record<string, number> }): string {
  const lines: string[] = [];
  for (const t of s.tables as Array<{ name: string; kind: string; description: string; columns: Array<{ name: string; type: string; description: string }> }>) {
    lines.push(`${t.name} (${t.kind}, ${s.rowCounts[t.name] ?? 0} rows) — ${t.description}`);
    for (const c of t.columns) lines.push(`  ${c.name} ${c.type} — ${c.description}`);
    lines.push("");
  }
  return applyRenderBudget("SQL schema (read-only SELECT only):", lines, "").text;
}

export class SqlArm implements Arm {
  readonly name = "sql-v0.1";

  constructor(private readonly captureAbsPath: string) {}

  get systemPrompt(): string {
    return buildSystemPrompt("sql", this.captureAbsPath);
  }

  buildTools(records: ToolCallRecord[]): Array<Tool<any, any>> {
    /* eslint-disable @typescript-eslint/no-explicit-any */

    const openTool: Tool<any, any> = {
      name: "traffic_open",
      description: "Open a pcap/pcapng capture. Returns capture_id used by traffic_sql/traffic_schema.",
      parameters: z.object({
        path: z.string().describe("Absolute path to the .pcap/.pcapng file"),
      }),
      executor: async (params: { path?: string }): Promise<ToolResult> => {
        if (typeof params?.path !== "string" || params.path.trim() === "") {
          return fail(paramValidationError({
            tool: "traffic_open", problem: "path 须为绝对路径", received: params,
            emptyArrivals: ["path"], expectedShape: "path(字符串: 绝对路径)",
          }));
        }
        try {
          if (sessions.size >= MAX_SESSIONS) {
            const oldest = sessions.keys().next().value;
            if (oldest !== undefined) sessions.delete(oldest);
          }
          const session = await TrafficSession.open(params.path, {
            cacheDir: path.join(os.tmpdir(), "bench-sql-arm-cache"),
            autoDownload: false,
          });
          sessions.set(session.capture.capture_id, session);
          return ok(`capture ${session.capture.capture_id}: ${session.capture.packet_count} packets`);
        } catch (e) {
          return fail(`ERROR: ${(e as Error).message}`);
        }
      },
    };

    const sqlTool: Tool<any, any> = {
      name: "traffic_sql",
      description:
        "Run a read-only SQL query (DuckDB) over the capture's tables. " +
        "Tables: conversations (bidirectional only), events (attr flattened), frames, frame_refs (evidence). " +
        'Example: SELECT conversation_id, retransmission_count FROM conversations WHERE retransmission_count > 0 ORDER BY retransmission_count DESC',
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
        sql: z.string().describe("Single SELECT/WITH statement"),
        limit: z.number().optional().describe("Row cap [1,500], default 100"),
      }),
      executor: async (params: { capture_id?: string; sql?: string; limit?: number }): Promise<ToolResult> => {
        if (!params?.capture_id?.trim()) {
          return fail(paramValidationError({
            tool: "traffic_sql", problem: "capture_id 缺失", received: params,
            emptyArrivals: ["capture_id"], expectedShape: "capture_id(字符串), sql(字符串: SELECT 语句)",
          }));
        }
        if (!params?.sql?.trim()) {
          return fail(paramValidationError({
            tool: "traffic_sql", problem: "sql 缺失", received: params,
            emptyArrivals: ["sql"], expectedShape: "capture_id(字符串), sql(字符串: SELECT 语句)",
          }));
        }
        return errText(async () => renderSql(await getSession(params.capture_id!).sqlQuery(params.sql!, { limit: params.limit })));
      },
    };

    const schemaTool: Tool<any, any> = {
      name: "traffic_schema",
      description: "Inspect SQL tables/views: columns, types, null semantics, evidence availability. Read before writing traffic_sql.",
      parameters: z.object({
        capture_id: z.string().describe("capture_id from traffic_open"),
      }),
      executor: async (params: { capture_id?: string }): Promise<ToolResult> => {
        if (!params?.capture_id?.trim()) {
          return fail(paramValidationError({
            tool: "traffic_schema", problem: "capture_id 缺失", received: params,
            emptyArrivals: ["capture_id"], expectedShape: "capture_id(字符串)",
          }));
        }
        return errText(async () => renderSqlSchema(await getSession(params.capture_id!).sqlSchema()));
      },
    };

    return [openTool, sqlTool, schemaTool].map((t) => withTiming(t, records));
    /* eslint-enable @typescript-eslint/no-explicit-any */
  }
}
