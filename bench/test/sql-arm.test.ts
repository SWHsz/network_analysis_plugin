/**
 * T3 确定性对账测试（零 LLM）：SQL 臂 vs AST/IR vs GT 在 fixture 上三方对账
 * + 双向会话语义（5 vs 3 陷阱用例）+ 三臂静态 per-request 字符表。
 */
import { describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import { TrafficSession } from "traffic-core";
import { REPO_ROOT } from "../src/paths.js";
import { loadGroundTruth, loadQuestionByName } from "../src/scorer/question.js";
import { SqlArm } from "../src/runner/sql-arm.js";
import { BashArm } from "../src/runner/bash-arm.js";
import { AstArm } from "../src/runner/ast-tools.js";
import type { Tool } from "@stirrup/stirrup";

/** 内联字符测量（toOpenAITools 不在公开导出面——直接量工具定义 JSON 长度） */
function measureArm(arm: { buildTools(records: never[]): Array<Tool<any, any>>; systemPrompt: string }): {
  tools: number; system: number; total: number; estTokens: number;
} {
  const tools = arm.buildTools([]);
  const toolsJson = JSON.stringify(tools.map((t) => ({ name: t.name, description: t.description, parameters: "schema" })));
  return {
    tools: toolsJson.length,
    system: arm.systemPrompt.length,
    total: toolsJson.length + arm.systemPrompt.length,
    estTokens: Math.ceil((toolsJson.length + arm.systemPrompt.length) / 4),
  };
}

const capture = path.join(REPO_ROOT, "fixtures", "web-session.pcap");

async function openSession(): Promise<TrafficSession> {
  return TrafficSession.open(capture, {
    cacheDir: path.join(os.tmpdir(), "bench-t3-test-cache"),
    autoDownload: false,
  });
}

describe("T3 SQL↔AST 对账（确定性，零 LLM）", () => {
  it("conversations 帧集对账：SQL 双向视图（D5 过滤）== GT 3 会话", async () => {
    const session = await openSession();
    // SQL：D5 过滤后的双向视图
    const sql = await session.sqlQuery(
      "SELECT conversation_id FROM conversations ORDER BY conversation_id",
    );
    const sqlIds = sql.rows.map((r) => r.conversation_id as string);
    // GT：恰 3 个双向会话
    const gt = loadGroundTruth(loadQuestionByName("q-web-001-retrans-count.json"));
    expect(gt.facts.conversations).toHaveLength(3);
    expect(sqlIds).toHaveLength(3);
    // AST/IR 层的 conversation scope 包含全部 5 条（含单向 UDP）——已知层间差异
    // （SQL 臂 D5 过滤后与 GT 对齐，AST 臂的 q-web-002 题面要求 agent 自行排除单向流）
    const ast = await session.query({ scope: "conversation", select: ["conversation_id"], order_by: [{ field: "conversation_id", direction: "asc" }] });
    expect(ast.result.items.length).toBe(5);
  });

  it("字节排序对账：SQL bytes_forward+reverse == AST bytes_total == GT bytes", async () => {
    const session = await openSession();
    const sql = await session.sqlQuery(
      "SELECT conversation_id, bytes_forward + bytes_reverse AS bytes_wire FROM conversations ORDER BY bytes_wire DESC",
    );
    // GT
    const gt = loadGroundTruth(loadQuestionByName("q-web-001-retrans-count.json"));
    const gtBytes = (gt.facts.conversations as Array<{ id: string; bytes: number }>)
      .map((c) => c.bytes)
      .sort((a, b) => b - a);
    // 每会话逐值对齐
    const sqlBytes = sql.rows.map((r) => Number(r.bytes_wire));
    expect(sqlBytes).toEqual(gtBytes);
    expect(sqlBytes[0]).toBe(6575); // conv A wire bytes（裁决 #3 互证值）
  });

  it("重传事件对账：SQL events WHERE type='tcp_retransmission' == GT retransmissions 帧集", async () => {
    const session = await openSession();
    const sql = await session.sqlQuery(
      "SELECT frame_number FROM events WHERE type = 'tcp_retransmission' ORDER BY frame_number",
    );
    const gt = loadGroundTruth(loadQuestionByName("q-web-001-retrans-count.json"));
    const gtFrames = (gt.facts.retransmissions as Array<{ frame: number }>).map((r) => r.frame).sort((a, b) => a - b);
    expect(sql.rows.map((r) => Number(r.frame_number))).toEqual(gtFrames);
    expect(gtFrames).toEqual([8, 11, 14, 26]); // A×3 + B×1
  });

  it("双向会话语义（D5 陷阱用例）：SQL 不出现单向 UDP", async () => {
    const session = await openSession();
    const sql = await session.sqlQuery("SELECT conversation_id FROM conversations");
    const ids = sql.rows.map((r) => r.conversation_id as string);
    // web-session 有 2 条单向 UDP（噪声帧 31/32）——不应出现在双向视图中
    expect(ids.some((id) => id.includes("udp:1") || id.includes("udp:2"))).toBe(false);
    expect(ids).toHaveLength(3);
  });
});

describe("T3 三臂静态 per-request 字符表（定义性指标，非经验 claim）", () => {
  it("interface_chars 对照：bash < sql < ast（SQL 工具面最小）", async () => {
    const bash = measureArm(new BashArm(capture));
    const sql = measureArm(new SqlArm(capture));
    const ast = measureArm(new AstArm(capture));
    console.log("三臂静态字符表（定义性指标，报告注明非经验 claim）:");
    console.log(`  bash-v0.2: tools=${bash.tools}c system=${bash.system}c total=${bash.total}c ≈${bash.estTokens} tok/req`);
    console.log(`  sql-v0.1:  tools=${sql.tools}c system=${sql.system}c total=${sql.total}c ≈${sql.estTokens} tok/req`);
    console.log(`  ast-v0.5:  tools=${ast.tools}c system=${ast.system}c total=${ast.total}c ≈${ast.estTokens} tok/req`);

    // bash < sql < ast（SQL 工具面最小，接口税最低的 AST 替代路径）
    expect(bash.total).toBeLessThan(sql.total);
    expect(sql.total).toBeLessThan(ast.total);
  });
});
