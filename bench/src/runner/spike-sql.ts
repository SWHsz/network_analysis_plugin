/**
 * DuckDB spike（E2 SQL 臂前置，P7 允许的半天级验证项）：
 * 验证 traffic-core 的有界 SQL 栈在 bench 进程内可用——
 *   1) TrafficSession.sqlSchema() 列出注册表；
 *   2) 三条代表性查询（聚合/排序/事件过滤）；
 *   3) 口径互证：SQL conversations.bytes_total vs gt conversations[].bytes
 *     （裁决 #3：wire bytes 含重传帧，两侧应逐会话相等）。
 * 运行：tsx src/runner/spike-sql.ts；只读 stdout 输出，不写盘。
 */
import os from "node:os";
import path from "node:path";
import { REPO_ROOT } from "../paths.js";
import { loadGroundTruth, loadQuestionByName } from "../scorer/question.js";
import { TrafficSession } from "traffic-core";

async function main(): Promise<number> {
  const q = loadQuestionByName("q-web-001-retrans-count.json");
  const gt = loadGroundTruth(q);
  const session = await TrafficSession.open(path.join(REPO_ROOT, "fixtures", "web-session.pcap"), {
    cacheDir: path.join(os.tmpdir(), "bench-sql-spike-cache"),
    autoDownload: false,
  });

  console.log("== traffic_schema ==");
  const schema = await session.sqlSchema();
  for (const t of schema.tables as Array<{ name: string; kind: string; rowCounts?: number }>) {
    console.log(`  ${t.name} (${t.kind})`);
  }

  const runSql = async (label: string, sql: string): Promise<void> => {
    const r = await session.sqlQuery(sql);
    console.log(`\n== ${label} ==\n${r.rows.map((row) => JSON.stringify(row)).join("\n") || "(0 rows)"}`);
  };

  await runSql(
    "conversations 按字节降序（SQL 表无合成列 bytes_total，用 forward+reverse）",
    "SELECT conversation_id, initiator_ip, responder_ip, bytes_forward + bytes_reverse AS bytes_wire, retransmission_count FROM conversations ORDER BY bytes_wire DESC",
  );
  await runSql(
    "重传事件",
    "SELECT event_id, conversation_id, frame_number, direction FROM events WHERE type = 'tcp_retransmission' ORDER BY frame_number",
  );

  // 口径互证：SQL bytes_forward+reverse vs gt bytes（端点对双向匹配，wire 含重传）
  const r = await session.sqlQuery("SELECT conversation_id, initiator_ip, initiator_port, responder_ip, responder_port, bytes_forward + bytes_reverse AS bytes_wire FROM conversations");
  const gtByEndpoints = new Map<string, unknown>();
  for (const c of gt.facts.conversations as Array<Record<string, unknown>>) {
    gtByEndpoints.set(`${c.src}:${c.sport}>${c.dst}:${c.dport}`, c.bytes);
  }
  let mismatches = 0;
  let extras = 0;
  console.log("\n== 口径互证：SQL bytes_forward+reverse vs gt bytes（wire，含重传） ==");
  for (const row of r.rows as Array<Record<string, unknown>>) {
    const fwd = `${row.initiator_ip}:${row.initiator_port}>${row.responder_ip}:${row.responder_port}`;
    const rev = `${row.responder_ip}:${row.responder_port}>${row.initiator_ip}:${row.initiator_port}`;
    const expected = gtByEndpoints.get(fwd) ?? gtByEndpoints.get(rev);
    if (expected === undefined) {
      // 层间语义差异：SQL 表把单向 UDP（gt 的 noise/orphan 帧）也列为会话，
      // AST/IR 层与 gt 只认双向会话——E2 SQL 臂的已知陷阱（q-web-002 known_bad 即此形态）
      extras++;
      console.log(`  ${row.conversation_id}: sql=${row.bytes_wire} gt=无此会话（层间语义差异：单向流）`);
      continue;
    }
    const sqlNum = Number(row.bytes_wire);
    const ok = expected === sqlNum;
    if (!ok) mismatches++;
    console.log(`  ${row.conversation_id}: sql=${sqlNum} gt=${expected} ${ok ? "OK" : "MISMATCH"}`);
  }
  console.log(
    mismatches === 0
      ? `\nSPIKE-PASS：SQL 栈可用；共同会话字节口径与 gt 一致；另 ${extras} 条单向 UDP 为 SQL 层可见的会话语义差异`
      : `\nSPIKE-FAIL：${mismatches} 处口径不一致`,
  );
  return mismatches === 0 ? 0 : 1;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("[spike-sql] fatal:", err);
    process.exitCode = 1;
  },
);
