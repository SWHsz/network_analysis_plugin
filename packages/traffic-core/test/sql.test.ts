import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { validateUserSql, SqlSecurityError } from "../src/sql/executor.js";
import { runBinary } from "../src/backend/spawn.js";

const FIXTURE = path.resolve(__dirname, "../../../fixtures/edge-cases.pcap");
const QUIC = path.resolve(__dirname, "../../../fixtures/quic-sample.pcapng");

const skip = !(await (async () => {
  try {
    await runBinary("tshark", ["--version"], { timeoutMs: 10_000 });
    return true;
  } catch {
    return false;
  }
})());

const cacheDirs: string[] = [];

describe("S1: Bounded SQL (DuckDB/Parquet, pure addition)", { skip: skip || undefined }, () => {
  let session: TrafficSession;
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-s1-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("wide conversations table answers common questions with zero joins", async () => {
    const r = await session.sqlQuery(
      "SELECT conversation_id, retransmission_count, rtt_median_ms, throughput_bps FROM conversations ORDER BY retransmission_count DESC",
    );
    expect(r.rows[0]!.conversation_id).toBe("conv:tcp:1");
    expect(Number(r.rows[0]!.retransmission_count)).toBeGreaterThanOrEqual(1);
  });

  it("events attrs flattened; http transaction view pairs correctly", async () => {
    const r = await session.sqlQuery(
      "SELECT method, uri, status_code, resp_time_ms, request_frame, response_frame FROM v_http_transactions",
    );
    // duckdb JSON 序列化可能将数值字符串化，语义断言用 Number 比较
    expect(String(r.rows[0]!.method)).toBe("GET");
    expect(String(r.rows[0]!.uri)).toBe("/data");
    expect(Number(r.rows[0]!.status_code)).toBe(200);
    expect(Number(r.rows[0]!.request_frame)).toBe(4);
    expect(Number(r.rows[0]!.response_frame)).toBe(7);
  });

  it("frame_refs side table maps event owners to frames", async () => {
    const r = await session.sqlQuery(
      "SELECT owner_id, frame_number FROM frame_refs WHERE owner_type='event' ORDER BY frame_number LIMIT 3",
    );
    expect(r.rows.length).toBe(3);
    expect(r.rows.every((x) => x.owner_id.startsWith("evt:"))).toBe(true);
  });

  it("row budget enforced with envelope", async () => {
    const r = await session.sqlQuery("SELECT frame_number FROM frames", { limit: 3 });
    expect(r.returned).toBe(3);
    expect(r.truncated).toBe(true);
  });

  it("sql schema exposes catalog with row counts", async () => {
    const sch = await session.sqlSchema();
    expect(Object.keys(sch.rowCounts)).toContain("v_http_transactions");
    expect(sch.rowCounts.events).toBeGreaterThan(0);
  });

  it("security: file/system statements and table paths rejected (S1 exit criterion)", async () => {
    const cases = [
      "SELECT * FROM read_csv('/etc/hosts')",
      "SELECT * FROM read_parquet('/tmp/x.parquet')",
      "COPY events TO '/tmp/x.parquet'",
      "CREATE VIEW evil AS SELECT 1",
      "INSERT INTO events VALUES ('x')",
      "SELECT 1; DROP VIEW events",
      "SELECT * FROM 'file.parquet'",
      "SELECT * FROM nonexistent_table",
      "PRAGMA memory_limit='1GB'",
      "ATTACH '/tmp/x.db' AS evil",
    ];
    for (const sql of cases) {
      await expect(session.sqlQuery(sql), sql).rejects.toThrow(SqlSecurityError);
    }
  });

  it("security: validateUserSql unit-level rejections", () => {
    expect(() => validateUserSql("WITH t AS (SELECT 1) SELECT * FROM t")).not.toThrow();
    expect(() => validateUserSql("-- comment\nSELECT read_blob('/etc/passwd')")).toThrow(SqlSecurityError);
    // 常见误写：列名撞黑名单词（如 description 含 'set'）不应误伤 —— 词边界保证
    expect(() => validateUserSql("SELECT 1 AS resettable")).not.toThrow();
  });

  it("parquet store is cached (marker) and reused across sessions", async () => {
    const files = await import("node:fs/promises").then((m) => m.readdir(path.join(cacheDirs[0]!, "captures", session.capture.capture_id, "sql")));
    expect(files).toContain("events.parquet");
    expect(files).toContain("version");
  });
});

describe("S1: QUIC capture through SQL stack", { skip: skip || undefined }, () => {
  it("v_streams exposes flattened quic streams; frame_refs carries stream evidence", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-s1-quic-"));
    cacheDirs.push(dir);
    const s = await TrafficSession.open(QUIC, { cacheDir: dir, autoDownload: false });
    const r = await s.sqlQuery(
      "SELECT stream_id, bytes FROM v_streams ORDER BY bytes DESC LIMIT 2",
    );
    expect(Number(r.rows[0]!.bytes)).toBeGreaterThan(100000);
    const refs = await s.sqlQuery(
      "SELECT count(*) AS n FROM frame_refs WHERE owner_type='stream'",
    );
    expect(Number(refs.rows[0]!.n)).toBeGreaterThan(0);
  });
});
