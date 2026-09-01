import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { DuckDBInstance } from "@duckdb/node-api";
import { BoundedSql } from "./executor.js";
import { PLUGIN_VERSION } from "../util.js";
import type { Extraction } from "../events/extract.js";
import type { FrameTable } from "../frames.js";

/**
 * S1 物化：JSON 缓存 → Parquet + view（不重跑 tshark）。
 * 产物在 captureDir/sql/，marker 记录版本（plugin+tshark+duck）；命中则复用。
 * 建表/建 view 走内部通道（受控 SQL），用户 SQL 只见 view 且受白名单约束。
 */

/** events.attributes → 宽表列（schema 纪律：常用 attr 拍平零 join） */
const EVENT_ATTRS = [
  "variant", "dup_ack_count", "gap_bytes", "origin", "qname", "rcode_num",
  "version", "cipher", "sni", "cn", "san_dns", "method", "host", "uri",
  "status_code", "resp_time_ms",
];

export interface SqlStoreDeps {
  captureDir: string;
  extraction: Extraction;
  frames: FrameTable;
  tsharkVersion: string;
}

export async function buildSqlStore(deps: SqlStoreDeps): Promise<BoundedSql> {
  const { captureDir, tsharkVersion } = deps;
  const sqlDir = path.join(captureDir, "sql");
  await mkdir(sqlDir, { recursive: true });
  const marker = path.join(sqlDir, "version");
  const versionKey = `${PLUGIN_VERSION}+tshark${tsharkVersion}+duck1.5`;
  let markerOk = false;
  try {
    markerOk = (await readFile(marker, "utf8")).trim() === versionKey;
  } catch {
    markerOk = false;
  }

  const q = (lit: string) => `'${lit.replace(/'/g, "''")}'`;
  const pq = (name: string) => path.join(sqlDir, `${name}.parquet`);
  const eventsJson = path.join(captureDir, "events.json");
  const framesJson = path.join(captureDir, "frames.json");
  const J = `read_json_auto(${q(eventsJson)}, maximum_object_size=104857600)`;

  // streams 是 union struct 的可选键（仅 QUIC 会话有），点路径访问会 Binder Error，
  // 经 from_json + 显式 schema 访问（缺键 → NULL → UNNEST 为空行）
  const STREAM_SCHEMA =
    `'[{"conversation_id":"VARCHAR","stream_id":"BIGINT","stream_direction":"VARCHAR",` +
    `"initiator":"VARCHAR","start_ms":"DOUBLE","duration_ms":"DOUBLE",` +
    `"packets":"BIGINT","bytes":"BIGINT","evidence_frames":"BIGINT[]"}]'`;

  const inst = await DuckDBInstance.create(":memory:");
  const conn = await inst.connect();

  if (!markerOk) {
    // attributes 为 union struct（各事件类型键不同），点路径访问会 Binder Error；
    // 经 to_json → json_extract_string → TRY_CAST 拍平
    const NUMERIC_ATTRS = new Set(["dup_ack_count", "gap_bytes", "rcode_num", "status_code", "resp_time_ms"]);
    const attrSel = EVENT_ATTRS.map(
      (a) =>
        `TRY_CAST(json_extract_string(to_json(e.attributes), '$.${a}') AS ${
          NUMERIC_ATTRS.has(a) ? (a === "rcode_num" || a === "status_code" ? "INTEGER" : "BIGINT") : "VARCHAR"
        }) AS attr_${a}`,
    ).join(", ");
    await conn.run(`COPY (
      SELECT e.event_id, e.conversation_id, e.type, e.time_ms, e.direction, e.detection,
             e.evidence.frame_number AS frame_number, ${attrSel}
      FROM ${J} j, UNNEST(j.events) AS t(e)
    ) TO ${q(pq("events"))} (FORMAT PARQUET)`);

    await conn.run(`COPY (
      SELECT c.conversation_id, c.transport,
             c.initiator.ip AS initiator_ip, c.initiator.port AS initiator_port,
             c.responder.ip AS responder_ip, c.responder.port AS responder_port,
             c.direction_basis, c.start_ms, c.duration_ms,
             c.packets.forward AS packets_forward, c.packets.reverse AS packets_reverse,
             c.bytes.forward AS bytes_forward, c.bytes.reverse AS bytes_reverse,
             c.metrics.retransmission_count, c.metrics.dns_query_count,
             c.metrics.tls_handshake_count, c.metrics.tcp_handshake_ms, c.metrics.tls_handshake_ms,
             c.metrics.rtt_median_ms, c.metrics.rtt_max_ms, c.metrics.throughput_bps,
             c.metrics.missing_segment_count, c.metrics.http_txn_count,
             c.metrics.payload_bytes_forward, c.metrics.payload_bytes_reverse,
             c.metrics.tls_app_bytes, c.metrics.quic_stream_count,
             c.protocol_tags
      FROM ${J} j, UNNEST(j.conversations) AS t(c)
    ) TO ${q(pq("conversations"))} (FORMAT PARQUET)`);

    await conn.run(`COPY (
      SELECT f.frame_number, f.time_ms, f.epoch, f.len, f.transport,
             f.ip_src, f.ip_dst, f.stream_id, f.src_port, f.dst_port,
             f.tcp_seq_raw, f.tcp_ack_raw, f.tcp_len, f.tcp_flags, f.tcp_window,
             f.ack_rtt_ms, f.tls_record_bytes, f.analysis,
             f.http_method, f.http_status, f.dns_qname, f.dns_rcode, f.tls_handshake_type
      FROM read_json_auto(${q(framesJson)}, maximum_object_size=104857600) j, UNNEST(j.frames) AS t(f)
    ) TO ${q(pq("frames"))} (FORMAT PARQUET)`);

    // frame_refs 侧表：events 1:1 + streams evidence_frames 展开（含无 stream 捕获）
    await conn.run(`COPY (
      SELECT 'event' AS owner_type, event_id AS owner_id, frame_number
      FROM read_parquet(${q(pq("events"))})
      UNION ALL
      SELECT 'stream' AS owner_type,
             s.conversation_id || '/stream/' || CAST(s.stream_id AS VARCHAR) AS owner_id,
             fr AS frame_number
      FROM ${J} j, UNNEST(j.conversations) AS t(c),
           UNNEST(from_json(json_extract(to_json(c), '$.streams'), ${STREAM_SCHEMA})) AS t2(s),
           UNNEST(s.evidence_frames) AS t3(fr)
    ) TO ${q(pq("frame_refs"))} (FORMAT PARQUET)`);

    await rm(marker, { force: true });
    await writeFile(marker, versionKey, "utf8");
  }

  // view（内部通道；用户侧 read_parquet 在黑名单内，只能经 view 访问）
  // D5 裁决取 ①（2026-08-28）：conversations 默认视图过滤为双向——与 AST/IR 口径一致
  const setupSqls = [
    `CREATE VIEW conversations AS SELECT * FROM read_parquet(${q(pq("conversations"))}) WHERE packets_forward > 0 AND packets_reverse > 0`,
    `CREATE VIEW events AS SELECT * FROM read_parquet(${q(pq("events"))})`,
    `CREATE VIEW frames AS SELECT * FROM read_parquet(${q(pq("frames"))})`,
    `CREATE VIEW frame_refs AS SELECT * FROM read_parquet(${q(pq("frame_refs"))})`,
    `CREATE VIEW v_streams AS
       SELECT s.conversation_id, s.stream_id, s.stream_direction, s.initiator,
              s.start_ms, s.duration_ms, s.packets, s.bytes
       FROM ${J} j, UNNEST(j.conversations) AS t(c),
            UNNEST(from_json(json_extract(to_json(c), '$.streams'), ${STREAM_SCHEMA})) AS t2(s)`,
    `CREATE VIEW v_http_transactions AS
       WITH reqs AS (
         SELECT conversation_id, attr_method AS method, attr_host AS host, attr_uri AS uri,
                time_ms AS request_time_ms, frame_number AS request_frame,
                row_number() OVER (PARTITION BY conversation_id ORDER BY time_ms) AS rn
         FROM events WHERE type='http_request'
       ), resps AS (
         SELECT conversation_id, attr_status_code AS status_code,
                time_ms AS response_time_ms, frame_number AS response_frame,
                row_number() OVER (PARTITION BY conversation_id ORDER BY time_ms) AS rn
         FROM events WHERE type='http_response'
       )
       SELECT r.conversation_id, r.method, r.host, r.uri, s.status_code,
              r.request_time_ms, s.response_time_ms,
              s.response_time_ms - r.request_time_ms AS resp_time_ms,
              r.request_frame, s.response_frame
       FROM reqs r LEFT JOIN resps s ON s.conversation_id=r.conversation_id AND s.rn=r.rn`,
  ];
  for (const s of setupSqls) await conn.run(s);

  return BoundedSql.adopt(inst, conn);
}

/** marker 失效检测（供 session 在版本变化时清理旧 parquet） */
export async function sqlStoreStale(captureDir: string, tsharkVersion: string): Promise<boolean> {
  try {
    const v = (await readFile(path.join(captureDir, "sql", "version"), "utf8")).trim();
    return v !== `${PLUGIN_VERSION}+tshark${tsharkVersion}+duck1.5`;
  } catch {
    return true;
  }
}

void stat;
