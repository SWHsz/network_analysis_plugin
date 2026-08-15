/**
 * SQL 目录（S1）：注册的表/view 与其文档——traffic_schema 的数据源，
 * 也是表引用白名单（用户 SQL 只允许 FROM/JOIN 目录中的名字）。
 *
 * Schema 设计纪律（RFC §4.4）：宽表、自描述列名、常用问题零 join、
 * 嵌套只在 view 中扁平暴露。
 */
export interface SqlColumnDoc {
  name: string;
  type: string;
  description: string;
  /** null 含义（P3 null≠0 约定的 SQL 侧延续） */
  null_semantics?: string;
}

export interface SqlTableDoc {
  name: string;
  kind: "table" | "view";
  description: string;
  /** 证据获取方式 */
  evidence: "inline frame_number column" | "join frame_refs by owner_id" | "none";
  columns: SqlColumnDoc[];
}

const eventAttrs = (extra: SqlColumnDoc[]): SqlColumnDoc[] => [
  { name: "event_id", type: "VARCHAR", description: "stable id, evt:NNNNNN" },
  { name: "conversation_id", type: "VARCHAR", description: "owning conversation" },
  { name: "type", type: "VARCHAR", description: "event type (tcp_retransmission, dns_query, http_request, tls_certificate, ...)" },
  { name: "time_ms", type: "DOUBLE", description: "milliseconds since capture start" },
  { name: "direction", type: "VARCHAR", description: "initiator_to_responder | responder_to_initiator | unknown" },
  { name: "detection", type: "VARCHAR", description: "tshark heuristic/dissector provenance (observation, not ground truth)" },
  { name: "frame_number", type: "BIGINT", description: "evidence frame in the capture" },
  ...extra,
];

export const SQL_CATALOG: SqlTableDoc[] = [
  {
    name: "conversations",
    kind: "table",
    description:
      "One row per transport conversation (bidirectional session). Wide table: all metrics flattened. " +
      "direction_basis tells how initiator was determined (handshake=observed SYN; port_heuristic=guess for mid-capture; first_packet=fallback).",
    evidence: "none",
    columns: [
      { name: "conversation_id", type: "VARCHAR", description: "e.g. conv:tcp:0" },
      { name: "transport", type: "VARCHAR", description: "tcp | udp" },
      { name: "initiator_ip", type: "VARCHAR", description: "" },
      { name: "initiator_port", type: "INTEGER", description: "" },
      { name: "responder_ip", type: "VARCHAR", description: "" },
      { name: "responder_port", type: "INTEGER", description: "" },
      { name: "direction_basis", type: "VARCHAR", description: "handshake | port_heuristic | first_packet" },
      { name: "start_ms", type: "DOUBLE", description: "" },
      { name: "duration_ms", type: "DOUBLE", description: "" },
      { name: "packets_forward", type: "BIGINT", description: "initiator→responder" },
      { name: "packets_reverse", type: "BIGINT", description: "" },
      { name: "bytes_forward", type: "BIGINT", description: "frame.len incl. headers" },
      { name: "bytes_reverse", type: "BIGINT", description: "" },
      { name: "payload_bytes_forward", type: "BIGINT", description: "Σtcp.len (headerless)" },
      { name: "payload_bytes_reverse", type: "BIGINT", description: "" },
      { name: "tls_app_bytes", type: "BIGINT", description: "Σtls.record.length" },
      { name: "retransmission_count", type: "BIGINT", description: "" },
      { name: "missing_segment_count", type: "BIGINT", description: "" },
      { name: "dup_ack_count", type: "BIGINT", description: "derived: events of type tcp_dup_ack" },
      { name: "http_txn_count", type: "BIGINT", description: "http_request events" },
      { name: "dns_query_count", type: "BIGINT", description: "" },
      { name: "tls_handshake_count", type: "BIGINT", description: "" },
      { name: "rtt_median_ms", type: "DOUBLE", description: "median of tcp.analysis.ack_rtt samples", null_semantics: "null = no RTT sample observed (≠ 0)" },
      { name: "rtt_max_ms", type: "DOUBLE", description: "", null_semantics: "null = no sample" },
      { name: "throughput_bps", type: "DOUBLE", description: "bytes_total*8/duration", null_semantics: "null = duration≤0" },
      { name: "tcp_handshake_ms", type: "DOUBLE", description: "SYN→client ACK", null_semantics: "null = no handshake observed" },
      { name: "tls_handshake_ms", type: "DOUBLE", description: "ClientHello→ServerHello", null_semantics: "null = not observed" },
      { name: "quic_stream_count", type: "BIGINT", description: "QUIC streams with observable stream_id" },
      { name: "protocol_tags", type: "VARCHAR[]", description: "list of observed protocol tags; use list_contains" },
    ],
  },
  {
    name: "events",
    kind: "table",
    description:
      "One row per observed event, with frequently-used attributes flattened as attr_* columns. " +
      "Types: tcp_retransmission, tcp_out_of_order, tcp_dup_ack, tcp_zero_window, tcp_missing_segment, " +
      "dns_query, dns_response, tls_client_hello, tls_server_hello, tls_certificate, http_request, http_response.",
    evidence: "inline frame_number column",
    columns: eventAttrs([
      { name: "attr_variant", type: "VARCHAR", description: "tcp_retransmission: plain | fast | spurious" },
      { name: "attr_dup_ack_count", type: "BIGINT", description: "tcp_dup_ack: index in the dup-ack series" },
      { name: "attr_gap_bytes", type: "BIGINT", description: "tcp_missing_segment: gap vs highest contiguous seq", null_semantics: "null = no prior seq (capture_start)" },
      { name: "attr_origin", type: "VARCHAR", description: "tcp_missing_segment: mid_stream | capture_start" },
      { name: "attr_qname", type: "VARCHAR", description: "dns_*: queried name" },
      { name: "attr_rcode_num", type: "INTEGER", description: "dns_response: 0=NOERROR 3=NXDOMAIN" },
      { name: "attr_version", type: "VARCHAR", description: "tls_*_hello: negotiated/advertised version hex" },
      { name: "attr_cipher", type: "VARCHAR", description: "tls_server_hello: negotiated suite hex" },
      { name: "attr_sni", type: "VARCHAR", description: "tls_client_hello: server name indication" },
      { name: "attr_cn", type: "VARCHAR", description: "tls_certificate: subject CN (TLS≤1.2 only)" },
      { name: "attr_san_dns", type: "VARCHAR", description: "tls_certificate: comma-joined SAN dNSName list" },
      { name: "attr_method", type: "VARCHAR", description: "http_request" },
      { name: "attr_host", type: "VARCHAR", description: "http_request" },
      { name: "attr_uri", type: "VARCHAR", description: "http_request" },
      { name: "attr_status_code", type: "INTEGER", description: "http_response" },
      { name: "attr_resp_time_ms", type: "DOUBLE", description: "http_response: http.time", null_semantics: "null = unpaired" },
    ]),
  },
  {
    name: "frames",
    kind: "table",
    description:
      "One row per captured frame (fixed field set, same source as traffic_evidence). " +
      "analysis is a VARCHAR[] of hit tcp.analysis flags (use list_contains(analysis,'retransmission')).",
    evidence: "inline frame_number column",
    columns: [
      { name: "frame_number", type: "BIGINT", description: "primary evidence key" },
      { name: "time_ms", type: "DOUBLE", description: "" },
      { name: "epoch", type: "DOUBLE", description: "unix seconds" },
      { name: "len", type: "BIGINT", description: "frame.len" },
      { name: "transport", type: "VARCHAR", description: "tcp | udp | null" },
      { name: "ip_src", type: "VARCHAR", description: "" },
      { name: "ip_dst", type: "VARCHAR", description: "" },
      { name: "stream_id", type: "BIGINT", description: "tshark stream index", null_semantics: "null = no stream identity" },
      { name: "src_port", type: "INTEGER", description: "" },
      { name: "dst_port", type: "INTEGER", description: "" },
      { name: "tcp_seq_raw", type: "BIGINT", description: "" },
      { name: "tcp_ack_raw", type: "BIGINT", description: "" },
      { name: "tcp_len", type: "INTEGER", description: "payload bytes in this segment" },
      { name: "tcp_flags", type: "VARCHAR", description: "e.g. [PSH, ACK]" },
      { name: "tcp_window", type: "INTEGER", description: "" },
      { name: "ack_rtt_ms", type: "DOUBLE", description: "tcp.analysis.ack_rtt", null_semantics: "null = heuristic not applicable" },
      { name: "tls_record_bytes", type: "BIGINT", description: "" },
      { name: "analysis", type: "VARCHAR[]", description: "retransmission|fast_retransmission|spurious_retransmission|out_of_order|duplicate_ack|zero_window|lost_segment" },
      { name: "http_method", type: "VARCHAR", description: "" },
      { name: "http_status", type: "INTEGER", description: "" },
      { name: "dns_qname", type: "VARCHAR", description: "" },
      { name: "dns_rcode", type: "INTEGER", description: "" },
      { name: "tls_handshake_type", type: "INTEGER", description: "" },
    ],
  },
  {
    name: "frame_refs",
    kind: "table",
    description:
      "Normalized evidence side table: maps owners (events, quic streams) to frames. " +
      "JOIN on owner_id when you need to drill an aggregate claim down to frames.",
    evidence: "inline frame_number column",
    columns: [
      { name: "owner_type", type: "VARCHAR", description: "event | stream" },
      { name: "owner_id", type: "VARCHAR", description: "event_id, or <conversation_id>/stream/<stream_id>" },
      { name: "frame_number", type: "BIGINT", description: "" },
    ],
  },
  {
    name: "v_streams",
    kind: "view",
    description:
      "QUIC streams flattened (one row per stream). Visibility boundary: stream_id only observable on " +
      "decryptable QUIC frames (Initial/Handshake, or 1-RTT with keylog); packets/bytes are per-frame approximations.",
    evidence: "join frame_refs by owner_id",
    columns: [
      { name: "conversation_id", type: "VARCHAR", description: "" },
      { name: "stream_id", type: "BIGINT", description: "" },
      { name: "stream_direction", type: "VARCHAR", description: "QUIC-layer Bidirectional | Unidirectional" },
      { name: "initiator", type: "VARCHAR", description: "QUIC-layer Client | Server (independent of conversation direction)" },
      { name: "start_ms", type: "DOUBLE", description: "" },
      { name: "duration_ms", type: "DOUBLE", description: "" },
      { name: "packets", type: "BIGINT", description: "frames where this stream_id appeared" },
      { name: "bytes", type: "BIGINT", description: "" },
    ],
  },
  {
    name: "v_http_transactions",
    kind: "view",
    description:
      "HTTP request→response pairing (per conversation, FIFO by time) — the SQL face of traffic_http_timeline. " +
      "Plaintext HTTP only. response_* are null for unmatched requests.",
    evidence: "inline frame_number column",
    columns: [
      { name: "conversation_id", type: "VARCHAR", description: "" },
      { name: "method", type: "VARCHAR", description: "" },
      { name: "host", type: "VARCHAR", description: "" },
      { name: "uri", type: "VARCHAR", description: "" },
      { name: "status_code", type: "INTEGER", description: "", null_semantics: "null = no response observed" },
      { name: "request_time_ms", type: "DOUBLE", description: "" },
      { name: "response_time_ms", type: "DOUBLE", description: "", null_semantics: "null = unmatched" },
      { name: "resp_time_ms", type: "DOUBLE", description: "response minus request time" },
      { name: "request_frame", type: "BIGINT", description: "" },
      { name: "response_frame", type: "BIGINT", description: "" },
    ],
  },
];

/** 表引用白名单（用户 SQL 中 FROM/JOIN 的目标必须在此） */
export const SQL_ALLOWED_TABLES = new Set(SQL_CATALOG.map((t) => t.name));
