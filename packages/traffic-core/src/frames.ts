import { PLUGIN_VERSION } from "./util.js";

/**
 * FrameTable —— per-frame 原始字段表（traffic_evidence / traffic_timeseries 的数据源）。
 *
 * 与 events.json 的区别：事件抽取只保留「发生了什么」；本表保留每帧的
 * 原始协议字段（固定字段集），供模型复核 claim 与计算时序聚合。
 * 字段集固定 → 确定性可检验（provenance 记录 tshark 版本）。
 */
export interface FrameRecord {
  frame_number: number;
  /** 相对捕获起点毫秒 */
  time_ms: number;
  /** epoch 秒 */
  epoch: number;
  len: number;
  transport: "tcp" | "udp" | null;
  ip_src: string | null;
  ip_dst: string | null;
  /** 流编号（与 Conversation IR 的 conv:{transport}:{stream} 对应） */
  stream_id: number | null;
  src_port: number | null;
  dst_port: number | null;
  tcp_seq_raw: number | null;
  tcp_ack_raw: number | null;
  tcp_len: number | null;
  /** tcp.flags.str，如 [ACK],[PSH,ACK] */
  tcp_flags: string | null;
  tcp_window: number | null;
  /** tcp.analysis.ack_rtt（毫秒） */
  ack_rtt_ms: number | null;
  /** 命中的 tcp.analysis 标志列表 */
  analysis: string[];
  dns_id: number | null;
  dns_qname: string | null;
  dns_response: boolean | null;
  dns_rcode: number | null;
  tls_handshake_type: number | null;
  /** 该帧 TLS 记录层字节（多 record 求和） */
  tls_record_bytes: number | null;
  http_method: string | null;
  http_host: string | null;
  http_uri: string | null;
  http_status: number | null;
  http_content_type: string | null;
  /** http.time（毫秒） */
  http_time_ms: number | null;
}

export interface FrameTable {
  plugin_version: string;
  tshark_version: string;
  built_at: string;
  first_epoch: number;
  frame_count: number;
  frames: FrameRecord[];
}

/** 固定字段集（traffic_evidence 的确定性边界；变更需 bump plugin_version） */
export const FRAMES_FIELDS = [
  "frame.number",
  "frame.time_epoch",
  "frame.len",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "tcp.stream",
  "udp.stream",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.seq_raw",
  "tcp.ack_raw",
  "tcp.len",
  "tcp.flags.str",
  "tcp.window_size",
  "tcp.analysis.ack_rtt",
  "tcp.analysis.retransmission",
  "tcp.analysis.fast_retransmission",
  "tcp.analysis.spurious_retransmission",
  "tcp.analysis.out_of_order",
  "tcp.analysis.duplicate_ack",
  "tcp.analysis.zero_window",
  "tcp.analysis.lost_segment",
  "dns.id",
  "dns.qry.name",
  "dns.flags.response",
  "dns.flags.rcode",
  "tls.handshake.type",
  "tls.record.length",
  "http.request.method",
  "http.host",
  "http.request.uri",
  "http.response.code",
  "http.content_type",
  "http.time",
] as const;

const COL: Readonly<Record<string, number>> = Object.fromEntries(
  FRAMES_FIELDS.map((f, i) => [f, i]),
);

const TRUTHY = new Set(["1", "true", "True", "TRUE"]);
function truthyAny(value: string | undefined): boolean {
  if (!value) return false;
  return value.split(",").some((tok) => TRUTHY.has(tok));
}
function num(v: string | undefined): number | null {
  return v ? Number(v) : null;
}
function str(v: string | undefined): string | null {
  return v ? v.split(",")[0]! : null;
}

/** 单行 → FrameRecord；无法解析返回 null */
export function parseFrameLine(line: string, firstEpoch: number): FrameRecord | null {
  const cols = line.split("\t");
  if (cols.length < FRAMES_FIELDS.length) return null;
  const g = (name: string): string => cols[COL[name]!] ?? "";

  const frameNumber = Number(g("frame.number"));
  const epoch = Number(g("frame.time_epoch"));
  if (!frameNumber || !Number.isFinite(epoch)) return null;

  const analysis: string[] = [];
  if (truthyAny(g("tcp.analysis.retransmission"))) analysis.push("retransmission");
  if (truthyAny(g("tcp.analysis.fast_retransmission"))) analysis.push("fast_retransmission");
  if (truthyAny(g("tcp.analysis.spurious_retransmission"))) analysis.push("spurious_retransmission");
  if (truthyAny(g("tcp.analysis.out_of_order"))) analysis.push("out_of_order");
  if (truthyAny(g("tcp.analysis.duplicate_ack"))) analysis.push("duplicate_ack");
  if (truthyAny(g("tcp.analysis.zero_window"))) analysis.push("zero_window");
  if (truthyAny(g("tcp.analysis.lost_segment"))) analysis.push("lost_segment");

  const tcpStream = g("tcp.stream");
  const udpStream = g("udp.stream");
  const tcpPresent = !!tcpStream;
  const udpPresent = !!udpStream;
  const ackRtt = g("tcp.analysis.ack_rtt");

  return {
    frame_number: frameNumber,
    time_ms: Number(((epoch - firstEpoch) * 1000).toFixed(3)),
    epoch,
    len: Number(g("frame.len")) || 0,
    transport: tcpPresent ? "tcp" : udpPresent ? "udp" : null,
    ip_src: str(g("ip.src")) ?? str(g("ipv6.src")),
    ip_dst: str(g("ip.dst")) ?? str(g("ipv6.dst")),
    stream_id: num(tcpStream || udpStream),
    src_port: num(g("tcp.srcport") || g("udp.srcport")),
    dst_port: num(g("tcp.dstport") || g("udp.dstport")),
    tcp_seq_raw: num(g("tcp.seq_raw")),
    tcp_ack_raw: num(g("tcp.ack_raw")),
    tcp_len: num(g("tcp.len")),
    tcp_flags: str(g("tcp.flags.str")),
    tcp_window: num(g("tcp.window_size")),
    ack_rtt_ms: ackRtt ? Number((Number(ackRtt) * 1000).toFixed(3)) : null,
    analysis,
    dns_id: g("dns.id") ? parseInt(g("dns.id"), 16) : null,
    dns_qname: str(g("dns.qry.name")),
    dns_response: g("dns.flags.response") ? truthyAny(g("dns.flags.response")) : null,
    dns_rcode: num(g("dns.flags.rcode")),
    tls_handshake_type: num(g("tls.handshake.type")),
    tls_record_bytes: g("tls.record.length")
      ? g("tls.record.length").split(",").reduce((acc, part) => acc + (Number(part) || 0), 0)
      : null,
    http_method: str(g("http.request.method")),
    http_host: str(g("http.host")),
    http_uri: str(g("http.request.uri")),
    http_status: num(g("http.response.code")),
    http_content_type: str(g("http.content_type")),
    http_time_ms: g("http.time") ? Number((Number(g("http.time")) * 1000).toFixed(3)) : null,
  };
}

/** 两遍式构建：先收集 first_epoch，再生成记录（time_ms 需要全局起点） */
export class FrameTableBuilder {
  private epochs: number[] = [];
  private lines: string[] = [];

  feed(line: string): void {
    this.lines.push(line);
    const cols = line.split("\t");
    const epoch = Number(cols[COL["frame.time_epoch"]!]);
    if (Number.isFinite(epoch)) this.epochs.push(epoch);
  }

  finish(tsharkVersion: string): FrameTable {
    const firstEpoch = this.epochs.length ? Math.min(...this.epochs) : 0;
    const frames: FrameRecord[] = [];
    for (const line of this.lines) {
      const rec = parseFrameLine(line, firstEpoch);
      if (rec) frames.push(rec);
    }
    frames.sort((a, b) => a.frame_number - b.frame_number);
    return {
      plugin_version: PLUGIN_VERSION,
      tshark_version: tsharkVersion,
      built_at: new Date().toISOString(),
      first_epoch: firstEpoch,
      frame_count: frames.length,
      frames,
    };
  }
}

/** 组装 tshark frame-table 命令行（与事件抽取同一文件、不同字段集） */
export function framesArgs(file: string): string[] {
  return [
    "-r",
    file,
    "-n",
    "-T",
    "fields",
    "-E",
    "separator=\t",
    "-E",
    "occurrence=a",
    "-E",
    "aggregator=,",
    "-E",
    "quote=n",
    ...FRAMES_FIELDS.flatMap((f) => ["-e", f]),
  ];
}
