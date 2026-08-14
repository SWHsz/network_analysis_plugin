/**
 * Traffic Observation IR — v0.1
 *
 * 原则：Plugin 只输出 observation（可下钻到 frame 的事实），
 * 不输出 network_condition / congestion 之类的高级结论。
 * 所有事件均为 backend（tshark）启发式判定的投影，非 ground truth，
 * 见各 Event 的 detection 字段。
 */

/** 端点：IP + 传输层端口。 */
export interface Endpoint {
  ip: string;
  port: number;
}

/** 打开一个 pcap 后得到的 Capture Identity。 */
export interface Capture {
  /** 基于内容采样的稳定指纹，形如 cap_a82f3c1d9e0b4f2a */
  capture_id: string;
  /** 原始文件绝对路径 */
  path: string;
  /** pcap | pcapng（无法识别时为 unknown） */
  format: "pcap" | "pcapng" | "unknown";
  size_bytes: number;
  /** 首包 epoch 秒（浮点） */
  first_packet_epoch: number;
  /** 末包 epoch 秒 */
  last_packet_epoch: number;
  /** 捕获时长（毫秒） */
  duration_ms: number;
  packet_count: number;
  /** 本次会话使用的 backend 与版本，用于 provenance */
  backend: {
    name: "tshark";
    version: string;
  };
  plugin_version: string;
}

export type Transport = "tcp" | "udp";

/**
 * Conversation：两个 endpoint 之间的一次双向传输会话。
 * 方向以 initiator（发起方）为基准：forward = initiator→responder。
 */
export interface Conversation {
  conversation_id: string; // conv:tcp:17
  transport: Transport;
  initiator: Endpoint;
  responder: Endpoint;
  /**
   * initiator 方向的判定依据：
   * - handshake：观测到 TCP 握手，SYN 发送方即 initiator（最可靠）；
   * - port_heuristic：无握手观测（如中途开始抓包），按「知名端口(<1024)侧为
   *   responder」的约定推断 —— 是猜测，可能是 NAT/中转等场景下的误判；
   * - first_packet：无握手且端口无法区分，退化为首个包的发送方。
   */
  direction_basis: "handshake" | "port_heuristic" | "first_packet";
  /** 相对捕获起点的毫秒 */
  start_ms: number;
  duration_ms: number;
  packets: { forward: number; reverse: number };
  bytes: { forward: number; reverse: number };
  /** 由本包事件抽取聚合出的派生指标（无数据为 0/null） */
  metrics: ConversationMetrics;
  /** 仅标记实际观测到的协议特征：transport + dns/tls 等来自事件证据 */
  protocol_tags: string[];
}

export interface ConversationMetrics {
  retransmission_count: number;
  dns_query_count: number;
  tls_handshake_count: number;
  /** SYN → 握手完成（首个 SYN 后的 ACK）耗时，未观测到为 null */
  tcp_handshake_ms: number | null;
  /** 首个 ClientHello → 首个 ServerHello 耗时，未观测到为 null */
  tls_handshake_ms: number | null;
}

export type EventType =
  | "tcp_retransmission"
  | "dns_query"
  | "dns_response"
  | "tls_client_hello"
  | "tls_server_hello";

export type EventDirection = "initiator_to_responder" | "responder_to_initiator" | "unknown";

/**
 * Event：时间轴上的一个观测点。
 * v0.1 仅 3 族（retrans / dns / tls），扩展走 event registry，
 * 见 src/events/registry.ts 与 docs/event-registry.md。
 */
export interface TrafficEvent {
  event_id: string; // evt:<seq>
  conversation_id: string;
  type: EventType;
  /** 相对捕获起点的毫秒 */
  time_ms: number;
  direction: EventDirection;
  attributes: Record<string, string | number | null>;
  detection: EventDetection;
  evidence: EventEvidence;
}

/** 判定来源：tshark 启发式字段的投影，非 ground truth。 */
export type EventDetection = "tshark_tcp_analysis" | "tshark_dns_dissector" | "tshark_tls_dissector";

export type EventEvidence =
  | { kind: "frame"; frame_number: number }
  | { kind: "frames"; frame_numbers: number[] };

/** 聚合观测的 evidence（frame 列表在 Context Shaper 中有上限） */
export interface AggregateEvidence {
  kind: "aggregate";
  frames: number[];
  /** 超过上限时给区间描述，避免撑爆 context */
  frame_count: number;
  truncated: boolean;
}

/** 返回给调用方（DSH output.schema 规范值）的有界结果信封 */
export interface BoundedResult<T> {
  returned: number;
  total: number;
  offset: number;
  truncated: boolean;
  items: T[];
}

export interface AuditMetadata {
  capture_id: string;
  query_hash: string;
  backend: "tshark";
  backend_version: string;
  plugin_version: string;
  /** 实际执行的 backend 命令摘要（debug 用） */
  backend_commands: string[];
}
