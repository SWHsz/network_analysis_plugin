import type { EventDetection, EventType } from "../types.js";

/**
 * Event Registry —— v0.2：5 族 11 种。
 *
 * 注册表是字段清单与文档的单一来源：
 * - 抽取遍历的 -e 字段集合 = 所有 source.tsharkFields 的并集；
 * - attributes 声明每个事件类型的 attributes 形状（用于校验与文档生成）；
 * - queryable 标记哪些 attributes 进入 event where 白名单（attr.<name>）。
 *
 * 新增事件类型：在此加一行 + 在 extract.ts 写映射逻辑
 * （映射本身是协议相关的，无法纯声明式），文档自动跟随。
 */
export interface EventSpec {
  type: EventType;
  detection: EventDetection;
  description: string;
  attributes: Record<string, "string" | "number">;
  /** 进入 attr.* 查询白名单的 attributes（生成 EVENT_ATTR_FIELDS 用） */
  queryable?: string[];
  /** 该事件依赖的 tshark 字段 */
  source: { tsharkFields: string[] };
}

export const EVENT_REGISTRY: Record<EventType, EventSpec> = {
  tcp_retransmission: {
    type: "tcp_retransmission",
    detection: "tshark_tcp_analysis",
    description:
      "TCP 段重传。tshark tcp.analysis.* 启发式判定的投影（非 ground truth）；" +
      "attributes.variant 区分 plain/fast/spurious。不蕴含网络拥塞结论。",
    attributes: { variant: "string" },
    queryable: ["variant"],
    source: {
      tsharkFields: [
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
      ],
    },
  },
  tcp_out_of_order: {
    type: "tcp_out_of_order",
    detection: "tshark_tcp_analysis",
    description: "TCP 乱序到达段（后发先至）。",
    attributes: {},
    source: { tsharkFields: ["tcp.analysis.out_of_order"] },
  },
  tcp_dup_ack: {
    type: "tcp_dup_ack",
    detection: "tshark_tcp_analysis",
    description: "重复 ACK（接收端在等缺失段）。attributes.dup_ack_count 为该系列中的第几个。",
    attributes: { dup_ack_count: "number" },
    queryable: ["dup_ack_count"],
    source: { tsharkFields: ["tcp.analysis.duplicate_ack", "tcp.analysis.duplicate_ack_num"] },
  },
  tcp_zero_window: {
    type: "tcp_zero_window",
    detection: "tshark_tcp_analysis",
    description: "零窗口通告（接收方缓冲区满）。",
    attributes: {},
    source: { tsharkFields: ["tcp.analysis.zero_window"] },
  },
  tcp_missing_segment: {
    type: "tcp_missing_segment",
    detection: "tshark_tcp_analysis",
    description:
      "缺失段（tcp.analysis.lost_segment）。attributes.gap_bytes 为相对流内已见最高连续序号的缺口大小；" +
      "attributes.origin 区分 capture_start（抓包起点前已有数据，常见于中途抓包）与 mid_stream（流中途缺口）。",
    attributes: { gap_bytes: "number", origin: "string" },
    queryable: ["gap_bytes", "origin"],
    source: { tsharkFields: ["tcp.analysis.lost_segment"] },
  },
  dns_query: {
    type: "dns_query",
    detection: "tshark_dns_dissector",
    description: "DNS 查询请求。",
    attributes: { dns_id: "number", qname: "string", qtype: "string" },
    queryable: ["qname"],
    source: { tsharkFields: ["dns.id", "dns.qry.name", "dns.qry.type"] },
  },
  dns_response: {
    type: "dns_response",
    detection: "tshark_dns_dissector",
    description: "DNS 应答。rcode_num 为数字（0=NOERROR, 3=NXDOMAIN …）。",
    attributes: { dns_id: "number", qname: "string", rcode_num: "number" },
    queryable: ["qname", "rcode_num"],
    source: { tsharkFields: ["dns.flags.response", "dns.id", "dns.qry.name", "dns.flags.rcode"] },
  },
  tls_client_hello: {
    type: "tls_client_hello",
    detection: "tshark_tls_dissector",
    description: "TLS ClientHello（握手发起）。",
    attributes: {},
    source: { tsharkFields: ["tls.handshake.type"] },
  },
  tls_server_hello: {
    type: "tls_server_hello",
    detection: "tshark_tls_dissector",
    description: "TLS ServerHello。",
    attributes: {},
    source: { tsharkFields: ["tls.handshake.type"] },
  },
  http_request: {
    type: "http_request",
    detection: "tshark_http_dissector",
    description: "HTTP 请求（经 TCP 重组还原）。",
    attributes: { method: "string", host: "string", uri: "string" },
    queryable: ["method", "host", "uri"],
    source: {
      tsharkFields: ["http.request.method", "http.host", "http.request.uri"],
    },
  },
  http_response: {
    type: "http_response",
    detection: "tshark_http_dissector",
    description: "HTTP 应答。resp_time_ms 来自 http.time（请求→应答间隔），未配对为 null。",
    attributes: { status_code: "number", content_type: "string", resp_time_ms: "number" },
    queryable: ["status_code", "content_type"],
    source: {
      tsharkFields: ["http.response.code", "http.content_type", "http.time"],
    },
  },
};

/** 抽取遍历的公共字段（事件无关的会话/方向信息） */
export const BASE_FIELDS = [
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
  "tcp.flags.syn",
  "tcp.flags.ack",
  // v0.2：缺失段 gap 计算（流内已见最高序号）与 RTT 指标
  "tcp.seq_raw",
  "tcp.len",
  "tcp.analysis.ack_rtt",
] as const;

/** 全部需要抽取的 tshark 字段（公共 + 注册表并集，按插入顺序去重） */
export const EXTRACTION_FIELDS: string[] = (() => {
  const set = new Set<string>(BASE_FIELDS);
  for (const spec of Object.values(EVENT_REGISTRY)) {
    for (const f of spec.source.tsharkFields) set.add(f);
  }
  return [...set];
})();

export interface AttrFieldSpec {
  /** attr.<name> 的值类型 */
  type: "number" | "string";
  /** 声明了该 queryable attribute 的事件类型（where 里须有其中之一的 type eq） */
  compatibleTypes: EventType[];
}

/**
 * event scope 的 attr.* 查询白名单（由注册表 queryable 声明生成）。
 * 校验规则：使用 attr.X 必须同时在 where 里给出 type eq <兼容类型>。
 */
export const EVENT_ATTR_FIELDS: Record<string, AttrFieldSpec> = (() => {
  const map: Record<string, AttrFieldSpec> = {};
  for (const spec of Object.values(EVENT_REGISTRY)) {
    for (const name of spec.queryable ?? []) {
      const decl = spec.attributes[name];
      if (!decl) continue;
      const entry = (map[name] ??= {
        type: decl as "number" | "string",
        compatibleTypes: [],
      });
      entry.compatibleTypes.push(spec.type);
    }
  }
  return map;
})();
