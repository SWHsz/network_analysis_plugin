import type { EventDetection, EventType } from "../types.js";

/**
 * Event Registry —— v0.1 冻结为 3 族 5 种。
 *
 * 注册表是字段清单与文档的单一来源：
 * - 抽取遍历的 -e 字段集合 = 所有 source.tsharkFields 的并集；
 * - attributes 声明每个事件类型的 attributes 形状（用于校验与文档生成）。
 *
 * 新增事件类型：在此加一行 + 在 extract.ts 写映射逻辑
 * （映射本身是协议相关的，无法纯声明式），文档自动跟随。
 */
export interface EventSpec {
  type: EventType;
  detection: EventDetection;
  description: string;
  attributes: Record<string, "string" | "number">;
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
    source: {
      tsharkFields: [
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
      ],
    },
  },
  dns_query: {
    type: "dns_query",
    detection: "tshark_dns_dissector",
    description: "DNS 查询请求。",
    attributes: { dns_id: "number", qname: "string", qtype: "string" },
    source: { tsharkFields: ["dns.id", "dns.qry.name", "dns.qry.type"] },
  },
  dns_response: {
    type: "dns_response",
    detection: "tshark_dns_dissector",
    description: "DNS 应答。rcode_num 为数字（0=NOERROR, 3=NXDOMAIN …）。",
    attributes: { dns_id: "number", qname: "string", rcode_num: "number" },
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
] as const;

/** 抽取遍历的完整字段序列（公共 + 注册表并集，按插入顺序去重） */
export const EXTRACTION_FIELDS: string[] = (() => {
  const set = new Set<string>(BASE_FIELDS);
  for (const spec of Object.values(EVENT_REGISTRY)) {
    for (const f of spec.source.tsharkFields) set.add(f);
  }
  return [...set];
})();
