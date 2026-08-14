import type {
  Conversation,
  Endpoint,
  EventDirection,
  TrafficEvent,
  Transport,
} from "../types.js";
import { PLUGIN_VERSION } from "../util.js";
import { EXTRACTION_FIELDS } from "./registry.js";

/** 字段名 → 列号（与 extractionArgs 的 -e 顺序严格一致） */
const COL: Readonly<Record<string, number>> = Object.fromEntries(
  EXTRACTION_FIELDS.map((f, i) => [f, i]),
);

/** 抽取结果（缓存于 events.json） */
export interface Extraction {
  plugin_version: string;
  tshark_version: string;
  built_at: string;
  first_epoch: number;
  last_epoch: number;
  packet_count: number;
  conversations: Conversation[];
  events: TrafficEvent[];
}

const TRUTHY = new Set(["1", "true", "True", "TRUE"]);

/**
 * -T fields occurrence=a 下布尔标志可能聚合为 "1,1"（同帧多 occurrence），
 * 判定真值须按逗号拆分。
 */
function truthyAny(value: string | undefined): boolean {
  if (!value) return false;
  return value.split(",").some((tok) => TRUTHY.has(tok));
}

interface ConvAccumulator {
  transport: Transport;
  streamId: number;
  initiator: Endpoint;
  responder: Endpoint;
  /** 是否观测到 SYN（方向判定的最可靠依据） */
  sawSyn: boolean;
  firstEpoch: number;
  lastEpoch: number;
  packetsForward: number;
  packetsReverse: number;
  bytesForward: number;
  bytesReverse: number;
  /** TCP 握手：首个 SYN 的 epoch；握手的完成以客户端 ACK 为准 */
  firstSynEpoch: number | null;
  handshakeDoneEpoch: number | null;
  firstClientHelloEpoch: number | null;
  firstServerHelloEpoch: number | null;
  /** 每方向已见最高连续序号终点（seq_raw+len），用于缺失段 gap 计算 */
  maxSeqEnd: { forward: number | null; reverse: number | null };
  /** tcp.analysis.ack_rtt 样本（秒） */
  ackRttSamples: number[];
  events: RawEvent[];
}

interface RawEvent {
  epoch: number;
  frameNumber: number;
  type: TrafficEvent["type"];
  direction: EventDirection;
  attributes: Record<string, string | number | null>;
}

function parseEndpoint(ip: string | undefined, port: string | undefined): Endpoint | null {
  if (!ip) return null;
  return { ip, port: port ? Number(port) : 0 };
}

function sameEndpoint(a: Endpoint | null, b: Endpoint | null): boolean {
  return !!a && !!b && a.ip === b.ip && a.port === b.port;
}

function segLenPositive(segLen: string | undefined): boolean {
  if (!segLen) return false;
  const n = Number(segLen);
  return Number.isFinite(n) && n > 0;
}

function median(sorted: number[]): number | null {
  if (sorted.length === 0) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[mid]!
    : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

/** 一次 tshark -T fields 全量遍历的行处理器；feed() 每行调用一次。 */
export class ExtractionState {
  private convs = new Map<string, ConvAccumulator>();
  private firstEpoch = Number.POSITIVE_INFINITY;
  private lastEpoch = 0;
  private packetCount = 0;

  feed(line: string): void {
    const cols = line.split("\t");
    if (cols.length < EXTRACTION_FIELDS.length) return; // 不是我们的字段布局
    const g = (name: string): string => cols[COL[name]!] ?? "";

    const frameNumber = g("frame.number");
    const timeEpoch = g("frame.time_epoch");
    const frameLen = g("frame.len");
    const ipSrc = g("ip.src");
    const ipDst = g("ip.dst");
    const ipv6Src = g("ipv6.src");
    const ipv6Dst = g("ipv6.dst");
    const tcpStream = g("tcp.stream");
    const udpStream = g("udp.stream");
    const tcpSrcport = g("tcp.srcport");
    const tcpDstport = g("tcp.dstport");
    const udpSrcport = g("udp.srcport");
    const udpDstport = g("udp.dstport");
    const tcpSyn = g("tcp.flags.syn");
    const tcpAck = g("tcp.flags.ack");
    const tcpRetrans = g("tcp.analysis.retransmission");
    const tcpFastRetrans = g("tcp.analysis.fast_retransmission");
    const tcpSpuriousRetrans = g("tcp.analysis.spurious_retransmission");
    const tcpHandshakeType = g("tls.handshake.type");
    const dnsId = g("dns.id");
    const dnsResponse = g("dns.flags.response");
    const dnsQname = g("dns.qry.name");
    const dnsQtype = g("dns.qry.type");
    const dnsRcode = g("dns.flags.rcode");
    const tcpOutOfOrder = g("tcp.analysis.out_of_order");
    const tcpDupAck = g("tcp.analysis.duplicate_ack");
    const tcpDupAckNum = g("tcp.analysis.duplicate_ack_num");
    const tcpZeroWindow = g("tcp.analysis.zero_window");
    const tcpLostSegment = g("tcp.analysis.lost_segment");
    const tcpSeqRaw = g("tcp.seq_raw");
    const tcpSegLen = g("tcp.len");
    const ackRtt = g("tcp.analysis.ack_rtt");
    const httpMethod = g("http.request.method");
    const httpHost = g("http.host");
    const httpUri = g("http.request.uri");
    const httpStatus = g("http.response.code");
    const httpContentType = g("http.content_type");
    const httpTime = g("http.time");

    const epoch = Number(timeEpoch);
    if (!Number.isFinite(epoch) || !frameNumber) return;
    const len = Number(frameLen) || 0;
    this.packetCount += 1;
    if (epoch < this.firstEpoch) this.firstEpoch = epoch;
    if (epoch > this.lastEpoch) this.lastEpoch = epoch;

    const srcIp = ipSrc || ipv6Src || undefined;
    const dstIp = ipDst || ipv6Dst || undefined;

    const isTcp = !!tcpStream;
    const streamId = isTcp ? tcpStream : udpStream;
    if (!streamId || !srcIp || !dstIp) return; // 无流标识的包不进 conversation

    const transport: Transport = isTcp ? "tcp" : "udp";
    const key = `${transport}:${streamId}`;
    const src = parseEndpoint(srcIp, isTcp ? tcpSrcport : udpSrcport)!;
    const dst = parseEndpoint(dstIp, isTcp ? tcpDstport : udpDstport)!;

    let conv = this.convs.get(key);
    if (!conv) {
      conv = {
        transport,
        streamId: Number(streamId),
        initiator: src,
        responder: dst,
        sawSyn: false,
        firstEpoch: epoch,
        lastEpoch: epoch,
        packetsForward: 0,
        packetsReverse: 0,
        bytesForward: 0,
        bytesReverse: 0,
        firstSynEpoch: null,
        handshakeDoneEpoch: null,
        firstClientHelloEpoch: null,
        firstServerHelloEpoch: null,
        maxSeqEnd: { forward: null, reverse: null },
        ackRttSamples: [],
        events: [],
      };
      this.convs.set(key, conv);
    }
    conv.lastEpoch = epoch;
    const forward = sameEndpoint(src, conv.initiator) || !sameEndpoint(src, conv.responder);
    if (forward) {
      conv.packetsForward += 1;
      conv.bytesForward += len;
    } else {
      conv.packetsReverse += 1;
      conv.bytesReverse += len;
    }

    const direction: EventDirection = forward ? "initiator_to_responder" : "responder_to_initiator";
    const frame = Number(frameNumber);

    // --- TCP 握手计时（仅 metrics，不产生事件）---
    if (isTcp && truthyAny(tcpSyn)) {
      conv.sawSyn = true;
      if (!truthyAny(tcpAck) && conv.firstSynEpoch === null && forward) {
        conv.firstSynEpoch = epoch;
      }
      // SYN/SYNACK 建立该方向的序号基线（SYN 占 1 序号），
      // 供缺失段 gap 计算区分 mid_stream 与 capture_start
      if (tcpSeqRaw) {
        const base = Number(tcpSeqRaw) + 1;
        if (forward && conv.maxSeqEnd.forward === null) conv.maxSeqEnd.forward = base;
        if (!forward && conv.maxSeqEnd.reverse === null) conv.maxSeqEnd.reverse = base;
      }
    } else if (
      isTcp &&
      conv.firstSynEpoch !== null &&
      conv.handshakeDoneEpoch === null &&
      !truthyAny(tcpSyn) &&
      truthyAny(tcpAck) &&
      forward
    ) {
      conv.handshakeDoneEpoch = epoch;
    }

    // --- 事件映射（v0.2：5 族 11 种，见 EVENT_REGISTRY）---
    if (isTcp && (truthyAny(tcpRetrans) || truthyAny(tcpFastRetrans) || truthyAny(tcpSpuriousRetrans))) {
      const variant = truthyAny(tcpRetrans)
        ? "plain"
        : truthyAny(tcpFastRetrans)
          ? "fast"
          : "spurious";
      conv.events.push({ epoch, frameNumber: frame, type: "tcp_retransmission", direction, attributes: { variant } });
    }

    if (isTcp && truthyAny(tcpOutOfOrder)) {
      conv.events.push({ epoch, frameNumber: frame, type: "tcp_out_of_order", direction, attributes: {} });
    }

    if (isTcp && truthyAny(tcpDupAck)) {
      conv.events.push({
        epoch,
        frameNumber: frame,
        type: "tcp_dup_ack",
        direction,
        attributes: { dup_ack_count: tcpDupAckNum ? Number(tcpDupAckNum) : null },
      });
    }

    if (isTcp && truthyAny(tcpZeroWindow)) {
      conv.events.push({ epoch, frameNumber: frame, type: "tcp_zero_window", direction, attributes: {} });
    }

    if (isTcp && truthyAny(tcpLostSegment)) {
      // gap 相对流内该方向已见最高连续序号；无先验序号（中途抓包首帧）则标 capture_start
      const seq = tcpSeqRaw ? Number(tcpSeqRaw) : null;
      const segLen = tcpSegLen ? Number(tcpSegLen) : 0;
      const priorEnd = forward ? conv.maxSeqEnd.forward : conv.maxSeqEnd.reverse;
      let gap: number | null = null;
      let origin: string = "mid_stream";
      if (seq !== null) {
        if (priorEnd === null) {
          origin = "capture_start";
        } else if (seq > priorEnd) {
          gap = seq - priorEnd;
        }
      }
      conv.events.push({
        epoch,
        frameNumber: frame,
        type: "tcp_missing_segment",
        direction,
        attributes: { gap_bytes: gap, origin },
      });
    }

    // 每方向最高连续序号终点（len>0 的数据段），供后续缺失段 gap 计算
    if (isTcp && tcpSeqRaw && segLenPositive(tcpSegLen)) {
      const end = Number(tcpSeqRaw) + Number(tcpSegLen);
      const side = forward ? conv.maxSeqEnd.forward : conv.maxSeqEnd.reverse;
      if (side === null || end > side) {
        if (forward) conv.maxSeqEnd.forward = end;
        else conv.maxSeqEnd.reverse = end;
      }
    }

    // RTT 样本（tcp.analysis.ack_rtt，秒）
    if (ackRtt) {
      const v = Number(ackRtt);
      if (Number.isFinite(v) && v >= 0) conv.ackRttSamples.push(v);
    }

    if (tcpHandshakeType) {
      for (const t of tcpHandshakeType.split(",")) {
        if (t === "1") {
          conv.events.push({ epoch, frameNumber: frame, type: "tls_client_hello", direction, attributes: {} });
          if (conv.firstClientHelloEpoch === null) conv.firstClientHelloEpoch = epoch;
        } else if (t === "2") {
          conv.events.push({ epoch, frameNumber: frame, type: "tls_server_hello", direction, attributes: {} });
          if (conv.firstServerHelloEpoch === null) conv.firstServerHelloEpoch = epoch;
        }
      }
    }

    if (httpMethod) {
      conv.events.push({
        epoch,
        frameNumber: frame,
        type: "http_request",
        direction,
        attributes: { method: httpMethod, host: httpHost || null, uri: httpUri || null },
      });
    }
    if (httpStatus) {
      const respMs = httpTime ? Number((Number(httpTime) * 1000).toFixed(3)) : null;
      conv.events.push({
        epoch,
        frameNumber: frame,
        type: "http_response",
        direction,
        attributes: {
          status_code: Number(httpStatus),
          content_type: httpContentType || null,
          resp_time_ms: respMs,
        },
      });
    }

    if (dnsQname) {
      const attrs = {
        dns_id: dnsId ? parseInt(dnsId, 16) : null,
        qname: dnsQname.split(",")[0]!,
        qtype: dnsQtype ?? null,
      };
      if (truthyAny(dnsResponse)) {
        conv.events.push({
          epoch,
          frameNumber: frame,
          type: "dns_response",
          direction,
          attributes: { ...attrs, rcode_num: dnsRcode ? Number(dnsRcode) : null },
        });
      } else {
        conv.events.push({ epoch, frameNumber: frame, type: "dns_query", direction, attributes: attrs });
      }
    }
  }

  /** 遍历结束：构建权威 Conversation IR 与有序事件表 */
  finish(tsharkVersion: string): Extraction {
    const conversations: Conversation[] = [];
    let evtSeq = 0;

    const ordered = [...this.convs.values()].sort(
      (a, b) =>
        a.transport.localeCompare(b.transport) || a.streamId - b.streamId,
    );

    for (const acc of ordered) {
      const conversation_id = `conv:${acc.transport}:${acc.streamId}`;
      const baseEpoch = this.firstEpoch;
      const firstEventEpoch = Math.min(...acc.events.map((e) => e.epoch), acc.firstEpoch);
      const lastEpoch = Math.max(...acc.events.map((e) => e.epoch), acc.lastEpoch);

      // initiator 方向判定：握手 > 端口约定（无握手观测时，知名端口侧为 responder）
      // > 首包方向。port_heuristic 是猜测，direction_basis 诚实标注。
      let direction_basis: Conversation["direction_basis"];
      if (acc.sawSyn) {
        direction_basis = "handshake";
      } else if (acc.initiator.port < 1024 && acc.responder.port >= 1024) {
        const { initiator, responder } = acc;
        acc.initiator = responder;
        acc.responder = initiator;
        const pf = acc.packetsForward;
        acc.packetsForward = acc.packetsReverse;
        acc.packetsReverse = pf;
        const bf = acc.bytesForward;
        acc.bytesForward = acc.bytesReverse;
        acc.bytesReverse = bf;
        for (const e of acc.events) {
          if (e.direction === "initiator_to_responder") e.direction = "responder_to_initiator";
          else if (e.direction === "responder_to_initiator") e.direction = "initiator_to_responder";
        }
        direction_basis = "port_heuristic";
      } else {
        direction_basis = "first_packet";
      }

      const hasTls = acc.events.some((e) => e.type === "tls_client_hello" || e.type === "tls_server_hello");
      const hasDns = acc.events.some((e) => e.type === "dns_query" || e.type === "dns_response");
      const hasHttp = acc.events.some((e) => e.type === "http_request" || e.type === "http_response");
      const protocol_tags: string[] = [acc.transport];
      if (hasTls) protocol_tags.push("tls");
      if (hasDns) protocol_tags.push("dns");
      if (hasHttp) protocol_tags.push("http");

      const tcpHandshakeMs =
        acc.firstSynEpoch !== null && acc.handshakeDoneEpoch !== null
          ? Number(((acc.handshakeDoneEpoch - acc.firstSynEpoch) * 1000).toFixed(3))
          : null;
      const tlsHandshakeMs =
        acc.firstClientHelloEpoch !== null && acc.firstServerHelloEpoch !== null
          ? Number(((acc.firstServerHelloEpoch - acc.firstClientHelloEpoch) * 1000).toFixed(3))
          : null;

      // v0.2 指标：RTT（ack_rtt 启发式投影）与吞吐
      const rttSortedMs = [...acc.ackRttSamples].sort((a, b) => a - b);
      const rttMedianMs =
        rttSortedMs.length > 0 ? Number((median(rttSortedMs)! * 1000).toFixed(3)) : null;
      const rttMaxMs =
        rttSortedMs.length > 0 ? Number((rttSortedMs[rttSortedMs.length - 1]! * 1000).toFixed(3)) : null;
      const convDurationMs = (lastEpoch - firstEventEpoch) * 1000;
      const bytesTotal = acc.bytesForward + acc.bytesReverse;
      const throughputBps =
        convDurationMs > 0 ? Math.round((bytesTotal * 8) / (convDurationMs / 1000)) : null;

      conversations.push({
        conversation_id,
        transport: acc.transport,
        initiator: acc.initiator,
        responder: acc.responder,
        direction_basis,
        start_ms: Number(((firstEventEpoch - baseEpoch) * 1000).toFixed(3)),
        duration_ms: Number(((lastEpoch - firstEventEpoch) * 1000).toFixed(3)),
        packets: { forward: acc.packetsForward, reverse: acc.packetsReverse },
        bytes: { forward: acc.bytesForward, reverse: acc.bytesReverse },
        metrics: {
          retransmission_count: acc.events.filter((e) => e.type === "tcp_retransmission").length,
          dns_query_count: acc.events.filter((e) => e.type === "dns_query").length,
          tls_handshake_count: acc.events.filter((e) => e.type === "tls_client_hello").length,
          tcp_handshake_ms: tcpHandshakeMs,
          tls_handshake_ms: tlsHandshakeMs,
          rtt_median_ms: rttMedianMs,
          rtt_max_ms: rttMaxMs,
          throughput_bps: throughputBps,
          missing_segment_count: acc.events.filter((e) => e.type === "tcp_missing_segment").length,
          http_txn_count: acc.events.filter((e) => e.type === "http_request").length,
        },
        protocol_tags,
      });
    }

    const events: TrafficEvent[] = ordered
      .flatMap((acc) => {
        const conversation_id = `conv:${acc.transport}:${acc.streamId}`;
        return acc.events.map((e) => ({
          ...e,
          event_id: "",
          conversation_id,
          time_ms: Number(((e.epoch - this.firstEpoch) * 1000).toFixed(3)),
          detection: detectFor(e.type),
          evidence: { kind: "frame" as const, frame_number: e.frameNumber },
        }));
      })
      .sort((a, b) => a.epoch - b.epoch || a.frameNumber - b.frameNumber)
      .map((e) => ({ ...e, event_id: `evt:${String(++evtSeq).padStart(6, "0")}` }));

    return {
      plugin_version: PLUGIN_VERSION,
      tshark_version: tsharkVersion,
      built_at: new Date().toISOString(),
      first_epoch: this.firstEpoch === Number.POSITIVE_INFINITY ? 0 : this.firstEpoch,
      last_epoch: this.lastEpoch,
      packet_count: this.packetCount,
      conversations,
      events,
    };
  }
}

function detectFor(type: TrafficEvent["type"]): TrafficEvent["detection"] {
  if (type.startsWith("tcp_")) return "tshark_tcp_analysis";
  if (type.startsWith("dns_")) return "tshark_dns_dissector";
  if (type.startsWith("http_")) return "tshark_http_dissector";
  return "tshark_tls_dissector";
}

/** 组装 tshark 事件抽取命令行 */
export function extractionArgs(file: string): string[] {
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
    ...EXTRACTION_FIELDS.flatMap((f) => ["-e", f]),
  ];
}
