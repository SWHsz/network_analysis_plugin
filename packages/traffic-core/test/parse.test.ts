import { describe, expect, it } from "vitest";
import { parseCapinfosTsv, parseZStats } from "../src/indexer.js";
import { ExtractionState } from "../src/events/extract.js";
import { EXTRACTION_FIELDS } from "../src/events/registry.js";
import { parseCapinfosDate } from "../src/util.js";

/** capinfos -T -t -u -c -d -a -e 的真实输出格式（macOS, Wireshark 4.4.8） */
const CAPINFOS_TSV = [
  "File name\tFile type\tNumber of packets\tData size (bytes)\tCapture duration (seconds)\tStart time\tEnd time",
  "web-session.pcap\tpcap\t32\t7669\t1.600000\t1970-01-01 08:00:00.000000\t1970-01-01 08:00:01.600000",
].join("\n");

/** tshark -q -z io,phs -z conv,tcp -z conv,udp 的真实输出片段 */
const ZSTATS = `

===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:32 bytes:7669
  ip                                     frames:32 bytes:7669
    tcp                                  frames:26 bytes:7247
      tls                                frames:2 bytes:205
    udp                                  frames:6 bytes:422
      dns                                frames:4 bytes:327

===================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.4:53124          <-> 142.250.74.14:443                7 4,745 bytes      10 1,830 bytes      17 6,575 bytes     0.000000000         0.6200
192.168.1.4:53125          <-> 93.184.216.34:80                 3 212 bytes       6 460 bytes       9 672 bytes       1.000000000         0.4200

===================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.4:53126          <-> 8.8.8.8:53                      2 412 bytes        2 340 bytes        4 752 bytes     0.050000000         0.2100
`;

describe("parseCapinfosTsv", () => {
  it("parses the real capinfos TSV format", () => {
    const info = parseCapinfosTsv(CAPINFOS_TSV);
    expect(info.format).toBe("pcap");
    expect(info.packet_count).toBe(32);
    expect(info.data_size_bytes).toBe(7669);
    expect(info.duration_s).toBeCloseTo(1.6);
    // epoch 由本地时区日期反推（生成时 scapy 用 epoch 0）
    expect(info.start_epoch).toBeCloseTo(0, 5);
    expect(info.end_epoch).toBeCloseTo(1.6, 5);
  });

  it("rejects missing columns", () => {
    expect(() => parseCapinfosTsv("File name\tPackets\nx\t1\n")).toThrow(/missing column/);
  });
});

describe("parseCapinfosDate", () => {
  it("roundtrips epoch 0 in the local timezone", () => {
    expect(parseCapinfosDate("1970-01-01 08:00:00.000000")).toBeCloseTo(0, 6);
  });
});

describe("parseZStats", () => {
  const capinfos = parseCapinfosTsv(CAPINFOS_TSV);
  const index = parseZStats(ZSTATS, capinfos, "4.4.8");

  it("parses protocol hierarchy with depth", () => {
    const eth = index.protocol_hierarchy.find((p) => p.name === "eth")!;
    const tls = index.protocol_hierarchy.find((p) => p.name === "tls")!;
    expect(eth.depth).toBe(0);
    expect(eth.frames).toBe(32);
    expect(tls.depth).toBe(3);
    expect(tls.frames).toBe(2);
  });

  it("parses tcp and udp conversations with direction split", () => {
    expect(index.conversations).toHaveLength(3);
    const tls = index.conversations.find((c) => c.endpoint_b.includes("443"))!;
    expect(tls.transport).toBe("tcp");
    expect(tls.endpoint_a).toBe("192.168.1.4:53124");
    expect(tls.frames_b_to_a).toBe(7); // "<-" 列
    expect(tls.bytes_b_to_a).toBe(4745); // 千分位逗号被剥离
    expect(tls.frames_a_to_b).toBe(10);
    expect(tls.relative_start_s).toBeCloseTo(0);
    const dns = index.conversations.find((c) => c.transport === "udp")!;
    expect(dns.endpoint_b).toBe("8.8.8.8:53");
  });

  it("parses humanized byte units (kB/MB) from real captures", () => {
    // 真实大流量抓包中 tshark conv 统计输出 1000 进制缩写（回归：曾解析为 0 会话）
    const real = [
      "TCP Conversations",
      "Filter:<No Filter>",
      "                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |",
      "                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |",
      "142.250.199.65:443         <-> 192.168.50.159:11606            64 4732 bytes     124 137 kB        188 141 kB        0.000000000         0.3634",
    ].join("\n");
    const parsed = parseZStats(`\n${real}\n`, capinfos, "4.4.8");
    expect(parsed.conversations).toHaveLength(1);
    const c = parsed.conversations[0]!;
    expect(c.bytes_a_to_b).toBe(137_000);
    expect(c.bytes_b_to_a).toBe(4732);
    expect(c.frames_a_to_b).toBe(124);
  });
});

describe("ExtractionState", () => {
  /** 按字段名生成一行 -T fields 输出（列序与 EXTRACTION_FIELDS 严格一致） */
  function line(fields: Record<string, string>): string {
    const cols = new Array<string>(EXTRACTION_FIELDS.length).fill("");
    for (const [name, value] of Object.entries(fields)) {
      const i = EXTRACTION_FIELDS.indexOf(name);
      if (i < 0) throw new Error(`unknown field in test: ${name}`);
      cols[i] = value;
    }
    return cols.join("\t");
  }

  it("builds conversations, events and metrics from field rows", () => {
    const s = new ExtractionState();
    const E0 = "1700000000.000000000";
    // conv tcp:0 —— SYN / SYNACK / ACK / ClientHello / ServerHello / 重传
    s.feed(line({ "frame.number": "1", "frame.time_epoch": E0, "frame.len": "60", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "1000", "tcp.dstport": "443", "tcp.flags.syn": "True", "tcp.flags.ack": "False" }));
    s.feed(line({ "frame.number": "2", "frame.time_epoch": `${Number(E0) + 0.035}`, "frame.len": "60", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "1000", "tcp.flags.syn": "True", "tcp.flags.ack": "True" }));
    s.feed(line({ "frame.number": "3", "frame.time_epoch": `${Number(E0) + 0.070}`, "frame.len": "52", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "1000", "tcp.dstport": "443", "tcp.flags.ack": "True" }));
    s.feed(line({ "frame.number": "4", "frame.time_epoch": `${Number(E0) + 0.075}`, "frame.len": "80", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "1000", "tcp.dstport": "443", "tcp.flags.ack": "True", "tls.handshake.type": "1" }));
    s.feed(line({ "frame.number": "5", "frame.time_epoch": `${Number(E0) + 0.220}`, "frame.len": "90", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "1000", "tcp.flags.ack": "True", "tls.handshake.type": "2" }));
    s.feed(line({ "frame.number": "6", "frame.time_epoch": `${Number(E0) + 0.340}`, "frame.len": "80", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "1000", "tcp.dstport": "443", "tcp.flags.ack": "True", "tcp.analysis.retransmission": "True" }));
    // conv udp:0 —— DNS 问答
    s.feed(line({ "frame.number": "7", "frame.time_epoch": `${Number(E0) + 0.050}`, "frame.len": "75", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "udp.stream": "0", "udp.srcport": "5300", "udp.dstport": "53", "dns.id": "0x1234", "dns.qry.name": "youtube.com", "dns.qry.type": "1" }));
    s.feed(line({ "frame.number": "8", "frame.time_epoch": `${Number(E0) + 0.095}`, "frame.len": "100", "ip.src": "8.8.8.8", "ip.dst": "10.0.0.1", "udp.stream": "0", "udp.srcport": "53", "udp.dstport": "5300", "dns.id": "0x1234", "dns.flags.response": "True", "dns.qry.name": "youtube.com", "dns.flags.rcode": "3" }));

    const x = s.finish("4.4.8");

    expect(x.conversations).toHaveLength(2);
    const tcp = x.conversations.find((c) => c.conversation_id === "conv:tcp:0")!;
    expect(tcp.initiator).toEqual({ ip: "10.0.0.1", port: 1000 });
    expect(tcp.packets).toEqual({ forward: 4, reverse: 2 });
    expect(tcp.metrics.retransmission_count).toBe(1);
    expect(tcp.metrics.tcp_handshake_ms).toBeCloseTo(70, 2);
    expect(tcp.metrics.tls_handshake_ms).toBeCloseTo(145, 2);
    expect(tcp.protocol_tags).toEqual(["tcp", "tls"]);
    expect(tcp.direction_basis).toBe("handshake");

    const dnsEvents = x.events.filter((e) => e.type.startsWith("dns_"));
    expect(dnsEvents).toHaveLength(2);
    const resp = dnsEvents.find((e) => e.type === "dns_response")!;
    expect(resp.attributes).toMatchObject({ dns_id: 0x1234, qname: "youtube.com", rcode_num: 3 });
    expect(resp.detection).toBe("tshark_dns_dissector");
    expect(resp.evidence).toEqual({ kind: "frame", frame_number: 8 });

    const evt = x.events.find((e) => e.type === "tcp_retransmission")!;
    expect(evt.attributes).toEqual({ variant: "plain" });
    expect(evt.detection).toBe("tshark_tcp_analysis");

    // 事件全局按时间排序且 event_id 连续
    expect(x.events.map((e) => e.event_id)).toEqual(
      x.events.map((_, i) => `evt:${String(i + 1).padStart(6, "0")}`),
    );
  });

  it("ignores frames without stream identity", () => {
    const s = new ExtractionState();
    s.feed(line({ "frame.number": "1", "frame.time_epoch": "1700000000.0", "frame.len": "60", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2" }));
    const x = s.finish("4.4.8");
    expect(x.conversations).toHaveLength(0);
    expect(x.packet_count).toBe(1);
  });

  it("mid-capture (no SYN, server first): port heuristic flips initiator to ephemeral side", () => {
    const s = new ExtractionState();
    const E0 = "1700000000.000000000";
    // 服务端 443 先发（中途抓包），客户端 52300 后应答
    s.feed(line({ "frame.number": "1", "frame.time_epoch": E0, "frame.len": "122", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.ack": "True" }));
    s.feed(line({ "frame.number": "2", "frame.time_epoch": `${Number(E0) + 0.002}`, "frame.len": "52", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "52300", "tcp.dstport": "443", "tcp.flags.ack": "True" }));
    s.feed(line({ "frame.number": "3", "frame.time_epoch": `${Number(E0) + 0.004}`, "frame.len": "122", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.ack": "True" }));
    const x = s.finish("4.4.8");
    const conv = x.conversations[0]!;
    // 端口启发式：临时端口一侧被认定为 initiator（诚实标注为猜测）
    expect(conv.initiator).toEqual({ ip: "10.0.0.1", port: 52300 });
    expect(conv.responder).toEqual({ ip: "10.0.0.2", port: 443 });
    expect(conv.direction_basis).toBe("port_heuristic");
    // forward = initiator→responder = 客户端方向
    expect(conv.packets).toEqual({ forward: 1, reverse: 2 });
    expect(conv.bytes).toEqual({ forward: 52, reverse: 244 });
  });

  it("indistinguishable ports fall back to first_packet basis", () => {
    const s = new ExtractionState();
    s.feed(line({ "frame.number": "1", "frame.time_epoch": "1700000000.0", "frame.len": "60", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "40000", "tcp.dstport": "40001", "tcp.flags.ack": "True" }));
    const conv = s.finish("4.4.8").conversations[0]!;
    expect(conv.direction_basis).toBe("first_packet");
    expect(conv.initiator.port).toBe(40000);
  });

  it("missing_segment without prior seq in direction → origin=capture_start, gap=null", () => {
    const s = new ExtractionState();
    const E0 = "1700000000.0";
    // 中途抓包首帧（无 SYN）：lost_segment 且该方向无先验序号
    s.feed(line({ "frame.number": "1", "frame.time_epoch": E0, "frame.len": "120", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.ack": "True", "tcp.seq_raw": "9000", "tcp.len": "100", "tcp.analysis.lost_segment": "1" }));
    const evt = s.finish("4.4.8").events.find((e) => e.type === "tcp_missing_segment")!;
    expect(evt.attributes.origin).toBe("capture_start");
    expect(evt.attributes.gap_bytes).toBeNull();
  });

  it("missing_segment with prior max seq → gap computed, origin=mid_stream", () => {
    const s = new ExtractionState();
    const E0 = "1700000000.0";
    // SYNACK 建立基线 2001 → 数据 seq 2001..2100 → 缺口段 seq 2200
    s.feed(line({ "frame.number": "1", "frame.time_epoch": E0, "frame.len": "60", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.syn": "True", "tcp.flags.ack": "True", "tcp.seq_raw": "2000" }));
    s.feed(line({ "frame.number": "2", "frame.time_epoch": `${Number(E0) + 0.01}`, "frame.len": "160", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.ack": "True", "tcp.seq_raw": "2001", "tcp.len": "100" }));
    s.feed(line({ "frame.number": "3", "frame.time_epoch": `${Number(E0) + 0.02}`, "frame.len": "160", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "443", "tcp.dstport": "52300", "tcp.flags.ack": "True", "tcp.seq_raw": "2200", "tcp.len": "100", "tcp.analysis.lost_segment": "1" }));
    const evt = s.finish("4.4.8").events.find((e) => e.type === "tcp_missing_segment")!;
    expect(evt.attributes.origin).toBe("mid_stream");
    expect(evt.attributes.gap_bytes).toBe(99); // 2101(下一期望) → 2200：缺 [2101,2200) 共 99B
  });

  it("http events map method/host/uri/status and resp_time", () => {
    const s = new ExtractionState();
    s.feed(line({ "frame.number": "1", "frame.time_epoch": "1700000000.0", "frame.len": "100", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "tcp.stream": "0", "tcp.srcport": "5000", "tcp.dstport": "80", "tcp.flags.ack": "True", "http.request.method": "GET", "http.host": "edge.test", "http.request.uri": "/data" }));
    s.feed(line({ "frame.number": "2", "frame.time_epoch": "1700000000.03", "frame.len": "200", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "tcp.stream": "0", "tcp.srcport": "80", "tcp.dstport": "5000", "tcp.flags.ack": "True", "http.response.code": "200", "http.content_type": "text/html", "http.time": "0.030000000" }));
    const evts = s.finish("4.4.8").events;
    expect(evts.find((e) => e.type === "http_request")!.attributes).toMatchObject({ method: "GET", host: "edge.test", uri: "/data" });
    const resp = evts.find((e) => e.type === "http_response")!;
    expect(resp.attributes).toMatchObject({ status_code: 200, content_type: "text/html", resp_time_ms: 30 });
    expect(resp.detection).toBe("tshark_http_dissector");
  });
});
