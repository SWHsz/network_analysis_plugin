import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { runBinary } from "../src/backend/spawn.js";

const FIXTURE = path.resolve(__dirname, "../../../fixtures/web-session.pcap");
const MID_CAPTURE = path.resolve(__dirname, "../../../fixtures/mid-capture.pcap");

async function tsharkAvailable(): Promise<boolean> {
  try {
    await runBinary("tshark", ["--version"], { timeoutMs: 10_000 });
    return true;
  } catch {
    return false;
  }
}

const skip = !(await tsharkAvailable());
const cacheDirs: string[] = [];

describe("TrafficSession end-to-end (real tshark)", { skip: skip || undefined }, () => {
  let session: TrafficSession;

  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-core-e2e-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
  });

  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("traffic_open: capture identity", () => {
    expect(session.capture.capture_id).toMatch(/^cap_[0-9a-f]{16}$/);
    expect(session.capture.format).toBe("pcap");
    expect(session.capture.packet_count).toBe(32);
    expect(session.capture.duration_ms).toBeCloseTo(1600, -1);
    expect(session.capture.first_packet_epoch).toBeCloseTo(0, 3);
    expect(session.capture.backend.name).toBe("tshark");
  });

  it("overview: protocol distribution and conversation counts", async () => {
    const o = await session.overview();
    const dns = o.protocol_distribution.find((p) => p.name === "dns")!;
    const tls = o.protocol_distribution.find((p) => p.name === "tls")!;
    expect(dns.frames).toBe(4);
    expect(tls.frames).toBe(2);
    expect(o.conversation_counts).toEqual({ tcp: 2, udp: 3 });
    // 按字节排序的 top 会话是 TLS conv
    expect(o.top_conversations_by_bytes[0]!.endpoint_b).toContain("443");
    expect(o.audit.capture_id).toBe(session.capture.capture_id);
    expect(o.audit.backend_commands.length).toBeGreaterThan(0);
  });

  it("query conversations with retransmissions, ordered", async () => {
    const { result } = await session.query({
      scope: "conversation",
      where: [{ field: "retransmission_count", op: "gt", value: 0 }],
      select: ["conversation_id", "retransmission_count", "tcp_handshake_ms", "tls_handshake_ms"],
      order_by: [{ field: "retransmission_count", direction: "desc" }],
    });
    expect(result.total).toBe(2);
    expect(result.items[0]).toMatchObject({ conversation_id: "conv:tcp:0", retransmission_count: 3 });
    expect(result.items[0]!.tcp_handshake_ms).toBeCloseTo(70, 1);
    expect(result.items[0]!.tls_handshake_ms).toBeCloseTo(145, 1);
    expect(result.items[1]).toMatchObject({ conversation_id: "conv:tcp:1", retransmission_count: 1 });
  });

  it("inspect: timeline and retransmission evidence down to frames", async () => {
    const insp = await session.inspect("conv:tcp:0");
    expect(insp.conversation.protocol_tags).toEqual(["tcp", "tls"]);
    expect(insp.aggregates.retransmissions.count).toBe(3);
    expect(insp.aggregates.retransmissions.evidence.frames).toEqual([8, 11, 14]);
    const types = insp.timeline.items.map((e) => e.type);
    expect(types).toContain("tls_client_hello");
    expect(types).toContain("tls_server_hello");
    expect(insp.timeline.truncated).toBe(false);
  });

  it("query events: dns responses include NXDOMAIN with rcode evidence", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [{ field: "type", op: "eq", value: "dns_response" }],
      select: ["event_id", "time_ms", "frame_number"],
      order_by: [{ field: "time_ms", direction: "asc" }],
    });
    expect(result.total).toBe(2);
    expect(result.items.map((i) => i.frame_number)).toEqual([19, 21]);
  });

  it("event drill-down per conversation keeps evidence binding", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [
        { field: "conversation_id", op: "eq", value: "conv:tcp:1" },
        { field: "type", op: "eq", value: "tcp_retransmission" },
      ],
    });
    expect(result.total).toBe(1);
    expect(result.items[0]!.frame_number).toBe(26);
  });

  it("invalid queries surface helpful errors", async () => {
    await expect(
      session.query({ scope: "conversation", where: [{ field: "tcp.stream", op: "eq", value: 1 }] }),
    ).rejects.toThrow(/unknown field 'tcp\.stream'/);
    await expect(session.inspect("conv:tcp:99")).rejects.toThrow(/unknown conversation/);
  });

  it("cache: second session reuses artifacts without re-running tshark", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-core-e2e2-"));
    cacheDirs.push(dir);
    const first = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
    await first.overview(); // 触发轻索引
    await first.query({ scope: "conversation", limit: 1 }); // 触发全量抽取
    const commandsAfterFirst = first.audit().backend_commands.length;

    const second = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
    await second.query({ scope: "conversation", limit: 1 });
    // 第二次会话只跑了 capinfos（open 时），索引与事件均来自缓存
    expect(second.audit().backend_commands.length).toBe(1);
    expect(commandsAfterFirst).toBeGreaterThan(1);
    const files = await readdir(path.join(dir, "captures", second.capture.capture_id));
    expect(files).toContain("index.json");
    expect(files).toContain("events.json");
    expect(files).toContain("version");
  });

  // 真实世界回归：中途开始抓包（无 SYN，服务端先发包），源自 23.pcap 会话暴露的两个 bug
  describe("mid-capture regression (23.pcap session findings)", () => {
    it("overview counts conversations with humanized byte units (137 kB)", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "traffic-core-mid-"));
      cacheDirs.push(dir);
      const s = await TrafficSession.open(MID_CAPTURE, { cacheDir: dir, autoDownload: false });
      const o = await s.overview();
      // 回归前：0 tcp / 0 udp（conv 行带 kB 单位，正则不匹配）
      expect(o.conversation_counts).toEqual({ tcp: 1, udp: 0 });
      expect(o.top_conversations_by_bytes).toHaveLength(1);
      expect(o.top_conversations_by_bytes[0]!.endpoint_a).toContain("443");
    });

    it("initiator resolved to ephemeral-port side via port heuristic", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "traffic-core-mid2-"));
      cacheDirs.push(dir);
      const s = await TrafficSession.open(MID_CAPTURE, { cacheDir: dir, autoDownload: false });
      const { result } = await s.query({
        scope: "conversation",
        select: ["conversation_id", "initiator_ip", "initiator_port", "responder_ip", "responder_port"],
      });
      expect(result.total).toBe(1);
      // 回归前：initiator 被判为服务端 443（首包启发式在中途抓包下失效）
      expect(result.items[0]).toMatchObject({
        initiator_ip: "192.168.9.9",
        initiator_port: 52300,
        responder_ip: "93.184.10.20",
        responder_port: 443,
      });
      const insp = await s.inspect("conv:tcp:0");
      expect(insp.conversation.direction_basis).toBe("port_heuristic");
    });
  });
});
