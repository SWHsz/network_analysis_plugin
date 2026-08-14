import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { runBinary } from "../src/backend/spawn.js";

const FIXTURE = path.resolve(__dirname, "../../../fixtures/edge-cases.pcap");

const skip = !(await (async () => {
  try {
    await runBinary("tshark", ["--version"], { timeoutMs: 10_000 });
    return true;
  } catch {
    return false;
  }
})());

const cacheDirs: string[] = [];
let session: TrafficSession;

describe("edge-cases fixture (real tshark): v0.2 event families", { skip: skip || undefined }, () => {
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-edge-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("X1: http request/response events with reassembled response and resp_time", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [{ field: "conversation_id", op: "eq", value: "conv:tcp:0" }],
      select: ["type", "time_ms", "frame_number", "direction"],
    });
    const req = result.items.find((i) => i.type === "http_request");
    const resp = result.items.find((i) => i.type === "http_response");
    expect(req).toBeDefined();
    expect(resp).toBeDefined();
    expect(resp!.frame_number).toBeGreaterThan(req!.frame_number);
    const conv = (await session.query({
      scope: "conversation",
      where: [{ field: "conversation_id", op: "eq", value: "conv:tcp:0" }],
      select: ["http_txn_count", "protocol_tags"],
    })).result.items[0]!;
    expect(conv.http_txn_count).toBe(1);
    expect(conv.protocol_tags).toContain("http");
  });

  it("X2: lost_segment(gap=100) + 3 dup_acks + fast retransmission + zero window", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [{ field: "conversation_id", op: "eq", value: "conv:tcp:1" }],
      select: ["type", "time_ms", "frame_number"],
      order_by: [{ field: "time_ms", direction: "asc" }],
    });
    const types = result.items.map((i) => i.type);
    expect(types.filter((t) => t === "tcp_missing_segment")).toHaveLength(1);
    expect(types.filter((t) => t === "tcp_dup_ack")).toHaveLength(3);
    expect(types.filter((t) => t === "tcp_zero_window")).toHaveLength(1);
    expect(types).toContain("tcp_retransmission"); // 快速重传（variant=fast）
    const ms = await session.inspect("conv:tcp:1");
    expect(ms.conversation.metrics.missing_segment_count).toBe(1);
  });

  it("X3: out_of_order fires on late first-copy segment", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [
        { field: "conversation_id", op: "eq", value: "conv:tcp:2" },
        { field: "type", op: "eq", value: "tcp_out_of_order" },
      ],
    });
    expect(result.total).toBe(1);
    expect(result.items[0]!.detection ?? true).toBeTruthy();
  });

  it("missing_segment attributes carry gap_bytes and origin", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [
        { field: "conversation_id", op: "eq", value: "conv:tcp:1" },
        { field: "type", op: "eq", value: "tcp_missing_segment" },
      ],
    });
    const full = await session.ensureExtraction();
    const evt = full.events.find(
      (e) => e.conversation_id === "conv:tcp:1" && e.type === "tcp_missing_segment",
    )!;
    expect(evt.attributes.gap_bytes).toBe(100);
    expect(evt.attributes.origin).toBe("mid_stream");
    void result;
  });

  it("mid-capture: no spurious lost_segment events when tshark reports none (regression guard)", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-mid-lost-"));
    cacheDirs.push(dir);
    const s = await TrafficSession.open(
      path.resolve(__dirname, "../../../fixtures/mid-capture.pcap"),
      { cacheDir: dir, autoDownload: false },
    );
    const full = await s.ensureExtraction();
    // tshark 在该场景（无 gap 证据）不标 lost_segment；插件不得凭空产生事件
    expect(full.events.filter((e) => e.type === "tcp_missing_segment")).toHaveLength(0);
  });

  it("rtt metrics: median/max from ack_rtt samples", async () => {
    const conv = (await session.query({
      scope: "conversation",
      where: [{ field: "conversation_id", op: "eq", value: "conv:tcp:0" }],
      select: ["rtt_median_ms", "rtt_max_ms", "throughput_bps"],
    })).result.items[0]!;
    // X1 节奏：握手 4ms + 数据样本 12ms / 25ms
    expect(conv.rtt_median_ms).toBeGreaterThan(3);
    expect(conv.rtt_max_ms).toBeGreaterThanOrEqual(20);
    expect(conv.throughput_bps).toBeGreaterThan(1000);
  });

  it("dup_ack events carry dup_ack_count series 1..3", async () => {
    const full = await session.ensureExtraction();
    const counts = full.events
      .filter((e) => e.conversation_id === "conv:tcp:1" && e.type === "tcp_dup_ack")
      .map((e) => e.attributes.dup_ack_count);
    expect(counts).toEqual([1, 2, 3]);
  });
});
