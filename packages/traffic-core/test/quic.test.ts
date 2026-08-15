import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { runBinary } from "../src/backend/spawn.js";

const QUIC_FIXTURE = path.resolve(__dirname, "../../../fixtures/quic-sample.pcapng");
const HTTP_FIXTURE = path.resolve(__dirname, "../../../fixtures/edge-cases.pcap");

const skip = !(await (async () => {
  try {
    await runBinary("tshark", ["--version"], { timeoutMs: 10_000 });
    return true;
  } catch {
    return false;
  }
})());

const cacheDirs: string[] = [];

describe("v0.4: QUIC stream model (real quic_follow_multistream capture)", { skip: skip || undefined }, () => {
  let session: TrafficSession;
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-quic-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(QUIC_FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("conversation carries quic tag and stream count", async () => {
    const { result } = await session.query({
      scope: "conversation",
      select: ["conversation_id", "quic_stream_count", "protocol_tags"],
    });
    expect(result.total).toBe(1);
    expect(result.items[0]!.quic_stream_count).toBe(28);
    expect(result.items[0]!.protocol_tags).toContain("quic");
  });

  it("stream scope: filter/sort over aggregated streams", async () => {
    const { result } = await session.query({
      scope: "stream",
      where: [{ field: "bytes", op: "gt", value: 100000 }],
      select: ["stream_id", "stream_direction", "initiator", "bytes", "packets"],
      order_by: [{ field: "bytes", direction: "desc" }],
    });
    expect(result.total).toBe(2);
    expect(result.items[0]!.bytes).toBeGreaterThan(100000);
    // 默认紧凑投影包含全部 7 列
    const def = await session.query({ scope: "stream", limit: 1 });
    expect(Object.keys(def.result.items[0]!).length).toBe(7);
  });

  it("streams carry frame evidence (bounded at 50)", async () => {
    const ext = await session.ensureExtraction();
    const streams = ext.conversations[0]!.streams!;
    expect(streams.length).toBe(28);
    expect(streams.every((s) => s.evidence_frames.length <= 50)).toBe(true);
    expect(streams.every((s) => s.evidence_frames.length > 0)).toBe(true);
  });

  it("unknown stream field error lists whitelist", async () => {
    await expect(
      session.query({ scope: "stream", where: [{ field: "quic.stream_id", op: "eq", value: 0 }] }),
    ).rejects.toThrow(/unknown field 'quic\.stream_id' for scope 'stream'/);
  });
});

describe("v0.4: traffic_http_timeline (edge-cases fixture)", { skip: skip || undefined }, () => {
  let session: TrafficSession;
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-h2t-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(HTTP_FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("pairs request→response with times and frames", async () => {
    const tl = await session.httpTimeline();
    expect(tl.transactions).toHaveLength(1);
    const t = tl.transactions[0]!;
    expect(t).toMatchObject({
      method: "GET",
      host: "edge.test",
      uri: "/data",
      status_code: 200,
      request_frame: 4,
      response_frame: 7,
    });
    expect(t.resp_time_ms).toBe(22);
    expect(t.request_time_ms).toBeLessThan(t.response_time_ms!);
    expect(tl.unmatched_requests).toBe(0);
  });

  it("per-conversation filter works", async () => {
    const tl = await session.httpTimeline("conv:tcp:1");
    expect(tl.transactions).toHaveLength(0); // conv:tcp:1 无 HTTP
  });
});
