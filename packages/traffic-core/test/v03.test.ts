import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { runBinary } from "../src/backend/spawn.js";

const FIXTURE = path.resolve(__dirname, "../../../fixtures/web-session.pcap"); // 含完整 TLS 握手（CH 带 SNI 场景）

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

describe("v0.3: tls attrs / frame scope / raw query", { skip: skip || undefined }, () => {
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-v03-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("tls handshake attrs: version/cipher/sni populated", async () => {
    const ext = await session.ensureExtraction();
    const ch = ext.events.find((e) => e.type === "tls_client_hello");
    const sh = ext.events.find((e) => e.type === "tls_server_hello");
    // fixture 的 ClientHello 未携带 SNI 扩展 → null（语义正确）
    expect(ch!.attributes.version).toBe("0x0303");
    expect(ch!.attributes.cipher_count).toBe(1);
    expect(sh!.attributes).toMatchObject({ version: "0x0303", cipher: "0x1301" });
  });

  it("metrics: payload vs frame-len bytes differ; tls_app_bytes counts records", async () => {
    const ext = await session.ensureExtraction();
    const conv = ext.conversations.find((c) => c.conversation_id === "conv:tcp:0")!;
    expect(conv.metrics.payload_bytes_forward).toBeLessThan(conv.bytes.forward); // frame.len 含头部
    expect(conv.metrics.payload_bytes_forward).toBeGreaterThan(0);
    // conv:tcp:0 含 ClientHello(45B record) + ServerHello(42B record) = 87
    expect(conv.metrics.tls_app_bytes).toBe(87);
    const http = ext.conversations.find((c) => c.conversation_id === "conv:tcp:1")!;
    expect(http.metrics.tls_app_bytes).toBe(0); // 明文 HTTP
  });

  it("frame scope: filter/sort/paginate over cached frame table", async () => {
    const { result } = await session.query({
      scope: "frame",
      where: [
        { field: "conversation_id", op: "eq", value: "conv:tcp:0" },
        { field: "tcp_len", op: "gt", value: 0 },
      ],
      select: ["frame_number", "ip_src", "tcp_len", "tcp_flags"],
      order_by: [{ field: "tcp_len", direction: "desc" }],
    });
    expect(result.total).toBe(9); // 5 个原发段 + 重传副本 + TLS 记录段
    expect(result.items[0]!.tcp_len).toBe(1440); // 服务端数据段
    expect(result.items.every((i) => i.ip_src === "192.168.1.4" || i.ip_src === "142.250.74.14")).toBe(true);
    // 默认紧凑投影
    const def = await session.query({ scope: "frame", limit: 3 });
    expect(Object.keys(def.result.items[0]!).sort()).toEqual(
      ["analysis", "frame_number", "ip_dst", "ip_src", "tcp_flags", "tcp_len", "time_ms"].sort(),
    );
  });

  it("frame scope unknown field error lists whitelist", async () => {
    await expect(
      session.query({ scope: "frame", where: [{ field: "tcp.stream", op: "eq", value: 0 }] }),
    ).rejects.toThrow(/unknown field 'tcp\.stream' for scope 'frame'/);
  });

  it("raw query: validated fields, bounded rows, filter applied", async () => {
    const rq = await session.rawQuery({
      display_filter: "dns",
      fields: ["dns.qry.name", "dns.flags.rcode"],
      limit: 10,
    });
    expect(rq.fields[0]).toBe("frame.number");
    expect(rq.returned).toBe(4);
    expect(rq.rows.some((r) => r[1] === "nonexistent.example" && r[2] === "3")).toBe(true);
    expect(rq.audit.backend_commands.length).toBeGreaterThan(0);
  });

  it("raw query rejects unknown fields with helpful error", async () => {
    await expect(
      session.rawQuery({ fields: ["tls.handshake.extensions.server_name"] }),
    ).rejects.toThrow(/unknown tshark field/i);
  });

  it("raw query suggests nearest field names (v0.3.1)", async () => {
    // 会话实测的自纠案例：点分 SNI 名 → 建议下划线形式
    const err = await session
      .rawQuery({ fields: ["tls.handshake.extensions.server_name"] })
      .catch((e: Error) => e.message);
    expect(err).toContain("tls.handshake.extensions_server_name");
  });

  it("raw query surfaces invalid display_filter fields with suggestions (v0.3.1)", async () => {
    const err = await session
      .rawQuery({ display_filter: "tcp.analysis.missing_segment > 0", fields: ["frame.number"] })
      .catch((e: Error) => e.message);
    expect(err).toMatch(/invalid field\(s\) in display_filter|unknown tshark field/i);
  });

  it("raw query rejects bad filter characters and out-of-range limit", async () => {
    await expect(session.rawQuery({ display_filter: "; rm -rf /", fields: ["frame.len"] })).rejects.toThrow(
      /unsupported characters/i,
    );
    await expect(session.rawQuery({ fields: ["frame.len"], limit: 501 })).rejects.toThrow(/limit/i);
    await expect(session.rawQuery({ fields: [] })).rejects.toThrow(/empty/i);
  });

  it("timeseries tls_bytes sums record lengths per bin", async () => {
    const ts = await session.timeseries("conv:tcp:0", "tls_bytes", 100);
    const total = ts.bins.reduce((a, b) => a + (b.forward ?? 0) + (b.reverse ?? 0), 0);
    expect(total).toBe(87); // 45 + 42
  });
});
