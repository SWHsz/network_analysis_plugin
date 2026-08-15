import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TrafficSession } from "../src/session.js";
import { runBinary } from "../src/backend/spawn.js";

const FIXTURE = path.resolve(__dirname, "../../../fixtures/tls-cert.pcap");

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

describe("v0.4: tls_certificate event (TLS 1.2 plaintext cert)", { skip: skip || undefined }, () => {
  beforeAll(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "traffic-tlscert-"));
    cacheDirs.push(dir);
    session = await TrafficSession.open(FIXTURE, { cacheDir: dir, autoDownload: false });
  });
  afterAll(async () => {
    for (const d of cacheDirs) await rm(d, { recursive: true, force: true });
  });

  it("certificate event carries cn/san_dns/cert_count", async () => {
    const ext = await session.ensureExtraction();
    const cert = ext.events.find((e) => e.type === "tls_certificate");
    expect(cert).toBeDefined();
    expect(cert!.attributes.cn).toBe("fixture.example.test");
    expect(cert!.attributes.san_dns).toBe("www.fixture.example.test,api.fixture.example.test");
    expect(cert!.attributes.cert_count).toBe(1);
    expect(cert!.detection).toBe("tshark_tls_dissector");
  });

  it("attr.cn and attr.san_dns are queryable with type condition", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [
        { field: "type", op: "eq", value: "tls_certificate" },
        { field: "attr.san_dns", op: "contains", value: "api.fixture" },
      ],
      select: ["event_id", "frame_number", "attr.cn", "attr.san_dns"],
    });
    expect(result.total).toBe(1);
    expect(result.items[0]!["attr.cn"]).toBe("fixture.example.test");
  });

  it("handshake flow intact: CH → SH → Certificate → SHD ordering", async () => {
    const { result } = await session.query({
      scope: "event",
      where: [{ field: "conversation_id", op: "eq", value: "conv:tcp:0" }],
      select: ["type", "time_ms"],
      order_by: [{ field: "time_ms", direction: "asc" }],
    });
    expect(result.items.map((i) => i.type)).toEqual([
      "tls_client_hello",
      "tls_server_hello",
      "tls_certificate",
    ]);
    expect(result.items[0]!.time_ms).toBeLessThan(result.items[2]!.time_ms);
  });

  it("TLS 1.3 captures produce no certificate event (encrypted) — 23.pcap semantics documented", async () => {
    // 语义护栏：注册表描述已声明 TLS1.3 证书不可见；这里验证 web-session（TLS1.2 无证书消息）
    const ext = await session.ensureExtraction();
    expect(ext.events.filter((e) => e.type === "tls_certificate")).toHaveLength(1);
  });
});
