#!/usr/bin/env node
/**
 * 端到端验证「首次运行时下载」链路：
 *   ensurePinnedInstalled() → 下载 dmg → sha256 校验 → hdiutil 解包 → strip quarantine
 *   → resolve() 命中 pinned → 用 pin 版 tshark 跑一次真实抽取。
 *
 * 用法：node scripts/verify-pinned-download.mjs
 * 缓存目录：/tmp/traffic-pinned-verify（重复运行跳过下载）
 */
import { rm } from "node:fs/promises";
import path from "node:path";
import { TrafficSession, TsharkBackend } from "../packages/traffic-core/dist/index.js";

const backendsDir = "/tmp/traffic-pinned-verify/backends";

console.log("[1/4] ensurePinnedInstalled() …");
const backend = new TsharkBackend({ backendsDir });
await backend.ensurePinnedInstalled();

console.log("[2/4] resolve() …");
const resolved = await backend.resolve();
console.log(`      source=${resolved.source} version=${resolved.version} tshark=${resolved.tsharkPath}`);
if (resolved.source !== "pinned") throw new Error(`expected source=pinned, got ${resolved.source}`);

console.log("[3/4] run pinned tshark on fixture …");
const fixture = path.resolve(process.argv[2] ?? "fixtures/web-session.pcap");
const session = await TrafficSession.open(fixture, {
  backendsDir,
  cacheDir: "/tmp/traffic-pinned-verify/cache",
});
console.log(`      capture=${session.capture.capture_id} packets=${session.capture.packet_count} backend=${session.capture.backend.version}`);
if (session.capture.backend.version !== resolved.version) {
  throw new Error("session backend version mismatch");
}

console.log("[4/4] one query to prove extraction works …");
const { result } = await session.query({
  scope: "conversation",
  where: [{ field: "retransmission_count", op: "gt", value: 0 }],
  select: ["conversation_id", "retransmission_count"],
});
console.log(`      ${JSON.stringify(result)}`);

await rm("/tmp/traffic-pinned-verify/cache", { recursive: true, force: true });
console.log("\nOK — pinned download path verified end-to-end.");
