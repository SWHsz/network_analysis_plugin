import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open as fsOpen } from "node:fs/promises";

export const PLUGIN_VERSION = "0.5.0";

/**
 * 采样内容指纹：size + 头部 + 尾部 + 均匀分布的内部块。
 * 对大文件避免全量 SHA256 的成本；碰撞概率对缓存用途足够低。
 */
export async function fingerprintFile(path: string, size: number): Promise<string> {
  const hash = createHash("sha256");
  hash.update(`size:${size}\n`);

  const HEAD = 256 * 1024;
  const TAIL = 256 * 1024;
  const BLOCK = 64 * 1024;
  const interiorCount = Math.min(8, Math.max(0, Math.ceil(size / (1024 * 1024))));
  const ranges: Array<[number, number]> = [];
  ranges.push([0, Math.min(HEAD, size)]);
  if (size > TAIL) ranges.push([size - TAIL, size]);
  for (let i = 1; i <= interiorCount; i++) {
    const pos = Math.floor((size / (interiorCount + 1)) * i);
    ranges.push([pos, Math.min(pos + BLOCK, size)]);
  }

  const fh = await fsOpen(path, "r");
  try {
    for (const [start, end] of ranges) {
      const len = end - start;
      if (len <= 0) continue;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, start);
      hash.update(buf);
    }
  } finally {
    await fh.close();
  }
  return hash.digest("hex").slice(0, 16);
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (c) => hash.update(c));
    stream.on("end", () => resolve());
    stream.on("error", reject);
  });
  return hash.digest("hex");
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function queryHash(captureId: string, query: unknown): string {
  return createHash("sha256").update(`${captureId}\n${canonicalJson(query)}`).digest("hex").slice(0, 16);
}

/**
 * 解析 capinfos 输出的固定格式日期 "1970-01-01 08:00:00.000000"（本地时区墙钟），
 * 返回 epoch 秒。getTimezoneOffset() 对 UTC+8 返回 -480（分钟，以西为负），
 * 故 epoch = UTC(墙钟) + offset。
 */
export function parseCapinfosDate(s: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(s.trim());
  if (!m) throw new Error(`unrecognized capinfos timestamp: ${JSON.stringify(s)}`);
  const frac = m[7];
  const ms = frac ? Number((Number(`0.${frac}`) * 1000).toFixed(3)) : 0;
  return (
    Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!, ms) +
    new Date().getTimezoneOffset() * 60_000
  ) / 1000;
}
