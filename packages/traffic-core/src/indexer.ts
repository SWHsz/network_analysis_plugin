import { parseCapinfosDate, PLUGIN_VERSION } from "./util.js";

/** 轻量索引：打开 capture 后一次 `-z` 统计遍历的产物（缓存于 index.json） */
export interface LightIndex {
  plugin_version: string;
  tshark_version: string;
  built_at: string;
  capinfos: {
    format: "pcap" | "pcapng" | "unknown";
    packet_count: number;
    data_size_bytes: number;
    duration_s: number;
    start_epoch: number;
    end_epoch: number;
  };
  protocol_hierarchy: Array<{ name: string; depth: number; frames: number; bytes: number }>;
  conversations: Array<{
    transport: "tcp" | "udp";
    endpoint_a: string;
    endpoint_b: string;
    /** A→B（“->”列）；A 为左侧端点 */
    frames_a_to_b: number;
    bytes_a_to_b: number;
    frames_b_to_a: number;
    bytes_b_to_a: number;
    relative_start_s: number;
    duration_s: number;
  }>;
}

/** 解析 capinfos -T -u -t -c -d -a -e 的 TSV 输出（首行表头） */
export function parseCapinfosTsv(stdout: string): LightIndex["capinfos"] {
  const lines = stdout.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length < 2) throw new Error("capinfos produced no data rows");
  const headers = lines[0]!.split("\t");
  const values = lines[1]!.split("\t");
  const col = (name: string): string => {
    const i = headers.indexOf(name);
    if (i < 0) throw new Error(`capinfos output missing column '${name}'`);
    return values[i] ?? "";
  };
  const fileType = col("File type").toLowerCase();
  return {
    format: fileType.includes("pcapng") ? "pcapng" : fileType.includes("pcap") ? "pcap" : "unknown",
    packet_count: Number(col("Number of packets")),
    data_size_bytes: Number(col("Data size (bytes)")),
    duration_s: Number(col("Capture duration (seconds)")),
    start_epoch: parseCapinfosDate(col("Start time")),
    end_epoch: parseCapinfosDate(col("End time")),
  };
}

// tshark conv 统计的字节数是人类化格式：纯字节数（"4732 bytes"）或
// 1000 进制缩写（"137 kB"、"1.5 MB"、"2 GB"），整数部分截断显示。
const CONV_LINE =
  /^(\S+)\s*<->\s*(\S+?)\s{2,}(\d+)\s+([\d,.]+)\s*(bytes|B|kB|MB|GB|TB)\s+(\d+)\s+([\d,.]+)\s*(bytes|B|kB|MB|GB|TB)\s+(\d+)\s+([\d,.]+)\s*(bytes|B|kB|MB|GB|TB)\s+([\d.]+)\s+([\d.]+)/;

const UNIT_MULTIPLIER: Record<string, number> = {
  bytes: 1,
  B: 1,
  kB: 1_000,
  MB: 1_000_000,
  GB: 1_000_000_000,
  TB: 1_000_000_000_000,
};

function parseHumanBytes(num: string, unit: string): number {
  return Math.round(Number(num.replace(/[,.]/g, "")) * (UNIT_MULTIPLIER[unit] ?? 1));
}

const PHS_LINE = /^(\s*)([\w.]+)\s+frames:(\d+)\s+bytes:(\d+)$/;

/**
 * 解析一次 `tshark -q -z io,phs -z conv,tcp -z conv,udp` 的合并输出。
 * 各 section 以 "=" 分隔线包围。
 */
export function parseZStats(stdout: string, capinfos: LightIndex["capinfos"], tsharkVersion: string): LightIndex {
  const phs: LightIndex["protocol_hierarchy"] = [];
  const convs: LightIndex["conversations"] = [];

  const lines = stdout.split("\n");
  let section = "";
  for (const raw of lines) {
    const line = raw.replace(/\r$/, "");
    if (/^={5,}/.test(line.trim()) || line.trim().length === 0) continue;
    if (/^Protocol Hierarchy Statistics/i.test(line)) {
      section = "phs";
      continue;
    }
    if (/^TCP Conversations/i.test(line)) {
      section = "conv-tcp";
      continue;
    }
    if (/^UDP Conversations/i.test(line)) {
      section = "conv-udp";
      continue;
    }
    if (/^Filter:/i.test(line)) continue;

    if (section === "phs") {
      const m = PHS_LINE.exec(line);
      if (m) {
        phs.push({
          name: m[2]!,
          depth: Math.floor(m[1]!.length / 2),
          frames: Number(m[3]),
          bytes: Number(m[4]),
        });
      }
    } else if (section === "conv-tcp" || section === "conv-udp") {
      // 跳过表头行（含 "|<-|" 或 "Frames" 字样）
      if (line.includes("|") && !CONV_LINE.test(line.trim())) continue;
      const m = CONV_LINE.exec(line.trim());
      if (m) {
        const transport = section === "conv-tcp" ? ("tcp" as const) : ("udp" as const);
        convs.push({
          transport,
          endpoint_a: m[1]!,
          endpoint_b: m[2]!,
          frames_b_to_a: Number(m[3]),
          bytes_b_to_a: parseHumanBytes(m[4]!, m[5]!),
          frames_a_to_b: Number(m[6]),
          bytes_a_to_b: parseHumanBytes(m[7]!, m[8]!),
          relative_start_s: Number(m[12]),
          duration_s: Number(m[13]),
        });
      }
    }
  }

  return {
    plugin_version: PLUGIN_VERSION,
    tshark_version: tsharkVersion,
    built_at: new Date().toISOString(),
    capinfos,
    protocol_hierarchy: phs,
    conversations: convs,
  };
}
