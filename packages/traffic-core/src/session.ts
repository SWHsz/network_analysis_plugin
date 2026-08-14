import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  AuditMetadata,
  BoundedResult,
  Capture,
  Conversation,
  TrafficEvent,
} from "./types.js";
import { TsharkBackend, type BackendConfig } from "./backend/provider.js";
import { resolveCacheRoot } from "./cachedir.js";
import { fingerprintFile, PLUGIN_VERSION, queryHash } from "./util.js";
import { parseCapinfosTsv, parseZStats, type LightIndex } from "./indexer.js";
import { ExtractionState, extractionArgs, type Extraction } from "./events/extract.js";
import { executeQuery } from "./query/engine.js";
import { shapeAggregateEvidence } from "./shaper.js";
import type { TrafficQuery } from "./query/ast.js";

export interface SessionOptions extends BackendConfig {
  cacheDir?: string;
}

export interface OverviewResult {
  capture: Capture;
  protocol_distribution: LightIndex["protocol_hierarchy"];
  conversation_counts: { tcp: number; udp: number };
  top_conversations_by_bytes: LightIndex["conversations"];
  audit: AuditMetadata;
}

export interface TimelineOptions {
  limit?: number;
}

export interface InspectResult {
  conversation: Conversation;
  timeline: BoundedResult<TrafficEvent>;
  aggregates: {
    retransmissions: { count: number; evidence: ReturnType<typeof shapeAggregateEvidence> };
  };
  audit: AuditMetadata;
}

export interface QueryResult {
  result: BoundedResult<Record<string, unknown>>;
  audit: AuditMetadata;
}

interface CacheVersion {
  plugin_version: string;
  tshark_version: string;
}

/**
 * TrafficSession —— 对外的分析门面。
 *
 * 典型流程：open → overview → query(scope=conversation) → inspect → query(scope=event)。
 * index 与事件抽取均按 capture_id 落盘缓存，且以 (plugin_version, tshark_version)
 * 为新鲜度 key，版本变化自动重建。
 */
export class TrafficSession {
  private indexPromise: Promise<LightIndex> | undefined;
  private extractionPromise: Promise<Extraction> | undefined;
  private readonly commands: string[] = [];

  private constructor(
    public readonly capture: Capture,
    private readonly backend: TsharkBackend,
    private readonly captureDir: string,
  ) {}

  static async open(pcapPath: string, opts: SessionOptions = {}): Promise<TrafficSession> {
    const absolute = path.resolve(pcapPath);
    let size: number;
    try {
      size = (await stat(absolute)).size;
    } catch (err) {
      throw new Error(`cannot read capture file '${absolute}': ${(err as Error).message}`);
    }

    const backend = new TsharkBackend(opts);
    const resolved = await backend.resolve();

    const captureId = await fingerprintFile(absolute, size);
    const cacheRoot = resolveCacheRoot(opts.cacheDir);
    const captureDir = path.join(cacheRoot, "captures", `cap_${captureId}`);
    await mkdir(captureDir, { recursive: true });

    // capinfos 元数据（快）
    const capinfosRaw = await backend.capinfos(absolute);
    const capinfos = parseCapinfosTsv(capinfosRaw);

    const capture: Capture = {
      capture_id: `cap_${captureId}`,
      path: absolute,
      format: capinfos.format,
      size_bytes: size,
      first_packet_epoch: capinfos.start_epoch,
      last_packet_epoch: capinfos.end_epoch,
      duration_ms: capinfos.duration_s * 1000,
      packet_count: capinfos.packet_count,
      backend: { name: "tshark", version: resolved.version },
      plugin_version: PLUGIN_VERSION,
    };

    const session = new TrafficSession(capture, backend, captureDir);
    session.commands.push(`${resolved.capinfosPath} -T -t -u -c -d -a -e ${absolute}`);

    await session.pruneStaleArtifacts();
    return session;
  }

  /** 删除版本不匹配的缓存产物（重命名/升级后自动重建） */
  private async pruneStaleArtifacts(): Promise<void> {
    const expected = `${PLUGIN_VERSION}+tshark${this.capture.backend.version}`;
    const current = await this.readVersionMarker();
    if (current && current !== expected) {
      await rm(path.join(this.captureDir, "index.json"), { force: true });
      await rm(path.join(this.captureDir, "events.json"), { force: true });
      await rm(path.join(this.captureDir, "version"), { force: true });
    }
    if (!current) {
      await writeFile(path.join(this.captureDir, "version"), expected, "utf8");
    }
  }

  private async readVersionMarker(): Promise<string | undefined> {
    try {
      return (await readFile(path.join(this.captureDir, "version"), "utf8")).trim();
    } catch {
      return undefined;
    }
  }

  /** 轻量索引（-z conv/phs 单遍统计），带缓存与并发去重 */
  async ensureIndex(): Promise<LightIndex> {
    this.indexPromise ??= (async () => {
      const cachedPath = path.join(this.captureDir, "index.json");
      try {
        const cached = JSON.parse(await readFile(cachedPath, "utf8")) as LightIndex;
        if (cached.plugin_version === PLUGIN_VERSION && cached.tshark_version === this.capture.backend.version) {
          return cached;
        }
      } catch {
        /* 无缓存或损坏，重建 */
      }
      const res = await this.backend.runTshark([
        "-r",
        this.capture.path,
        "-n",
        "-q",
        "-z",
        "io,phs",
        "-z",
        "conv,tcp",
        "-z",
        "conv,udp",
      ]);
      this.commands.push(res.command);
      const index = parseZStats(res.stdout, {
        format: this.capture.format,
        packet_count: this.capture.packet_count,
        data_size_bytes: 0,
        duration_s: this.capture.duration_ms / 1000,
        start_epoch: this.capture.first_packet_epoch,
        end_epoch: this.capture.last_packet_epoch,
      }, this.capture.backend.version);
      await writeFile(cachedPath, JSON.stringify(index), "utf8");
      return index;
    })();
    return this.indexPromise;
  }

  /** 事件抽取（单遍 -T fields 全量），带缓存与并发去重 */
  async ensureExtraction(): Promise<Extraction> {
    this.extractionPromise ??= (async () => {
      const cachedPath = path.join(this.captureDir, "events.json");
      try {
        const cached = JSON.parse(await readFile(cachedPath, "utf8")) as Extraction;
        if (cached.plugin_version === PLUGIN_VERSION && cached.tshark_version === this.capture.backend.version) {
          return cached;
        }
      } catch {
        /* 无缓存或损坏，重建 */
      }
      const state = new ExtractionState();
      const { command } = await this.backend.streamTsharkLines(
        extractionArgs(this.capture.path),
        (line) => state.feed(line),
      );
      this.commands.push(command);
      const extraction = state.finish(this.capture.backend.version);
      await writeFile(cachedPath, JSON.stringify(extraction), "utf8");
      return extraction;
    })();
    return this.extractionPromise;
  }

  async overview(): Promise<OverviewResult> {
    const index = await this.ensureIndex();
    const byBytes = [...index.conversations].sort(
      (a, b) => b.bytes_a_to_b + b.bytes_b_to_a - (a.bytes_a_to_b + a.bytes_b_to_a),
    );
    return {
      capture: this.capture,
      protocol_distribution: index.protocol_hierarchy,
      conversation_counts: {
        tcp: index.conversations.filter((c) => c.transport === "tcp").length,
        udp: index.conversations.filter((c) => c.transport === "udp").length,
      },
      top_conversations_by_bytes: byBytes.slice(0, 10),
      audit: this.audit(),
    };
  }

  async query(q: TrafficQuery): Promise<QueryResult> {
    const extraction = await this.ensureExtraction();
    const result = executeQuery(q, extraction.conversations, extraction.events);
    return { result, audit: this.audit(q) };
  }

  async inspect(conversationId: string, timelineOpts: TimelineOptions = {}): Promise<InspectResult> {
    const extraction = await this.ensureExtraction();
    const conversation = extraction.conversations.find((c) => c.conversation_id === conversationId);
    if (!conversation) {
      const known = extraction.conversations.slice(0, 20).map((c) => c.conversation_id);
      throw new Error(
        `unknown conversation '${conversationId}'. Known (first 20): ${known.join(", ")}`,
      );
    }
    const convEvents = extraction.events.filter((e) => e.conversation_id === conversationId);
    const limit = Math.min(timelineOpts.limit ?? 200, 500);
    const timeline: BoundedResult<TrafficEvent> = {
      returned: Math.min(convEvents.length, limit),
      total: convEvents.length,
      offset: 0,
      truncated: convEvents.length > limit,
      items: convEvents.slice(0, limit),
    };
    const retransFrames = convEvents
      .filter((e) => e.type === "tcp_retransmission")
      .map((e) => (e.evidence.kind === "frame" ? e.evidence.frame_number : 0));
    return {
      conversation,
      timeline,
      aggregates: {
        retransmissions: {
          count: retransFrames.length,
          evidence: shapeAggregateEvidence(retransFrames),
        },
      },
      audit: this.audit(),
    };
  }

  audit(q?: TrafficQuery): AuditMetadata {
    return {
      capture_id: this.capture.capture_id,
      query_hash: q ? queryHash(this.capture.capture_id, q) : "",
      backend: "tshark",
      backend_version: this.capture.backend.version,
      plugin_version: PLUGIN_VERSION,
      backend_commands: this.commands,
    };
  }
}
