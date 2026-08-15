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
import { FrameTableBuilder, framesArgs, type FrameRecord, type FrameTable } from "./frames.js";
import { rawQuery, type RawQueryOptions, type RawQueryResult, type RawQueryError } from "./raw.js";
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

export interface EvidenceOptions {
  /** 直接指定帧号 */
  frames?: number[];
  /** 或指定 event_id（取其 evidence frame） */
  event_ids?: string[];
}

export interface EvidenceResult {
  requested: number;
  returned: number;
  truncated: boolean;
  /** 请求中不存在于捕获里的帧号 */
  missing_frames: number[];
  frames: FrameRecord[];
  audit: AuditMetadata;
}

export type TimeseriesMetric = "bytes" | "packets" | "window" | "rtt" | "tls_bytes";

export type { RawQueryOptions, RawQueryResult, RawQueryError } from "./raw.js";

/** v0.4：HTTP 事务（waterfall 的一行） */
export interface HttpTransaction {
  conversation_id: string;
  method: string | null;
  host: string | null;
  uri: string | null;
  status_code: number | null;
  request_time_ms: number;
  response_time_ms: number | null;
  /** http.time（请求→应答），未配对为 null */
  resp_time_ms: number | null;
  request_frame: number;
  response_frame: number | null;
}

export interface HttpTimelineResult {
  conversation_id: string | null; // null = 整个 capture
  transactions: HttpTransaction[];
  unmatched_requests: number;
  audit: AuditMetadata;
}

export interface TimeseriesBin {
  t_start_ms: number;
  /** bytes/packets 为计数；window/rtt 为该箱中位数（无样本为 null） */
  forward: number | null;
  reverse: number | null;
}

export interface TimeseriesResult {
  conversation_id: string;
  metric: TimeseriesMetric;
  requested_bin_ms: number;
  /** 超过 500 箱时自动加倍加宽（sampled=true） */
  bin_ms: number;
  bins_count: number;
  sampled: boolean;
  bins: TimeseriesBin[];
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

  private framesPromise: Promise<FrameTable> | undefined;

  /**
   * per-frame 原始字段表（traffic_evidence / traffic_timeseries 数据源）。
   * 与事件抽取分开的第二次懒遍历（字段集更大），同样按版本缓存。
   */
  async ensureFrames(): Promise<FrameTable> {
    this.framesPromise ??= (async () => {
      const cachedPath = path.join(this.captureDir, "frames.json");
      try {
        const cached = JSON.parse(await readFile(cachedPath, "utf8")) as FrameTable;
        if (cached.plugin_version === PLUGIN_VERSION && cached.tshark_version === this.capture.backend.version) {
          return cached;
        }
      } catch {
        /* 无缓存或损坏，重建 */
      }
      const builder = new FrameTableBuilder();
      const { command } = await this.backend.streamTsharkLines(
        framesArgs(this.capture.path),
        (line) => builder.feed(line),
      );
      this.commands.push(command);
      const table = builder.finish(this.capture.backend.version);
      await writeFile(cachedPath, JSON.stringify(table), "utf8");
      return table;
    })();
    return this.framesPromise;
  }

  /** traffic_evidence：帧级原始记录（固定字段集、有界），供模型复核 claim */
  async evidence(opts: EvidenceOptions): Promise<EvidenceResult> {
    const EVIDENCE_FRAME_CAP = 200;
    let requested: number[] = [];
    if (opts.event_ids && opts.event_ids.length > 0) {
      const extraction = await this.ensureExtraction();
      const byId = new Map(extraction.events.map((e) => [e.event_id, e]));
      for (const id of opts.event_ids) {
        const evt = byId.get(id);
        if (evt && evt.evidence.kind === "frame") requested.push(evt.evidence.frame_number);
      }
    } else {
      requested = [...(opts.frames ?? [])];
    }
    const unique = [...new Set(requested)].sort((a, b) => a - b);

    const table = await this.ensureFrames();
    const byFrame = new Map(table.frames.map((f) => [f.frame_number, f]));
    const missing: number[] = [];
    const found: FrameRecord[] = [];
    for (const fn of unique) {
      const rec = byFrame.get(fn);
      if (rec) found.push(rec);
      else missing.push(fn);
    }
    const truncated = found.length > EVIDENCE_FRAME_CAP;
    return {
      requested: unique.length,
      returned: Math.min(found.length, EVIDENCE_FRAME_CAP),
      truncated,
      missing_frames: missing,
      frames: found.slice(0, EVIDENCE_FRAME_CAP),
      audit: this.audit(),
    };
  }

  /** traffic_timeseries：服务端分箱聚合（bytes/packets/window/rtt，双向） */
  async timeseries(
    conversationId: string,
    metric: TimeseriesMetric,
    binMs = 100,
  ): Promise<TimeseriesResult> {
    const extraction = await this.ensureExtraction();
    const conversation = extraction.conversations.find((c) => c.conversation_id === conversationId);
    if (!conversation) {
      throw new Error(
        `unknown conversation '${conversationId}'. Known (first 20): ${extraction.conversations
          .slice(0, 20)
          .map((c) => c.conversation_id)
          .join(", ")}`,
      );
    }
    if (!Number.isFinite(binMs) || binMs < 10 || binMs > 5000) {
      throw new Error("bin_ms must be in [10, 5000]");
    }

    const table = await this.ensureFrames();
    const streamId = Number(conversationId.split(":")[2]);
    const convFrames = table.frames.filter(
      (f) => f.transport === conversation.transport && f.stream_id === streamId,
    );
    const isForward = (f: FrameRecord): boolean =>
      f.ip_src === conversation.initiator.ip && f.src_port === conversation.initiator.port;

    const durationMs = convFrames.length
      ? convFrames[convFrames.length - 1]!.time_ms - convFrames[0]!.time_ms
      : 0;
    // 自动加宽：超过 500 箱时 bin 翻倍（sampled 标注）
    let width = binMs;
    let sampled = false;
    while (durationMs / width > 500) {
      width *= 2;
      sampled = true;
    }

    const binsCount = Math.max(1, Math.ceil(durationMs / width) + 1);
    const acc = Array.from({ length: binsCount }, () => ({
      f: [] as number[],
      r: [] as number[],
    }));
    for (const f of convFrames) {
      const idx = Math.min(binsCount - 1, Math.max(0, Math.floor(f.time_ms / width)));
      const side = isForward(f) ? acc[idx]!.f : acc[idx]!.r;
      if (metric === "bytes") side.push(f.len);
      else if (metric === "packets") side.push(1);
      else if (metric === "window") {
        if (f.tcp_window !== null) side.push(f.tcp_window);
      } else if (metric === "tls_bytes") {
        if (f.tls_record_bytes !== null) side.push(f.tls_record_bytes);
      } else if (f.ack_rtt_ms !== null) side.push(f.ack_rtt_ms);
    }

    const summarize = (values: number[]): number | null => {
      if (values.length === 0) return null;
      if (metric === "bytes" || metric === "packets") return values.reduce((a, b) => a + b, 0);
      const sorted = [...values].sort((a, b) => a - b);
      const mid = Math.floor(sorted.length / 2);
      const v =
        sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
      return Number(v.toFixed(3));
    };

    const bins: TimeseriesBin[] = acc.map((b, i) => ({
      t_start_ms: i * width,
      forward: summarize(b.f),
      reverse: summarize(b.r),
    }));

    return {
      conversation_id: conversationId,
      metric,
      requested_bin_ms: binMs,
      bin_ms: width,
      bins_count: binsCount,
      sampled,
      bins,
      audit: this.audit(),
    };
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
    const frames = q.scope === "frame" ? (await this.ensureFrames()).frames : undefined;
    const result = executeQuery(q, extraction.conversations, extraction.events, frames);
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

  /** traffic_raw_query：长尾查询的有界逃生口（字段词表校验 + 结构化 argv） */
  rawQuery(opts: RawQueryOptions): Promise<RawQueryResult> {
    return rawQuery(this.backend, this.capture.path, opts, this.audit());
  }

  /**
   * traffic_http_timeline：HTTP 事务配对（waterfall 语义宏）。
   * 同 conversation 内按时间序 FIFO 配对 request→response（response 为反向首个），
   * 未配对的 request 保留（response 字段为 null）。
   */
  async httpTimeline(conversationId?: string): Promise<HttpTimelineResult> {
    const extraction = await this.ensureExtraction();
    const httpEvents = extraction.events.filter((e) => {
      if (e.type !== "http_request" && e.type !== "http_response") return false;
      return conversationId ? e.conversation_id === conversationId : true;
    });

    const transactions: HttpTransaction[] = [];
    const pending: HttpTransaction[] = [];
    let unmatched = 0;
    for (const e of httpEvents) {
      if (e.type === "http_request") {
        pending.push({
          conversation_id: e.conversation_id,
          method: (e.attributes.method as string) ?? null,
          host: (e.attributes.host as string) ?? null,
          uri: (e.attributes.uri as string) ?? null,
          status_code: null,
          request_time_ms: e.time_ms,
          response_time_ms: null,
          resp_time_ms: null,
          request_frame: e.evidence.kind === "frame" ? e.evidence.frame_number : 0,
          response_frame: null,
        });
      } else {
        const req = pending.shift();
        if (!req) {
          continue; // 无待配对请求的响应（如 4xx 前的探测响应）
        }
        transactions.push({
          ...req,
          status_code: (e.attributes.status_code as number) ?? null,
          response_time_ms: e.time_ms,
          resp_time_ms: (e.attributes.resp_time_ms as number) ?? Number((e.time_ms - req.request_time_ms).toFixed(3)),
          response_frame: e.evidence.kind === "frame" ? e.evidence.frame_number : null,
        });
      }
    }
    unmatched = pending.length;
    transactions.push(...pending.map((p) => ({ ...p, response_time_ms: null, response_frame: null })));
    transactions.sort((a, b) => a.request_time_ms - b.request_time_ms);

    return { conversation_id: conversationId ?? null, transactions, unmatched_requests: unmatched, audit: this.audit() };
  }

  audit(q?: TrafficQuery): AuditMetadata {
    return {
      capture_id: this.capture.capture_id,
      query_hash: q ? queryHash(this.capture.capture_id, q) : "",
      backend: "tshark",
      backend_version: this.capture.backend.version,
      plugin_version: PLUGIN_VERSION,
      backend_commands: this.commands,
      render_chars: 0,
    };
  }
}
