/**
 * 模板派生器（RFC-002 §4.3 模板题路线）：从 ground_truth/*.gt.json 机械派生题目，
 * 覆盖能力轴 S1–S6、难度 D1–D2（备忘录 §6：S5/S7–S9 与诊断题不进派生器）。
 *
 * 纪律：
 * - gold 与 gold_evidence 只从 gt facts 推导（detection_basis=generator_intent）；
 * - canary 的 expect 由声明性规则给出（错值/错证据帧/格式错三形态轮转），
 *   再由 canary 元评测验证声明与判分器一致——不一致即阻塞；
 * - 已被手写题覆盖的实例经 SKIP 集合显式排除（排除理由=对应 question_id）；
 * - 布尔 false 实例（"未发生"类）gold_evidence 为空集：属否定性断言，
 *   证据帧集允许为空（与备忘录 §7 空集特例同一处理，校验器同步放行）；
 * - 产物为批量稿（provenance.source=generator），人工抽审后才可入库实验。
 */
import { refTarget, type JsonSchema } from "../scorer/schema.js";
import type { AnswerForm, GroundTruth, Question } from "../scorer/question.js";

type Tuple = { proto: string; src: string; sport: number; dst: string; dport: number };

const SESSION_TUPLE_DEFS: JsonSchema = {
  type: "object",
  properties: {
    proto: { enum: ["tcp", "udp"] },
    src: { type: "string" },
    sport: { type: "integer", minimum: 0, maximum: 65535 },
    dst: { type: "string" },
    dport: { type: "integer", minimum: 0, maximum: 65535 },
  },
  required: ["proto", "src", "sport", "dst", "dport"],
  additionalProperties: false,
};

function evidenceSchema(minItems: number): JsonSchema {
  return { type: "array", items: { type: "integer", minimum: 1 }, minItems, uniqueItems: true };
}

function nodeSchema(value: JsonSchema, minEvidence = 1): JsonSchema {
  return {
    type: "object",
    properties: { value, evidence: evidenceSchema(minEvidence) },
    required: ["value", "evidence"],
    additionalProperties: false,
  };
}

export interface DerivedQuestion {
  fileName: string;
  question: Question;
}

interface Ctx {
  capture: string;
  fixturePath: string;
  packetCount: number;
  seq: number;
}

interface PartialSpec {
  idSuffix: string;
  type: AnswerForm;
  text: string;
  answer_schema: JsonSchema;
  gold: Question["gold"];
  gold_evidence: Question["gold_evidence"];
  derivation: string;
  tolerance_note: string;
  gt_pointers: string[];
  steps: Array<{ n: number; tool: string; input: string; expect: string }>;
  bash: string;
  factors: Record<string, unknown>;
  difficulty: 1 | 2 | 3;
  skill: string[];
  protocols: string[];
  scenarioPack: string;
  irCoverage?: string;
}

function baseQuestion(ctx: Ctx, p: PartialSpec): DerivedQuestion {
  const difficultyLabel = `D${p.difficulty}`;
  const slug = ctx.capture.replace(/[^a-z0-9]/g, "");
  const id = `q-${slug}-${100 + ctx.seq}`;
  ctx.seq += 1;
  const question = {
    question_id: id,
    version: 1,
    capture: { fixture: ctx.capture, path: ctx.fixturePath, gt: `ground_truth/${ctx.capture}.gt.json` },
    type: p.type,
    question: p.text,
    answer_schema: p.answer_schema,
    gold: p.gold,
    gold_evidence: p.gold_evidence,
    gold_derivation: {
      gt_pointers: p.gt_pointers,
      derivation: p.derivation,
      tolerance_note: p.tolerance_note,
    },
    reference_solution: {
      steps: p.steps,
      bash_equivalent: p.bash,
      factors: p.factors,
      difficulty_derivation: `备忘录 §2：模板题固定口径 → ${difficultyLabel}；能力轴 ${p.skill.join("+")}`,
    } as Question["reference_solution"],
    tags: {
      protocols: p.protocols,
      skill: p.skill,
      difficulty: p.difficulty,
      difficulty_label: difficultyLabel,
      ir_coverage: p.irCoverage ?? "covered",
      corpus_layer: "L1",
      scenario_pack: p.scenarioPack,
    },
    provenance: { source: "generator", note: "模板派生批量稿；人工抽审后入库" },
    canary: null as unknown as Question["canary"],
  } as unknown as Question;
  return { fileName: `${id}-${p.idSuffix}.json`, question };
}

// ---- canary 机械生成（三形态轮转；expect 为声明性规则，由元评测复核） ----

const tupleKey = (t: unknown): string => {
  const x = t as Tuple;
  return `${x.proto}|${x.src}:${x.sport}>${x.dst}:${x.dport}`;
};

const BAD_FORMS = ["wrong_value", "wrong_evidence_frame", "format_error"] as const;

export function buildCanary(q: Question, variantIndex: number, packetCount: number): void {
  const goodAnswer: Record<string, unknown> = {};
  if (q.type === "set") {
    const f = Object.keys(q.gold)[0]!;
    const evMap = q.gold_evidence[f] as Record<string, number[]>;
    const elements = [...(q.gold[f]!.value as Tuple[])].map((t) => ({
      value: t,
      evidence: evMap[tupleKey(t)] ?? [],
    }));
    // 仅 unordered 打乱元素顺序（顺带验证无序比对）；ordered 保持原序
    if (q.answer_schema["x-match"] === "unordered" && elements.length > 1) {
      elements.push(elements.shift()!);
    }
    goodAnswer[f] = elements;
  } else {
    for (const [field, g] of Object.entries(q.gold)) {
      const ev = q.gold_evidence[field];
      goodAnswer[field] = { value: g.value, evidence: Array.isArray(ev) ? [...ev] : [] };
    }
  }
  q.canary = {
    known_good: {
      answer: goodAnswer,
      expect: { schema_valid: true, correctness: true, evidence_pass: true },
      note: "gold 合成答案（机械派生）",
    },
    known_bad: makeKnownBad(q, BAD_FORMS[variantIndex % 3]!, packetCount),
  };
}

function makeKnownBad(q: Question, form: "wrong_value" | "wrong_evidence_frame" | "format_error", packetCount: number): Question["canary"]["known_bad"] {
  const first = Object.keys(q.gold)[0]!;
  let emulates: string;

  if (form === "format_error") {
    const answer: Record<string, unknown> = {};
    for (const [f, g] of Object.entries(q.gold)) {
      answer[f] = f === first ? g.value : { value: g.value, evidence: plainEvidence(q, f) };
    }
    emulates = "首字段写成裸值而非 {value,evidence} 节点：违反答案契约的格式错误形态";
    return {
      answer, error_form: form, emulates,
      expect: { schema_valid: false, correctness: false, evidence_pass: false },
    };
  }

  if (form === "wrong_value") {
    // set 题：ordered 用相邻名次交换（值集不变、顺序错）；其余类型逐字段扰动
    if (q.type === "set" && q.answer_schema["x-match"] === "ordered") {
      const f = first;
      const evMap = q.gold_evidence[f] as Record<string, number[]>;
      const elements = (q.gold[f]!.value as Tuple[]).map((t) => ({
        value: t,
        evidence: evMap[tupleKey(t)] ?? [],
      }));
      if (elements.length > 1) {
        const tmp = elements[0]!;
        elements[0] = elements[1]!;
        elements[1] = tmp;
      }
      emulates = "值错形态（ordered）：成员集合正确但名次交换";
      return {
        answer: { [f]: elements }, error_form: form, emulates,
        expect: { schema_valid: true, correctness: false, evidence_pass: true },
      };
    }
    const answer: Record<string, unknown> = {};
    for (const [f, g] of Object.entries(q.gold)) {
      let v = g.value;
      if (typeof v === "number") v = v + ((g.tolerance_abs ?? 0) > 0 ? (g.tolerance_abs as number) * 2 : 1);
      else if (typeof v === "boolean") v = !v;
      else if (typeof v === "string") v = `${v}-x`;
      else if (v && typeof v === "object") v = { ...(v as Tuple), dport: (v as Tuple).dport + 1 };
      answer[f] = { value: v, evidence: plainEvidence(q, f) };
    }
    emulates = "值错形态：数值越容差偏移 / 枚举取反 / 字符串污染 / 五元组端口扰动";
    return {
      answer, error_form: form, emulates,
      expect: { schema_valid: true, correctness: false, evidence_pass: true },
    };
  }

  // wrong_evidence_frame：值正确，证据换成 gold 集之外的合法帧号
  if (q.type === "set") {
    const evMap = q.gold_evidence[first] as Record<string, number[]>;
    const elements = (q.gold[first]!.value as Tuple[]).map((t) => ({
      value: t,
      evidence: [outsideFrameOf(evMap[tupleKey(t)] ?? [], packetCount)],
    }));
    emulates = "证据帧错形态（集合逐元素）：值与名次正确但引用了各自 gold 帧集之外的帧";
    return {
      answer: { [first]: elements }, error_form: form, emulates,
      expect: { schema_valid: true, correctness: true, evidence_pass: false },
    };
  }

  const answer: Record<string, unknown> = {};
  for (const [f, g] of Object.entries(q.gold)) {
    answer[f] = { value: g.value, evidence: [outsideFrameOf(plainGoldFrames(q, f), packetCount)] };
  }
  emulates = "证据帧错形态：值正确但引用了 gold 帧集之外的帧";
  return {
    answer, error_form: form, emulates,
    expect: { schema_valid: true, correctness: true, evidence_pass: false },
  };
}

function plainEvidence(q: Question, field: string): number[] {
  if (q.type === "set") {
    const evMap = q.gold_evidence[field] as Record<string, number[]>;
    return Object.values(evMap)[0] ?? [];
  }
  const ev = q.gold_evidence[field];
  return Array.isArray(ev) ? [...ev] : [];
}

function plainGoldFrames(q: Question, field: string): number[] {
  if (q.type === "set") {
    const evMap = q.gold_evidence[field] as Record<string, number[]>;
    return Object.values(evMap).flat();
  }
  const ev = q.gold_evidence[field];
  return Array.isArray(ev) ? ev : [];
}

/** 取一个不在 gold 帧集内的合法帧号 */
function outsideFrameOf(goldFrames: number[], packetCount: number): number {
  const gold = new Set(goldFrames);
  for (let cand = 1; cand <= packetCount; cand++) {
    if (!gold.has(cand)) return cand;
  }
  throw new Error("no outside frame available");
}

// ---- 模板 ----

/** 手写题已覆盖的实例：显式跳过清单（排除理由=对应 question_id） */
const SKIP = new Set([
  "web-session:retrans-count:A", // q-web-001 / q-web-003
  "web-session:retrans-handshake:A", // q-web-003 的握手字段
  "web-session:dns-ttl:youtube.com", // q-web-004
  "web-session:dns-pivot:youtube.com", // q-web-005
]);

interface ConvRow { id: string; proto: string; src: string; sport: number; dst: string; dport: number; bytes?: number }

export function deriveAll(gtByCapture: Record<string, GroundTruth>): DerivedQuestion[] {
  const out: DerivedQuestion[] = [];

  for (const [capture, gt] of Object.entries(gtByCapture)) {
    const convs = gt.facts.conversations as ConvRow[];
    const retxs = (gt.facts.retransmissions ?? []) as Array<{ conv: string; frame: number }>;
    const handshakes = (gt.facts.handshakes ?? []) as Array<{ conv: string; syn_frame: number; synack_frame: number; ack_frame: number; handshake_ms: number }>;
    const anomalies = (gt.facts.tcp_anomalies ?? []) as Array<{ conv: string; kind: string; frame: number }>;
    const dns = (gt.facts.dns ?? []) as Array<{ qname: string; response_frame: number; ttl: number | null }>;
    const packOf = capture === "web-session" ? "P1" : capture === "tls-cert" ? "P4" : "P2";
    const tupleOfId = (id: string): Tuple => {
      const c = convs.find((x) => x.id === id)!;
      return { proto: c.proto, src: c.src, sport: c.sport, dst: c.dst, dport: c.dport };
    };

    // T1 重传计数（S2×D1）
    {
      const ctx: Ctx = { capture, fixturePath: `fixtures/${capture}.pcap`, packetCount: gt.packet_count, seq: 1 };
      let i = 0;
      for (const c of convs) {
        if (SKIP.has(`${capture}:retrans-count:${c.id}`)) continue;
        const frames = retxs.filter((r) => r.conv === c.id).map((r) => r.frame);
        if (frames.length === 0) continue;
        const d = baseQuestion(ctx, {
          idSuffix: "retrans-count",
          type: "record",
          text: `会话（五元组 ${c.proto} ${c.src}:${c.sport} → ${c.dst}:${c.dport}）发生了多少次 TCP 重传？`,
          answer_schema: {
            "x-kind": "record", type: "object",
            properties: { retransmission_count: nodeSchema({ type: "integer", minimum: 0 }) },
            required: ["retransmission_count"], additionalProperties: false,
          },
          gold: { retransmission_count: { value: frames.length } },
          gold_evidence: { retransmission_count: frames },
          derivation: `facts.retransmissions 过滤 conv=='${c.id}' 得 ${frames.length} 条（帧 ${frames.join("/")}）；证据帧 = 各重传帧。`,
          tolerance_note: "计数字段未声明容差 = 零容差（备忘录 §7 注册定义）",
          gt_pointers: [`facts.retransmissions[?(@.conv=='${c.id}')]`],
          steps: [
            { n: 1, tool: "traffic_open", input: `fixtures/${capture}.pcap`, expect: `确立 capture_id；packet_count=${gt.packet_count}` },
            { n: 2, tool: "traffic_query", input: "{scope:'event', where:[{field:'type',op:'eq',value:'tcp_retransmission'}]}", expect: `${c.id} 名下 ${frames.length} 行` },
            { n: 3, tool: "（组答）", input: "—", expect: `retransmission_count=${frames.length}` },
          ],
          bash: `tshark -r fixtures/${capture}.pcap -Y 'tcp.analysis.retransmission' -T fields -e frame.number`,
          factors: { H: 2, C: 1, G: "small", X: 1, N: "low" },
          difficulty: 1, skill: ["S2"], protocols: ["tcp"], scenarioPack: packOf,
        });
        buildCanary(d.question, i, gt.packet_count);
        out.push(d);
        i++;
      }
    }

    // T2 握手耗时（S3×D1）
    {
      const ctx: Ctx = { capture, fixturePath: `fixtures/${capture}.pcap`, packetCount: gt.packet_count, seq: 1 };
      let i = 0;
      for (const h of handshakes) {
        if (SKIP.has(`${capture}:retrans-handshake:${h.conv}`)) continue;
        const c = convs.find((x) => x.id === h.conv)!;
        const frames = [h.syn_frame, h.synack_frame, h.ack_frame];
        const d = baseQuestion(ctx, {
          idSuffix: "handshake-ms",
          type: "scalar_number",
          text: `会话（五元组 ${c.proto} ${c.src}:${c.sport} → ${c.dst}:${c.dport}）的 TCP 三次握手总耗时是多少毫秒？（客户端 SYN 到握手完成 ACK）`,
          answer_schema: {
            "x-kind": "scalar_number", type: "object",
            properties: { tcp_handshake_ms: nodeSchema({ type: "number", minimum: 0 }) },
            required: ["tcp_handshake_ms"], additionalProperties: false,
          },
          gold: { tcp_handshake_ms: { value: h.handshake_ms, tolerance_abs: 2.0 } },
          gold_evidence: { tcp_handshake_ms: frames },
          derivation: `facts.handshakes 过滤 conv=='${h.conv}' 得 handshake_ms=${h.handshake_ms}（syn 帧 ${h.syn_frame} / synack 帧 ${h.synack_frame} / 完成帧 ${h.ack_frame}）；证据帧 = 握手三元组。`,
          tolerance_note: "时延类指标 tolerance_abs=2.0（备忘录 §7）",
          gt_pointers: [`facts.handshakes[?(@.conv=='${h.conv}')]`],
          steps: [
            { n: 1, tool: "traffic_open", input: `fixtures/${capture}.pcap`, expect: "确立 capture_id" },
            { n: 2, tool: "traffic_inspect", input: "按五元组定位会话", expect: `metrics.tcp_handshake_ms=${h.handshake_ms}` },
            { n: 3, tool: "（组答）", input: "—", expect: `tcp_handshake_ms=${h.handshake_ms}(±2.0)` },
          ],
          bash: `tshark -r fixtures/${capture}.pcap -Y 'tcp.flags.syn==1 || (tcp.flags.ack==1 && tcp.len==0)' -T fields -e frame.number -e frame.time_epoch`,
          factors: { H: 2, C: 1, G: "small", X: 1, N: "low" },
          difficulty: 1, skill: ["S3"], protocols: ["tcp"], scenarioPack: packOf,
        });
        buildCanary(d.question, i, gt.packet_count);
        out.push(d);
        i++;
      }
    }

    // T3 零窗口存在性（S6×D1；false 实例 = 否定性断言，空证据帧集）
    {
      const ctx: Ctx = { capture, fixturePath: `fixtures/${capture}.pcap`, packetCount: gt.packet_count, seq: 1 };
      let i = 0;
      for (const c of convs) {
        if (c.proto !== "tcp") continue;
        const frames = anomalies.filter((a) => a.conv === c.id && a.kind === "zero_window").map((a) => a.frame);
        const d = baseQuestion(ctx, {
          idSuffix: "zero-window",
          type: "scalar_enum",
          text: `会话（五元组 tcp ${c.src}:${c.sport} → ${c.dst}:${c.dport}）中是否发生过 TCP 零窗口通告？`,
          answer_schema: {
            "x-kind": "scalar_enum", type: "object",
            properties: { zero_window_seen: nodeSchema({ type: "boolean" }, 0) },
            required: ["zero_window_seen"], additionalProperties: false,
          },
          gold: { zero_window_seen: { value: frames.length > 0 } },
          gold_evidence: { zero_window_seen: frames },
          derivation: `facts.tcp_anomalies 过滤 conv=='${c.id}' 且 kind=='zero_window' → ${frames.length} 条${frames.length ? `（帧 ${frames.join("/")}）` : ""}。true 实例证据帧 = 通告帧；false 实例为否定性断言，证据帧集为空（备忘录 §7 空集特例同型）。`,
          tolerance_note: "枚举精确比对，无容差",
          gt_pointers: [`facts.tcp_anomalies[?(@.conv=='${c.id}' && @.kind=='zero_window')]`],
          steps: [
            { n: 1, tool: "traffic_open", input: `fixtures/${capture}.pcap`, expect: "确立 capture_id" },
            { n: 2, tool: "traffic_query", input: "{scope:'event', where:[{field:'type',op:'eq',value:'tcp_zero_window'}]}", expect: frames.length ? `命中帧 ${frames.join("/")}` : "0 行" },
            { n: 3, tool: "（组答）", input: "—", expect: frames.length ? "true" : "false" },
          ],
          bash: `tshark -r fixtures/${capture}.pcap -Y 'tcp.window_size==0 && tcp.flags.ack==1' -T fields -e frame.number`,
          factors: { H: 2, C: 1, G: "small", X: 1, N: "low" },
          difficulty: 1, skill: ["S6"], protocols: ["tcp"], scenarioPack: packOf,
        });
        buildCanary(d.question, i, gt.packet_count);
        out.push(d);
        i++;
      }
    }

    // T4 按字节数排序 top-3（S2×D2，ordered——gt bytes 字段解锁的真排序题）
    if (convs.every((c) => typeof c.bytes === "number") && convs.length >= 3) {
      const sorted = [...convs].sort((a, b) => (b.bytes as number) - (a.bytes as number)).slice(0, 3);
      const ctx: Ctx = { capture, fixturePath: `fixtures/${capture}.pcap`, packetCount: gt.packet_count, seq: 1 };
      const allFrames = gt.frames as Array<{ frame: number; conv: string | null }>;
      const d = baseQuestion(ctx, {
        idSuffix: "top3-bytes-ordered",
        type: "set",
        text: "列出本捕获中按传输总字节数（含重传帧）降序排名前 3 的双向会话，以规范化五元组作答，顺序必须与排名一致。",
        answer_schema: {
          "x-kind": "set", "x-match": "ordered",
          "x-element-key": "{proto}|{src}:{sport}>{dst}:{dport}",
          type: "object",
          properties: {
            top3_sessions: {
              type: "array",
              items: {
                type: "object",
                properties: { value: { $ref: "#/$defs/session_tuple" }, evidence: evidenceSchema(1) },
                required: ["value", "evidence"],
                additionalProperties: false,
              },
            },
          },
          required: ["top3_sessions"], additionalProperties: false,
          $defs: { session_tuple: SESSION_TUPLE_DEFS },
        },
        gold: { top3_sessions: { value: sorted.map((c) => tupleOfId(c.id)) } },
        gold_evidence: {
          top3_sessions: Object.fromEntries(sorted.map((c) => [
            `${c.proto}|${c.src}:${c.sport}>${c.dst}:${c.dport}`,
            allFrames.filter((f) => f.conv === c.id).map((f) => f.frame),
          ])),
        },
        derivation: `facts.conversations 按 bytes 降序取前 3：${sorted.map((c) => `${c.id}(${c.bytes}B)`).join(" > ")}；ordered 口径下名次即答案的一部分。conv=null 的单向流不构成双向会话，不参与排名。`,
        tolerance_note: "有序集合精确比对，无容差",
        gt_pointers: ["facts.conversations[].bytes", "facts.conversations[].frames"],
        steps: [
          { n: 1, tool: "traffic_open", input: `fixtures/${capture}.pcap`, expect: "确立 capture_id" },
          { n: 2, tool: "traffic_overview", input: "—", expect: "会话列表含 bytes 计数" },
          { n: 3, tool: "（组答）", input: "按 bytes 降序前 3", expect: sorted.map((c) => c.id).join(" > ") },
        ],
        bash: `tshark -r fixtures/${capture}.pcap -q -z conv,tcp -z conv,udp`,
        factors: { H: 2, C: 1, G: "会话级 top-N 排序", X: 1, N: "low" },
        difficulty: 2,
        skill: ["S2"],
        protocols: [...new Set(sorted.map((c) => c.proto))],
        scenarioPack: packOf,
      });
      buildCanary(d.question, 0, gt.packet_count);
      out.push(d);
    }

    // T5 DNS 应答 TTL（S1×D1，raw_query_only）
    {
      const ctx: Ctx = { capture, fixturePath: `fixtures/${capture}.pcap`, packetCount: gt.packet_count, seq: 1 };
      let i = 0;
      for (const entry of dns) {
        if (entry.ttl === null) continue;
        if (SKIP.has(`${capture}:dns-ttl:${entry.qname}`)) continue;
        const d = baseQuestion(ctx, {
          idSuffix: "dns-ttl",
          type: "scalar_number",
          text: `DNS 应答中 ${entry.qname} 的 TTL 是多少秒？`,
          answer_schema: {
            "x-kind": "scalar_number", type: "object",
            properties: { ttl_seconds: nodeSchema({ type: "integer", minimum: 0 }) },
            required: ["ttl_seconds"], additionalProperties: false,
          },
          gold: { ttl_seconds: { value: entry.ttl } },
          gold_evidence: { ttl_seconds: [entry.response_frame] },
          derivation: `facts.dns 过滤 qname=='${entry.qname}' 得 ttl=${entry.ttl}；证据帧 = 应答帧 ${entry.response_frame}。`,
          tolerance_note: "计数字段零容差",
          gt_pointers: [`facts.dns[?(@.qname=='${entry.qname}')].ttl`],
          steps: [
            { n: 1, tool: "traffic_open", input: `fixtures/${capture}.pcap`, expect: "确立 capture_id" },
            { n: 2, tool: "traffic_raw_query", input: `{fields:['dns.resp.ttl'], display_filter:'dns.flags.response==1 && dns.qry.name=="${entry.qname}"'}`, expect: `${entry.ttl}` },
            { n: 3, tool: "（组答）", input: "—", expect: `ttl_seconds=${entry.ttl}` },
          ],
          bash: `tshark -r fixtures/${capture}.pcap -Y 'dns.flags.response==1 && dns.qry.name=="${entry.qname}"' -T fields -e dns.resp.ttl`,
          factors: { H: 2, C: 1, G: "small", X: 1, N: "low" },
          difficulty: 1, skill: ["S1"], protocols: ["dns"], scenarioPack: packOf,
          irCoverage: "raw_query_only",
        });
        d.question.reference_solution.ir_rationale =
          "dns_response 的 attr.* 白名单仅 {dns_id,qname,rcode_num} 且 FRAMES_FIELDS 无 TTL——traffic_raw_query 是插件侧唯一路径（对照 docs/event-registry.md 与 traffic-core/src/frames.ts）。";
        buildCanary(d.question, i, gt.packet_count);
        out.push(d);
        i++;
      }
    }
  }

  const seen = new Set<string>();
  for (const d of out) {
    if (seen.has(d.fileName)) throw new Error(`重复文件名：${d.fileName}`);
    seen.add(d.fileName);
    assertRefsResolvable(d.question.answer_schema);
  }
  return out;
}

/** $ref 解析自检（防 answer_schema 引用悬空） */
export function assertRefsResolvable(schema: JsonSchema): void {
  const visit = (s: JsonSchema | undefined): void => {
    if (!s) return;
    if (s.$ref !== undefined && refTarget(schema, s.$ref) === undefined) {
      throw new Error(`悬空 $ref：${s.$ref}`);
    }
    for (const sub of Object.values(s.properties ?? {})) visit(sub);
    if (s.items) visit(s.items);
    for (const sub of Object.values(s.$defs ?? {})) visit(sub);
  };
  visit(schema);
}
