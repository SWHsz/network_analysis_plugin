import type { AuditMetadata } from "./types.js";
import type { TsharkBackend } from "./backend/provider.js";

/**
 * traffic_raw_query —— 长尾查询的有界逃生口（v0.3）。
 *
 * 与让模型直接 bash tshark 的区别：
 * - 无 shell：结构化 argv（display_filter/fields 是单参数，无拼接注入面）；
 * - 字段名经 tshark -G fields 词表校验（错字段立即报错而非静默空输出）；
 * - 有界：行数上限 + 每行长度上限 + 渲染预算；调用进 audit 可观测。
 *
 * 语义边界：输出是 tshark 原始字段行（display filter 的字符串值），不进 IR、
 * 不参与白名单——这是逃生口不是替代品。
 */
export interface RawQueryOptions {
  /** tshark display filter（如 "tls.handshake.type==1"） */
  display_filter?: string;
  /** 请求的字段（须在 tshark 字段词表中；frame.number 强制附加） */
  fields: string[];
  /** 行数上限 [1, 500]，默认 100 */
  limit?: number;
}

export interface RawQueryResult {
  fields: string[];
  returned: number;
  truncated: boolean;
  /** 每行按 fields 顺序的原始字符串（可能含空值） */
  rows: string[][];
  filter: string | null;
  audit: AuditMetadata;
}

export class RawQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RawQueryError";
  }
}

/** 词表中最近似的字段名（编辑距离 top-k，帮模型一步自纠） */
function nearestFields(vocab: Set<string>, name: string, k = 3): string[] {
  const lower = name.toLowerCase();
  const scored: Array<[number, string]> = [];
  for (const v of vocab) {
    // 粗筛：只对包含同名前缀/子串或长度接近的候选算精确距离
    const vl = v.toLowerCase();
    if (Math.abs(vl.length - lower.length) > 4 && !vl.includes(lower.split(".").pop() ?? "")) continue;
    scored.push([levenshtein(lower, vl), v]);
  }
  scored.sort((a, b) => a[0] - b[0]);
  return scored.slice(0, k).filter(([d]) => d <= 6).map(([, v]) => v);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (Math.min(m, n) === 0) return Math.max(m, n);
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n]!;
}

function fieldSuggestions(vocab: Set<string>, names: string[]): string {
  const parts = names.map((n) => {
    const near = nearestFields(vocab, n);
    return near.length ? `${n} (did you mean: ${near.join(" | ")}?)` : n;
  });
  return parts.join(", ");
}

/** display filter 的保守白名单：字母数字与一小撮结构字符（防参数逃逸） */
const FILTER_RE = /^[A-Za-z0-9_.:\[\]=<>!&|() ]+$/;
const FIELD_RE = /^[a-z0-9][a-z0-9_.]*$/i;

/** 惰性加载并校验 tshark 字段词表（进程内缓存） */
let fieldVocabCache: Promise<Set<string>> | undefined;
async function fieldVocab(backend: TsharkBackend): Promise<Set<string>> {
  fieldVocabCache ??= (async () => {
    const res = await backend.runTshark(["-G", "fields"], { timeoutMs: 60_000 });
    const set = new Set<string>();
    for (const line of res.stdout.split("\n")) {
      const cols = line.split("\t");
      // F <name> ... <name再次出现>；取第 3 列字段名（格式：F, 前缀, 名称, ...）
      if (cols.length > 3 && cols[0] === "F") set.add(cols[2]!);
    }
    return set;
  })();
  return fieldVocabCache;
}

export async function rawQuery(
  backend: TsharkBackend,
  file: string,
  opts: RawQueryOptions,
  auditBase: AuditMetadata,
): Promise<RawQueryResult> {
  if (opts.fields.length === 0) throw new RawQueryError("fields must not be empty");
  if (opts.fields.length > 16) throw new RawQueryError("at most 16 fields per raw query");
  const limit = opts.limit ?? 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
    throw new RawQueryError("limit must be an integer in [1, 500]");
  }
  if (opts.display_filter !== undefined) {
    if (opts.display_filter.length > 500) throw new RawQueryError("display_filter too long (max 500 chars)");
    if (!FILTER_RE.test(opts.display_filter)) {
      throw new RawQueryError(
        "display_filter contains unsupported characters; allowed: letters, digits, . : _ [ ] = < > ! & | ( ) and spaces",
      );
    }
  }
  for (const f of opts.fields) {
    if (!FIELD_RE.test(f)) throw new RawQueryError(`invalid field name '${f}'`);
  }

  const vocab = await fieldVocab(backend);
  const unknown = opts.fields.filter((f) => !vocab.has(f));
  if (unknown.length > 0) {
    throw new RawQueryError(
      `unknown tshark field(s): ${fieldSuggestions(vocab, unknown)}. ` +
        `Note: 4.x uses underscore forms for some extensions (SNI = tls.handshake.extensions_server_name)`,
    );
  }

  const fields = [...new Set(["frame.number", ...opts.fields])];
  const args = ["-r", file, "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n"];
  if (opts.display_filter) args.push("-Y", opts.display_filter);
  for (const f of fields) args.push("-e", f);

  let res;
  try {
    res = await backend.runTshark(args, { timeoutMs: 120_000 });
  } catch (err) {
    const msg = (err as Error).message;
    // tshark 对 filter 里无效字段的报错在 stderr：把字段名提出来并给建议
    // 两种格式：-e 字段错误（\n\t<name> 列表）；display filter 错误（"<expr>" is not a valid protocol ...）
    const fieldListNames = [...msg.matchAll(/\n\t((?:tls|tcp|udp|ip|ipv6|frame|dns|http|x509sat|quic)\.[^\s\n]+)/g)].map(
      (m) => m[1]!.trim(),
    );
    const quotedTokens = [...msg.matchAll(/"([^"]+)" is (?:neither a field|not a valid protocol)/gi)].flatMap((m) =>
      m[1]!.match(/(?:[a-z0-9_]+\.)+[a-z0-9_]+/gi) ?? [],
    );
    const invalid = [...fieldListNames, ...quotedTokens];
    if (invalid.length > 0) {
      throw new RawQueryError(
        `invalid field(s) in display_filter: ${fieldSuggestions(vocab, invalid)}`,
      );
    }
    throw err;
  }
  const lines = res.stdout.split("\n").filter((l) => l.length > 0);
  const truncated = lines.length > limit;
  const rows = lines.slice(0, limit).map((line) => {
    const cells = line.split("\t");
    while (cells.length < fields.length) cells.push("");
    return cells.map((c) => (c.length > 4000 ? c.slice(0, 4000) + "…[cell truncated]" : c));
  });

  return {
    fields,
    returned: rows.length,
    truncated,
    rows,
    filter: opts.display_filter ?? null,
    audit: {
      ...auditBase,
      backend_commands: [...auditBase.backend_commands, res.command],
    },
  };
}
