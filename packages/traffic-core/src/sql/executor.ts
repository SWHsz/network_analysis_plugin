import { DuckDBInstance, type DuckDBConnection } from "@duckdb/node-api";
import { SQL_ALLOWED_TABLES } from "./catalog.js";

/**
 * Bounded SQL Executor（S1，RFC §4.4 + v1.2 安全白名单）。
 *
 * 安全模型（纵深两层 + readonly）：
 * 1. 语句级：单条、首词 SELECT/WITH、黑名单词法（文件读取/DDL/DCL/副作用语句与表函数）；
 * 2. 引用级：FROM/JOIN 目标必须 ∈ 注册目录；FROM '<字符串路径>' 简写直接拒绝；
 * 3. DuckDB 只读内存实例（兜底，不作为主防线——spike 实证 read_csv 在 :memory: 下可读任意文件）。
 *
 * 预算：外包装强制 LIMIT（行）、序列化字节预算（调用方）、超时 interrupt。
 */
export class SqlSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SqlSecurityError";
  }
}

/** 黑名单：带文件系统/运行时副作用的语句与表函数（词边界匹配） */
const FORBIDDEN_TOKENS = [
  // 文件/IO 表函数与简写
  "read_csv", "read_csv_auto", "read_json", "read_json_auto", "read_ndjson", "read_ndjson_auto",
  "read_parquet", "parquet_scan", "read_text", "read_text_lines", "read_blob", "glob", "sniff_csv",
  // 语句动词
  "copy", "install", "load", "pragma", "attach", "detach", "create", "insert", "update", "delete",
  "drop", "alter", "export", "import", "set", "reset", "call", "use", "begin", "commit", "rollback",
  "checkpoint", "vacuum", "analyze", "grant", "revoke", "prepare", "execute", "deallocate", "comment",
  "truncate", "merge", "replace",
];
const FORBIDDEN_RE = new RegExp(`\\b(${FORBIDDEN_TOKENS.join("|")})\\b`, "i");
/** FROM/JOIN '<字符串>' 路径简写（duckdb 允许 FROM 'file.parquet'） */
const FROM_LITERAL_RE = /\b(from|join)\s+'[^']*'/i;
const COMMENT_RE = /--[^\n]*|\/\*[\s\S]*?\*\//g;
/** FROM/JOIN 目标标识符（用于目录白名单校验；不追求完整 SQL 解析，配合引擎报错兜底） */
const TABLE_REF_RE = /\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi;

export function validateUserSql(rawSql: string): void {
  const sql = rawSql.replace(COMMENT_RE, " ").trim();
  if (sql.length === 0) throw new SqlSecurityError("empty statement");
  if (/;/.test(sql.slice(0, -1))) {
    throw new SqlSecurityError("multiple statements are not allowed");
  }
  const first = /^[a-zA-Z]+/.exec(sql)?.[0]?.toUpperCase();
  if (first !== "SELECT" && first !== "WITH") {
    throw new SqlSecurityError(`only SELECT/WITH statements are allowed (got '${first}')`);
  }
  const banned = FORBIDDEN_RE.exec(sql);
  if (banned) {
    throw new SqlSecurityError(
      `forbidden token '${banned[1]!.toLowerCase()}' (file/system side effects are not allowed; query registered tables only)`,
    );
  }
  const lit = FROM_LITERAL_RE.exec(sql);
  if (lit) {
    throw new SqlSecurityError(`string-literal table path is not allowed after ${lit[1]!.toUpperCase()}`);
  }
  // WITH 子句定义的 CTE 名视为合法引用（解析失败的边角由引擎 does-not-exist 报错兜底）
  const allowed = new Set(SQL_ALLOWED_TABLES);
  const withHeader = /^with\s+/i.exec(sql);
  if (withHeader) {
    // 从 WITH 起逐段提取 name AS ( ... ) 的顶层 CTE 名（含逗号链）
    let rest = sql.slice(withHeader[0].length);
    for (const m of rest.matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(/gi)) {
      allowed.add(m[1]!.toLowerCase());
    }
  }
  for (const m of sql.matchAll(TABLE_REF_RE)) {
    const name = m[1]!.toLowerCase();
    if (!allowed.has(name)) {
      throw new SqlSecurityError(
        `unknown table '${name}'. Allowed: ${[...SQL_ALLOWED_TABLES].join(", ")} (CTE names and traffic_schema tables)`,
      );
    }
  }
}

export interface SqlResult {
  columns: string[];
  returned: number;
  truncated: boolean;
  rows: Record<string, unknown>[];
  elapsed_ms: number;
}

export interface SqlQueryOptions {
  /** 行上限 [1, 500]，默认 100（外包装强制，用户 SQL 内的更小 LIMIT 不受影响） */
  limit?: number;
  /** 超时毫秒，默认 30_000；超时 interrupt 连接并抛错 */
  timeoutMs?: number;
}

export class BoundedSql {
  private constructor(
    private inst: DuckDBInstance,
    private conn: DuckDBConnection,
  ) {}

  /** 物化与建 view 均由内部通道执行（受控命令），不经过 validateUserSql */
  static async create(setupSqls: string[]): Promise<BoundedSql> {
    const inst = await DuckDBInstance.create(":memory:");
    const conn = await inst.connect();
    for (const s of setupSqls) await conn.run(s);
    return new BoundedSql(inst, conn);
  }

  /** 内部采用：由 materialize 在受控 setup 后接管连接 */
  static adopt(inst: DuckDBInstance, conn: DuckDBConnection): BoundedSql {
    return new BoundedSql(inst, conn);
  }

  async query(rawSql: string, opts: SqlQueryOptions = {}): Promise<SqlResult> {
    validateUserSql(rawSql);
    const limit = opts.limit ?? 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new SqlSecurityError("limit must be an integer in [1, 500]");
    }
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const wrapped = `SELECT * FROM (${rawSql.replace(/;\s*$/, "")}) AS _bounded LIMIT ${limit + 1}`;
    const started = Date.now();
    const query = (async () => {
      const res = await this.conn.runAndReadAll(wrapped);
      const all = res.getRowObjectsJson() as Record<string, unknown>[];
      const truncated = all.length > limit;
      const rows = truncated ? all.slice(0, limit) : all;
      const columns = rows.length > 0 ? Object.keys(rows[0]!) : [];
      return { columns, returned: rows.length, truncated, rows, elapsed_ms: Date.now() - started };
    })();
    const timer = new Promise<never>((_, reject) => {
      const t = setTimeout(() => {
        try {
          this.conn.interrupt();
        } catch {
          /* interrupt 失败也走 reject 路径 */
        }
        reject(new SqlSecurityError(`query timed out after ${timeoutMs}ms (interrupted)`));
      }, timeoutMs);
      // 查询结束后清掉定时器
      query.finally(() => clearTimeout(t)).catch(() => {});
    });
    return Promise.race([query, timer]);
  }

  async close(): Promise<void> {
    try {
      this.conn.disconnectSync();
    } catch {
      /* ignore */
    }
    try {
      this.inst.closeSync();
    } catch {
      /* ignore */
    }
  }
}
