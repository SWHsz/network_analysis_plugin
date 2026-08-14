import type { AggregateEvidence } from "./types.js";

export const AGGREGATE_FRAME_CAP = 100;

/**
 * Context Shaper 的聚合 evidence 上限：
 * frames > cap 时保留前 cap 个 + 计数 + 区间描述，防止坏网络抓包撑爆 context。
 */
export function shapeAggregateEvidence(frames: number[]): AggregateEvidence {
  const sorted = [...frames].sort((a, b) => a - b);
  if (sorted.length <= AGGREGATE_FRAME_CAP) {
    return { kind: "aggregate", frames: sorted, frame_count: sorted.length, truncated: false };
  }
  const head = sorted.slice(0, AGGREGATE_FRAME_CAP);
  return {
    kind: "aggregate",
    frames: head,
    frame_count: sorted.length,
    truncated: true,
  };
}

/** 每行渲染的紧凑文本（供 DSH output.render / 终端查看） */
export function renderRows(rows: Array<Record<string, unknown>>, maxCell = 40): string {
  if (rows.length === 0) return "(no rows)";
  const cols = Object.keys(rows[0]!);
  const widths = cols.map((c) =>
    Math.min(maxCell, Math.max(c.length, ...rows.map((r) => String(r[c] ?? "null").length)) || c.length),
  );
  const line = (cells: string[]) =>
    cells.map((c, i) => (i === 0 ? c.padEnd(widths[i]!) : c.padStart(widths[i]!))).join("  ");
  const out = [line(cols), line(widths.map((w) => "-".repeat(w)))];
  for (const r of rows) {
    out.push(
      line(cols.map((c) => {
        const s = String(r[c] ?? "null");
        return s.length > maxCell ? s.slice(0, maxCell - 1) + "…" : s;
      })),
    );
  }
  return out.join("\n");
}

/** 信封的紧凑渲染（模型可见文本） */
export function renderEnvelope(env: {
  returned: number;
  total: number;
  offset: number;
  truncated: boolean;
}): string {
  return `returned ${env.returned} of ${env.total} (offset ${env.offset})${env.truncated ? " [TRUNCATED — refine query or paginate]" : ""}`;
}

export const DEFAULT_RENDER_MAX_CHARS = 12_000;

/**
 * Context Shaper v2 的渲染预算：超出 maxChars 时砍行（不砍列），
 * 返回被保留的行数与截断标志。规范值（execute 返回）不受影响。
 */
export function applyRenderBudget(
  header: string,
  rows: string[],
  footer: string,
  maxChars: number = DEFAULT_RENDER_MAX_CHARS,
): { text: string; droppedRows: number } {
  const overhead = header.length + footer.length + rows.length + 8;
  let budget = maxChars - overhead;
  const kept: string[] = [];
  let dropped = 0;
  for (const row of rows) {
    if (row.length + 1 <= budget) {
      kept.push(row);
      budget -= row.length + 1;
    } else {
      dropped = rows.length - kept.length;
      break;
    }
  }
  const notice = dropped > 0 ? `\n[RENDER BUDGET EXCEEDED — ${dropped} row(s) dropped; narrow select or lower limit]` : "";
  return { text: header + "\n" + kept.join("\n") + (dropped > 0 ? notice : "") + "\n" + footer, droppedRows: dropped };
}
