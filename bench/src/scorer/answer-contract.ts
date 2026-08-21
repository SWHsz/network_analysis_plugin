/**
 * 终答提取与答案契约校验（RFC-002 §2.2 / §5.3）。
 *
 * 契约：agent 终答以唯一 fenced ```json block 提交；提取器取最后一个可解析的
 * block（§5.3），多 block 属契约违规但仅记诊断（non_unique_block），不直接判错——
 * 真正的裁决由 answer_schema 校验给出，失败统一记 format_error（单独分类，
 * 不计入对错也不赦免）。
 */
import { validateSchema, type JsonSchema } from "./schema.js";

export type Extraction =
  | { status: "ok"; value: unknown; nonUniqueBlock: boolean }
  | { status: "format_error"; reason: string; detail: string };

/** 取文本中全部 ```json fenced block 的内容（不要求闭合唯一） */
function fencedJsonBlocks(raw: string): string[] {
  const blocks: string[] = [];
  const lines = raw.split("\n");
  let inBlock = false;
  let buf: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!inBlock && /^```json\s*$/i.test(trimmed)) {
      inBlock = true;
      buf = [];
      continue;
    }
    if (inBlock && /^```\s*$/.test(trimmed)) {
      inBlock = false;
      blocks.push(buf.join("\n"));
      continue;
    }
    if (inBlock) buf.push(line);
  }
  return blocks;
}

/** 从 agent 终答原文提取答案对象（未做 schema 校验） */
export function extractFinalAnswer(raw: string): Extraction {
  const blocks = fencedJsonBlocks(raw);
  if (blocks.length === 0) {
    return { status: "format_error", reason: "no_fenced_json_block", detail: "终答中未找到 ```json fenced block" };
  }
  // §5.3：取最后一个合法 block
  for (let i = blocks.length - 1; i >= 0; i--) {
    const block = blocks[i];
    if (block === undefined) continue;
    try {
      const value: unknown = JSON.parse(block);
      return { status: "ok", value, nonUniqueBlock: blocks.length > 1 };
    } catch (e) {
      if (i === 0) {
        return {
          status: "format_error",
          reason: "json_parse_failed",
          detail: `fenced block 不是合法 JSON：${(e as Error).message}`,
        };
      }
    }
  }
  /* c8 ignore next: 循环必经 return */
  return { status: "format_error", reason: "json_parse_failed", detail: "unreachable" };
}

export interface ParsedAnswer {
  schemaValid: boolean;
  schemaErrors: string[];
  /** 校验通过时的答案对象（顶层字段 → AnswerNode 形态） */
  answer?: Record<string, unknown>;
}

/** 提取结果按题目 answer_schema 校验；失败即 format_error（RFC-002 §2.2） */
export function validateAgainstContract(schema: JsonSchema, extraction: Extraction): ParsedAnswer | { formatError: string } {
  if (extraction.status === "format_error") {
    return { formatError: `${extraction.reason}: ${extraction.detail}` };
  }
  const schemaErrors = validateSchema(schema, extraction.value);
  if (schemaErrors.length > 0) {
    return { formatError: `answer_schema 校验失败：${schemaErrors[0]}${schemaErrors.length > 1 ? `（共 ${schemaErrors.length} 项）` : ""}` };
  }
  return {
    schemaValid: true,
    schemaErrors: [],
    answer: extraction.value as Record<string, unknown>,
  };
}
