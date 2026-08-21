/** 终答提取（RFC-002 §2.2/§5.3）：fenced block 定位、取最后合法块、format_error 路径 */
import { describe, expect, it } from "vitest";
import { extractFinalAnswer } from "../src/scorer/answer-contract.js";
import { validateSchema } from "../src/scorer/schema.js";

describe("extractFinalAnswer", () => {
  it("提取唯一 fenced json block", () => {
    const raw = '分析如下。\n```json\n{"a": 1}\n```\n以上。';
    const r = extractFinalAnswer(raw);
    expect(r.status).toBe("ok");
    if (r.status === "ok") {
      expect(r.value).toEqual({ a: 1 });
      expect(r.nonUniqueBlock).toBe(false);
    }
  });

  it("多个 block 时取最后一个合法块并标记 non_unique_block", () => {
    const raw = '```json\n{"attempt": 1}\n```\n更正：\n```json\n{"attempt": 2}\n```';
    const r = extractFinalAnswer(raw);
    expect(r.status).toBe("ok");
    if (r.status === "ok") {
      expect(r.value).toEqual({ attempt: 2 });
      expect(r.nonUniqueBlock).toBe(true);
    }
  });

  it("无 fenced block → format_error", () => {
    const r = extractFinalAnswer("答案是 3 次。");
    expect(r).toMatchObject({ status: "format_error", reason: "no_fenced_json_block" });
  });

  it("block 非法 JSON → 取更早的合法块；全非法才报错", () => {
    const both = '```json\n{bad}\n```\n```json\n{"ok": true}\n```';
    expect(extractFinalAnswer(both)).toMatchObject({ status: "ok" });
    const onlyBad = '```json\n{bad}\n```';
    expect(extractFinalAnswer(onlyBad)).toMatchObject({ status: "format_error", reason: "json_parse_failed" });
  });
});

describe("validateSchema（JSON Schema 子集）", () => {
  const schema = {
    type: "object",
    properties: {
      n: { type: "integer", minimum: 0 },
      s: { enum: ["tcp", "udp"] },
      tags: { type: "array", items: { type: "string" }, minItems: 1, uniqueItems: true },
      tup: { $ref: "#/$defs/tuple" },
    },
    required: ["n"],
    additionalProperties: false,
    $defs: {
      tuple: {
        type: "object",
        properties: { proto: { enum: ["tcp"] }, port: { type: "integer" } },
        required: ["proto"],
        additionalProperties: false,
      },
    },
  };

  it("合法值通过", () => {
    expect(validateSchema(schema, { n: 3, s: "tcp", tags: ["a"], tup: { proto: "tcp" } })).toEqual([]);
  });

  it("缺必填 / 类型错 / enum 外 / 多余属性 / $ref 目标不存在", () => {
    expect(validateSchema(schema, { s: "tcp" }).join()).toContain('缺必填属性 "n"');
    expect(validateSchema(schema, { n: 1.5 }).join()).toContain("期望类型 integer");
    expect(validateSchema(schema, { n: 1, s: "gre" }).join()).toContain("不在 enum");
    expect(validateSchema(schema, { n: 1, extra: true }).join()).toContain("多余属性");
    expect(validateSchema(schema, { n: 1, tup: { proto: "tcp", port: 1, x: 2 } }).join()).toContain("多余属性");
    expect(validateSchema({ $ref: "#/$defs/none" }, {}).join()).toContain("$ref 目标不存在");
  });

  it("uniqueItems 与 min/maxItems", () => {
    expect(validateSchema(schema, { n: 1, tags: ["a", "a"] }).join()).toContain("元素重复");
    expect(validateSchema(schema, { n: 1, tags: [] }).join()).toContain("minItems");
  });
});
