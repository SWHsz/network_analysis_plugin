/**
 * question-schema.mjs 的类型声明（出题期校验器由 TS 侧桥接/测试复用时使用）。
 * 判分正典在 src/scorer/（TS）；本文件只声明信封校验入口的形状。
 */
export declare const ANSWER_FORMS: string[];
export declare const ANSWER_TOOLS: Set<string>;

export declare function canonicalTupleKey(t: { proto: string; src: string; sport: number; dst: string; dport: number }): string;
export declare function canonicalElementKey(v: unknown): string;

export declare function buildGoldAsAnswer(question: unknown): Record<string, unknown>;
export declare function validateEnvelope(question: unknown, gt: unknown): string[];
export declare function metaEvalCanary(question: unknown): string[];

export declare function validateSchemaStructure(schema: unknown, where?: string): string[];
export declare function validateSchema(schema: unknown, value: unknown, pathStr?: string, root?: unknown): string[];
export declare function scoreAnswer(question: unknown, answer: unknown): {
  schema_valid: boolean;
  correctness: boolean;
  evidence_pass: boolean;
  [k: string]: unknown;
};
