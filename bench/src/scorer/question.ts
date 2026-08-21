/**
 * 题目信封与 ground truth 的判分侧类型（RFC-002 §3 / §4.1）。
 * 加载器只做结构断言；信封级校验（枚举/gold 自洽/canary 声明）由
 * bench/src/schema/validate-questions.mjs 在出题期负责，此处不重复。
 *
 * 路径边界：题目固定读 bench/questions/<白名单 basename>.json，
 * gt 固定读 ground_truth/<capture.fixture 白名单>.gt.json——不解析题面里的
 * 相对路径串（capture.gt 仅作为声明性指针供人读）。每个动态文件名都过
 * 「basename 白名单 + 解析后根目录包含检查」双重边界。
 */
import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, assertSafeBasename } from "../paths.js";
import type { JsonSchema } from "./schema.js";

export const ANSWER_FORMS = ["scalar_number", "scalar_enum", "scalar_string", "set", "record"] as const;
export type AnswerForm = (typeof ANSWER_FORMS)[number];

export const SET_MATCH_MODES = ["unordered", "ordered", "top_k_prefix"] as const;
export type SetMatchMode = (typeof SET_MATCH_MODES)[number];

/** 事实节点二元组（RFC-002 §2.1）：每个 claim 都携带帧号证据 */
export interface AnswerNode {
  value: unknown;
  evidence: number[];
}

export interface GoldNode {
  value: unknown;
  tolerance_abs?: number;
  tolerance_rel?: number;
  unknowable?: boolean;
}

export interface Question {
  question_id: string;
  version: number;
  capture: { fixture: string; path: string; gt: string };
  type: AnswerForm;
  question: string;
  answer_schema: JsonSchema;
  gold: Record<string, GoldNode>;
  gold_evidence: Record<string, unknown>;
  gold_derivation: Record<string, unknown>;
  reference_solution: Record<string, unknown>;
  tags: {
    protocols: string[];
    skill: string[];
    difficulty: number;
    difficulty_label: string;
    ir_coverage: string;
    corpus_layer: string;
    scenario_pack: string;
  };
  provenance: Record<string, unknown>;
  canary: {
    known_good: { answer: Record<string, unknown>; expect: CanaryExpect; note?: string };
    known_bad: {
      answer: Record<string, unknown>;
      error_form: string;
      emulates: string;
      expect: CanaryExpect;
    };
  };
}

export interface CanaryExpect {
  schema_valid: boolean;
  correctness: boolean;
  evidence_pass: boolean;
}

/** gt.json 的判分侧切片（frames 用于等价帧细分，packet_count 用于证据有效性） */
export interface GroundTruth {
  capture: string;
  detection_basis: string;
  packet_count: number;
  duration_ms: number;
  facts: Record<string, unknown>;
  frames: Array<{
    frame: number;
    kind?: string;
    conv?: string | null;
    t_ms?: number;
    [k: string]: unknown;
  }>;
}

const QUESTIONS_DIR = path.join(REPO_ROOT, "bench", "questions");
const GT_DIR = path.join(REPO_ROOT, "ground_truth");

/** 解析结果必须仍落在指定目录内（防越界），basename 另过白名单 */
function containedIn(dir: string, fileName: string): string {
  assertSafeBasename(fileName, "数据文件名");
  const full = path.resolve(dir, fileName);
  if (!full.startsWith(dir + path.sep)) {
    throw new Error(`路径越出数据目录：${fileName}`);
  }
  return full;
}

/** 按文件名加载单题 */
export function loadQuestionByName(fileName: string): Question {
  return JSON.parse(fs.readFileSync(containedIn(QUESTIONS_DIR, fileName), "utf8")) as Question;
}

/** 加载 bench/questions/ 下全部题目（文件名序） */
export function loadQuestionsDir(): Question[] {
  const names = fs.readdirSync(QUESTIONS_DIR).filter((f) => f.endsWith(".json"));
  names.sort();
  return names.map((f) => loadQuestionByName(f));
}

/** 按 capture.fixture 加载对应 gt.json */
export function loadGroundTruth(q: Question): GroundTruth {
  return JSON.parse(fs.readFileSync(containedIn(GT_DIR, `${q.capture.fixture}.gt.json`), "utf8")) as GroundTruth;
}
