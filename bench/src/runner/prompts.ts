/**
 * 提示词（RFC-002 §5.2 v1.1 / §10-I2）：
 * - 两臂系统提示由同一模板生成、同等质量标准：都告知 pcap 路径、任务契约、终答格式；
 *   差异只在工具面描述（bash 工作流 vs traffic-* 工具流）。
 * - 任务题面模板两臂完全一致（控制变量）。
 * - budgetHint（disclosure 变体，备忘录 §7 注册）：追加预算告知行——量化
 *   "预算视野"成分的单变量对照实验用；主协议（budget-blind）不传此参数。
 */
import type { Question } from "../scorer/question.js";

export function buildSystemPrompt(armKind: "bash" | "ast" | "sql", captureAbsPath: string, budgetHintMaxTurns?: number): string {
  const toolFace =
    armKind === "bash"
      ? [
          "Tool face: a single `shell` tool that runs one zsh command at a time in the repository working directory.",
          "tshark (Wireshark CLI) is installed; python3 is available. Typical workflow:",
          "  capinfos <pcap>                       # overview",
          "  tshark -r <pcap> -q -z conv,tcp       # conversation tables",
          "  tshark -r <pcap> -Y '<display filter>' -T fields -e frame.number -e ...   # filtered field extraction",
          "Chain commands with pipes as needed. Keep each command's output bounded (use -c or head) so it stays readable.",
        ]
      : armKind === "sql"
        ? [
            "Tool face: three tools — traffic_open(path), traffic_schema(capture_id), traffic_sql(capture_id, sql).",
            "The SQL engine is DuckDB over the capture's materialized tables (read-only SELECT only).",
            "Start with traffic_schema to see available tables and columns, then write SQL queries.",
            "Key tables: conversations (bidirectional only), events (with attr_* flattened columns), frames, frame_refs.",
            "Evidence: events and frames carry frame_number; join frame_refs on owner_id for evidence chains.",
          ]
        : [
            "Tool face: the traffic-* structured analysis toolkit over a Traffic Observation IR.",
            "Typical flow: traffic_open(path) → traffic_overview(capture_id) → traffic_query(scope=conversation|event)",
            "→ traffic_inspect(conversation_id) → traffic_evidence(frames) to verify claims against packet-level records.",
            "traffic_timeseries gives per-bin series; traffic_http_timeline pairs HTTP transactions;",
            "traffic_raw_query is a bounded tshark escape hatch for fields the IR whitelists do not cover.",
          ];
  const budgetLine =
    budgetHintMaxTurns !== undefined
      ? [
          "",
          `Budget notice: you have at most ${budgetHintMaxTurns} tool-use turns in total. Plan your verification accordingly and call finish with your final answer before exhausting them.`,
        ]
      : [];
  return [
    "You are a network traffic analyst answering a question about a packet capture.",
    `The capture file is at: ${captureAbsPath}`,
    "",
    ...toolFace,
    "",
    "Investigate with the tools before answering; verify every number against packet-level evidence (frame numbers).",
    "Do not guess. If you cannot determine a fact from the capture, say so inside the JSON value rather than inventing frames.",
    ...budgetLine,
    "",
    "Final answer contract: call the finish tool exactly once. Its reason MUST contain exactly one ```json fenced block",
    "conforming to the answer schema given in the task. Every factual node is {\"value\": ..., \"evidence\": [frame numbers]};",
    "evidence frame numbers must be real frames you actually observed via your tools.",
  ].join("\n");
}

/** 两臂完全一致的题面任务（含 answer_schema 全文与证据要求） */
export function buildTaskPrompt(q: Question): string {
  return [
    `Question (${q.question_id}): ${q.question}`,
    "",
    "Answer schema (the fenced block must conform to it):",
    JSON.stringify(q.answer_schema, null, 2),
    "",
    'Reminder: finish reason contains exactly one ```json block; every factual node carries {"value", "evidence":[frames]}.',
  ].join("\n");
}
