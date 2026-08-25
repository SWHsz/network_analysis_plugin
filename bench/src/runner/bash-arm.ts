/**
 * BashArm：工具面 = shell（RFC-002 §5.2）。
 * 口径：这是 v0.1 真实路径的基线，不是 bash 工作流的能力上限（§9 如实标注）。
 */
import { spawn } from "node:child_process";
import { z } from "zod";
import type { Tool } from "@stirrup/stirrup";
import { REPO_ROOT } from "../paths.js";
import { marksEmptyArrival, paramValidationError } from "./tool-errors.js";
import type { Arm, ToolCallRecord } from "./types.js";
import { buildSystemPrompt } from "./prompts.js";

const OUTPUT_CHAR_CAP = 16_000;
const CMD_TIMEOUT_MS = 60_000;
const RAW_ARGS_CAP = 2_000;

function runShell(command: string): Promise<{ text: string; ok: boolean }> {
  return new Promise((resolve) => {
    // 参数列表形式 spawn，不经 shell 字符串二次解释；命令本身交给 zsh -c 执行是工具语义
    const child = spawn("/bin/zsh", ["-c", command], {
      cwd: REPO_ROOT,
      timeout: CMD_TIMEOUT_MS,
      env: { ...process.env, PATH: process.env.PATH ?? "/usr/bin:/bin:/opt/homebrew/bin" },
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => {
      if (out.length < OUTPUT_CHAR_CAP) out += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      if (err.length < OUTPUT_CHAR_CAP) err += d.toString("utf8");
    });
    child.on("error", (e) => resolve({ text: `ERROR: ${e.message}`, ok: false }));
    child.on("close", (code, signal) => {
      let text = `${out}${err.length > 0 ? `\n[stderr]\n${err}` : ""}`;
      if (text.length > OUTPUT_CHAR_CAP) text = `${text.slice(0, OUTPUT_CHAR_CAP)}\n...[truncated at ${OUTPUT_CHAR_CAP} chars]`;
      if (signal) text += `\n[terminated by ${signal} after ${CMD_TIMEOUT_MS}ms]`;
      else if (code !== null && code !== 0) text += `\n[exit code ${code}]`;
      resolve({ text: text === "" ? "(no output)" : text, ok: code === 0 });
    });
  });
}

export class BashArm implements Arm {
  readonly name = "bash-v0.2";

  constructor(private readonly captureAbsPath: string) {}

  get systemPrompt(): string {
    return buildSystemPrompt("bash", this.captureAbsPath);
  }

  buildTools(records: ToolCallRecord[]): Array<Tool<any, any>> {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const tool: Tool<any, any> = {
      name: "shell",
      description:
        "Run one zsh command in the repository working directory and receive combined stdout/stderr " +
        `(bounded at ${OUTPUT_CHAR_CAP} chars, per-command timeout ${CMD_TIMEOUT_MS / 1000}s). ` +
        "tshark/capinfos/python3 are on PATH. Use for packet-capture analysis.",
      parameters: z.object({
        command: z.string().describe("The shell command to execute, e.g. tshark -r capture.pcap -c 20"),
      }),
      executor: async (params: { command?: string }): Promise<{ content: string; success: boolean }> => {
        if (typeof params?.command !== "string" || params.command.trim() === "") {
          return {
            content: paramValidationError({
              tool: "shell",
              problem: "command 必须为非空字符串",
              received: params,
              emptyArrivals: ["command"],
              expectedShape: "command(字符串: 要执行的 zsh 命令)",
            }),
            success: false,
          };
        }
        const { text, ok } = await runShell(params.command);
        return { content: text, success: ok };
      },
    };
    return [withTiming(tool, records)];
    /* eslint-enable @typescript-eslint/no-explicit-any */
  }
}

/**
 * Stirrup 缺单次耗时的一等字段 → executor 计时 wrapper（spike 已验证形态）。
 * v0.2：同时记录 rawArgs 诊断遥测（executor 收到的参数若已是对象——Stirrup 已
 * JSON.parse——则序列化记录并置 rawArgsWasObject；若为字符串则原样记录，解析
 * 失败记 argsParseError），并从错误回显中提取「空到达」标注。
 */
export function withTiming(tool: Tool<any, any>, records: ToolCallRecord[]): Tool<any, any> {
  const inner = tool.executor;
  return {
    ...tool,
    executor: async (params: unknown) => {
      const startedAtMs = Date.now();
      let rawArgs = "";
      let rawArgsWasObject = false;
      let rawArgsTruncated = false;
      let argsParseError: string | null = null;
      let parsed: unknown = params;
      if (typeof params === "string") {
        rawArgs = params;
        try {
          parsed = JSON.parse(params);
        } catch (e) {
          argsParseError = (e as Error).message;
        }
      } else {
        rawArgsWasObject = true;
        rawArgs = JSON.stringify(params ?? null) ?? "";
      }
      if (rawArgs.length > RAW_ARGS_CAP) {
        rawArgs = rawArgs.slice(0, RAW_ARGS_CAP);
        rawArgsTruncated = true;
      }
      const rec: ToolCallRecord = {
        seq: records.length,
        name: tool.name,
        args: parsed,
        ok: false,
        durationMs: 0,
        resultChars: 0,
        startedAtMs,
        rawArgs,
        rawArgsWasObject,
        rawArgsTruncated,
        argsParseError,
      };
      records.push(rec);
      try {
        const out = await inner(parsed as never);
        rec.ok = out.success !== false;
        rec.resultChars = typeof out.content === "string" ? out.content.length : JSON.stringify(out.content ?? "").length;
        if (!rec.ok && typeof out.content === "string" && marksEmptyArrival(out.content)) {
          rec.emptyArrival = true;
        }
        return out;
      } finally {
        rec.durationMs = Date.now() - startedAtMs;
      }
    },
  };
}
