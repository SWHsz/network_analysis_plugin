/**
 * LLM 接线：provider 路由（DeepSeek 直连 / opengo 转发）+ 本地记录代理。
 *
 * 记录代理是 EVALUATION.md 附带条件 (b) 的落地：固化进 runner，持续计量
 * 每次请求实际下发的 system prompt + tools JSON（interface 载荷的 ground truth）。
 * 计量口径：chars 为原始事实，tokens 为 chars/4 估计（与 E1 一致，跨模型不作
 * tokenizer 精确对齐——口径一致性优先于绝对精度）。
 */
import http from "node:http";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const DEFAULT_MODEL = "deepseek-v4-flash";

/** 兼容旧脚本（run-slice-q1.ts）的模型常量 */
export const MODEL = DEFAULT_MODEL;

export interface ProviderConfig {
  name: string;
  upstream: string;
  keyEnvName: string;
}

/** provider 注册表：deepseek-* 走官方直连（与 E1 基线同路径），其余默认 opengo 转发 */
export const PROVIDERS: Record<string, ProviderConfig> = {
  deepseek: { name: "deepseek", upstream: "https://api.deepseek.com", keyEnvName: "DEEPSEEK_API_KEY" },
  opengo: { name: "opengo", upstream: "https://opencode.ai/zen/go", keyEnvName: "OPENCODE_GO_MYSELF_API_KEY" },
};

/** 模型 → provider 解析（可用 --provider 显式覆盖） */
export function resolveProvider(model: string, override?: string): ProviderConfig {
  if (override) {
    const p = PROVIDERS[override];
    if (!p) throw new Error(`未知 provider：${override}（可用：${Object.keys(PROVIDERS).join("/")}）`);
    return p;
  }
  return model.startsWith("deepseek-") ? PROVIDERS.deepseek! : PROVIDERS.opengo!;
}

async function readCredential(keyEnvName: string): Promise<string> {
  const credPath = path.join(os.homedir(), ".dsh", ".credentials.yaml");
  const raw = await readFile(credPath, "utf8");
  const m = raw.match(new RegExp(`^\\s*${keyEnvName}:\\s*["']?([^"'\\r\\n]+?)["']?\\s*$`, "m"));
  const key = m?.[1];
  if (!key) throw new Error(`${keyEnvName} not found in ${credPath}`);
  return key;
}

/** 兼容旧入口：DeepSeek key */
export async function loadDeepseekKey(): Promise<string> {
  return readCredential("DEEPSEEK_API_KEY");
}

export async function loadApiKey(provider: ProviderConfig): Promise<string> {
  return readCredential(provider.keyEnvName);
}

export interface InterfaceCapture {
  systemChars: number;
  toolsChars: number;
  /** chars/4 估计（与 E1 同口径；跨模型不做 tokenizer 精确对齐） */
  estTokens: number;
  systemText: string;
  toolsJson: string;
}

const captures: InterfaceCapture[] = [];

/** 取从 index 起的新增捕获（一次 arm run 的请求载荷） */
export function capturesFrom(index: number): InterfaceCapture[] {
  return captures.slice(index);
}

export function captureCount(): number {
  return captures.length;
}

/** 单次运行的 interface 计量：取该 run 首个请求的 (system+tools) 载荷 */
export function interfaceTokensOf(runCaptures: InterfaceCapture[]): number {
  return runCaptures.length > 0 ? runCaptures[0]!.estTokens : 0;
}

export function interfaceCharsOf(runCaptures: InterfaceCapture[]): { systemChars: number; toolsChars: number; totalChars: number } {
  const first = runCaptures[0];
  return {
    systemChars: first?.systemChars ?? 0,
    toolsChars: first?.toolsChars ?? 0,
    totalChars: (first?.systemChars ?? 0) + (first?.toolsChars ?? 0),
  };
}

/** v0.2 诊断：provider 响应体里的原始 tool_calls 参数串（H-harness vs H-model 的判别证据） */
export interface ProviderToolCall {
  name: string;
  arguments: string;
  truncated: boolean;
}

const PROVIDER_ARGS_CAP = 2_000;
const providerToolCalls: ProviderToolCall[] = [];

export function providerToolCallCount(): number {
  return providerToolCalls.length;
}

export function providerToolCallsFrom(index: number): ProviderToolCall[] {
  return providerToolCalls.slice(index);
}

function recordProviderToolCalls(respBuf: Buffer): void {
  try {
    const json = JSON.parse(respBuf.toString("utf8")) as {
      choices?: Array<{ message?: { tool_calls?: Array<{ function?: { name?: string; arguments?: string } }> } }>;
    };
    for (const tc of json.choices?.[0]?.message?.tool_calls ?? []) {
      const args = tc.function?.arguments ?? "";
      providerToolCalls.push({
        name: tc.function?.name ?? "(unknown)",
        arguments: args.length > PROVIDER_ARGS_CAP ? args.slice(0, PROVIDER_ARGS_CAP) : args,
        truncated: args.length > PROVIDER_ARGS_CAP,
      });
    }
  } catch {
    /* 响应体非 JSON（流式/错误页），跳过 */
  }
}

export function startRecordingProxy(upstream: string): Promise<{ baseURL: string; close: () => void }> {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
      res.writeHead(404);
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);
    try {
      const json = JSON.parse(body.toString("utf8")) as { messages?: Array<{ role: string; content?: string }>; tools?: unknown };
      const systemMsg = Array.isArray(json.messages) ? json.messages.find((m) => m.role === "system") : undefined;
      const systemText: string = typeof systemMsg?.content === "string" ? systemMsg.content : "";
      const toolsJson: string = json.tools ? JSON.stringify(json.tools) : "";
      captures.push({
        systemChars: systemText.length,
        toolsChars: toolsJson.length,
        estTokens: Math.ceil((systemText.length + toolsJson.length) / 4),
        systemText,
        toolsJson,
      });
    } catch {
      /* 非 JSON 请求体，跳过记录 */
    }
    const up = await fetch(`${upstream}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: req.headers.accept ?? "application/json",
        authorization: req.headers.authorization ?? "",
      },
      body,
    });
    const respBuf = Buffer.from(await up.arrayBuffer());
    recordProviderToolCalls(respBuf);
    res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
    res.end(respBuf);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ baseURL: `http://127.0.0.1:${port}/v1`, close: () => server.close() });
    });
  });
}
