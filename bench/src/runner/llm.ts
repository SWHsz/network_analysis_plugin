/**
 * LLM 接线：DeepSeek 凭证（只读内存，绝不落盘）+ 本地记录代理。
 *
 * 记录代理是 EVALUATION.md 附带条件 (b) 的落地：固化进 runner，持续计量
 * 每次请求实际下发的 system prompt + tools JSON（interfaceTokens 的 ground truth）。
 */
import http from "node:http";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const MODEL = "deepseek-v4-flash";

export async function loadDeepseekKey(): Promise<string> {
  const credPath = path.join(os.homedir(), ".dsh", ".credentials.yaml");
  const raw = await readFile(credPath, "utf8");
  const m = raw.match(/^\s*DEEPSEEK_API_KEY:\s*["']?([^"'\r\n]+?)["']?\s*$/m);
  const key = m?.[1];
  if (!key) throw new Error(`DEEPSEEK_API_KEY not found in ${credPath}`);
  return key;
}

export interface InterfaceCapture {
  systemChars: number;
  toolsChars: number;
  estTokens: number; // chars/4 启发式（与 spike 同口径）
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

/** 单次运行的 interfaceTokens：取该 run 首个请求的 (system+tools) chars/4 */
export function interfaceTokensOf(runCaptures: InterfaceCapture[]): number {
  return runCaptures.length > 0 ? runCaptures[0]!.estTokens : 0;
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
