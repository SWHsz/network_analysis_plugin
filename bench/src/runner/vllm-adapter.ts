/**
 * vLLM/OpenAI-compatible provider adapter（T4-增补④）。
 *
 * 用途：Lane A 本地 lane（零额度）跑 T3 边缘矩阵——qwen3.8-27B-FP8 via vLLM serve。
 * 接口：OpenAI-compatible chat/completions（vLLM 原生支持），token 计数对齐 vLLM usage。
 *
 * 环境变量：
 *   VLLM_BASE_URL   — e.g. http://localhost:8000/v1
 *   VLLM_API_KEY    — vLLM serve 的 API key（如无鉴权可设 dummy）
 *   VLLM_MODEL      — 模型名（e.g. Qwen/Qwen3.8-27B-FP8）
 */
import http from "node:http";

export interface VllmProviderConfig {
  baseURL: string;    // http://localhost:8000/v1
  apiKey: string;
  model: string;
}

export function loadVllmConfig(): VllmProviderConfig | null {
  const baseURL = process.env.VLLM_BASE_URL;
  const apiKey = process.env.VLLM_API_KEY ?? "dummy";
  const model = process.env.VLLM_MODEL;
  if (!baseURL || !model) return null;
  return { baseURL, apiKey, model };
}

/**
 * vLLM 预检：ping 端点 + 模型列表，确保 vLLM serve 已启动。
 * 返回 null=通过；否则返回错误摘要。
 */
export async function pingVllm(config: VllmProviderConfig): Promise<string | null> {
  try {
    const res = await fetch(`${config.baseURL}/models`, {
      headers: { authorization: `Bearer ${config.apiKey}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return `HTTP ${res.status}: ${res.statusText}`;
    const json = (await res.json()) as { data?: Array<{ id: string }> };
    const models = json.data?.map((m) => m.id) ?? [];
    if (models.length > 0 && !models.includes(config.model)) {
      return `模型 ${config.model} 不在 vLLM 可用列表中（可用：${models.join(", ")}）`;
    }
    return null;
  } catch (e) {
    return `vLLM 连接失败：${(e as Error).message}`;
  }
}

/**
 * vLLM 录制代理（与 zen 路由的 recording proxy 同构）：
 * 逐请求捕获 system+tools（interfaceTokens）+ 响应体 tool_calls（provider raw args）。
 */
export function startVllmRecordingProxy(config: VllmProviderConfig): Promise<{
  baseURL: string;
  close: () => void;
  getCaptures: () => Array<{ systemChars: number; toolsChars: number; estTokens: number; systemText: string; toolsJson: string }>;
  getProviderToolCalls: () => Array<{ name: string; arguments: string; truncated: boolean }>;
}> {
  const captures: Array<{ systemChars: number; toolsChars: number; estTokens: number; systemText: string; toolsJson: string }> = [];
  const providerToolCalls: Array<{ name: string; arguments: string; truncated: boolean }> = [];

  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || !req.url?.includes("/chat/completions")) {
      // 非 chat completions（如 /models）直接透传
      const up = await fetch(`${config.baseURL}${req.url}`, {
        headers: { authorization: `Bearer ${config.apiKey}` },
      });
      res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
      res.end(Buffer.from(await up.arrayBuffer()));
      return;
    }

    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);

    try {
      const json = JSON.parse(body.toString("utf8")) as {
        messages?: Array<{ role: string; content?: string }>;
        tools?: unknown;
      };
      const sys = json.messages?.find((m) => m.role === "system");
      const sysText = typeof sys?.content === "string" ? sys.content : "";
      const toolsJson = json.tools ? JSON.stringify(json.tools) : "";
      captures.push({
        systemChars: sysText.length,
        toolsChars: toolsJson.length,
        estTokens: Math.ceil((sysText.length + toolsJson.length) / 4),
        systemText: sysText,
        toolsJson,
      });
    } catch { /* skip */ }

    try {
      const up = await fetch(`${config.baseURL}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.apiKey}`,
        },
        body,
        signal: AbortSignal.timeout(200_000),
      });
      const respBuf = Buffer.from(await up.arrayBuffer());
      // 记录 provider 侧 tool_calls
      try {
        const resp = JSON.parse(respBuf.toString("utf8")) as {
          choices?: Array<{ message?: { tool_calls?: Array<{ function?: { name?: string; arguments?: string } }> } }>;
        };
        for (const tc of resp.choices?.[0]?.message?.tool_calls ?? []) {
          const args = tc.function?.arguments ?? "";
          providerToolCalls.push({
            name: tc.function?.name ?? "(unknown)",
            arguments: args.length > 2000 ? args.slice(0, 2000) : args,
            truncated: args.length > 2000,
          });
        }
      } catch { /* skip */ }
      res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
      res.end(respBuf);
    } catch (e) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: `vllm-proxy upstream failure: ${(e as Error).message}` } }));
    }
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({
        baseURL: `http://127.0.0.1:${port}/v1`,
        close: () => server.close(),
        getCaptures: () => captures,
        getProviderToolCalls: () => providerToolCalls,
      });
    });
  });
}
