import { spawn } from "node:child_process";

export class BackendTimeoutError extends Error {
  constructor(
    public command: string,
    public timeoutMs: number,
    public partialStderr: string,
  ) {
    super(`backend command timed out after ${timeoutMs}ms: ${command}`);
    this.name = "BackendTimeoutError";
  }
}

export class BackendSpawnError extends Error {
  constructor(
    public command: string,
    public causeMessage: string,
  ) {
    super(`failed to run backend command: ${command}: ${causeMessage}`);
    this.name = "BackendSpawnError";
  }
}

export interface RunOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  /** 单流输出上限（字符），默认 256MB */
  maxOutputChars?: number;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  durationMs: number;
  command: string;
}

const SIGKILL_GRACE_MS = 5_000;

/**
 * 带超时/取消/输出上限的子进程封装。
 * - 超时先 SIGTERM，宽限期后 SIGKILL
 * - AbortSignal 触发同样的终止路径
 * - stdout 超过上限时终止进程并抛错（防失控输出撑爆内存）
 */
export function runBinary(bin: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const maxChars = opts.maxOutputChars ?? 256 * 1024 * 1024;
  const command = `${bin} ${args.join(" ")}`;

  return new Promise<RunResult>((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let killer: NodeJS.Timeout | undefined;
    const startedAt = Date.now();

    const kill = (graceful: boolean) => {
      if (child.killed || child.exitCode !== null) return;
      try {
        child.kill(graceful ? "SIGTERM" : "SIGKILL");
      } catch {
        /* already gone */
      }
    };

    const onTimeout = () => {
      kill(true);
      killer = setTimeout(() => kill(false), SIGKILL_GRACE_MS);
      reject(new BackendTimeoutError(command, timeoutMs, stderr));
      settled = true;
    };

    const timer = setTimeout(onTimeout, timeoutMs);
    const onAbort = () => {
      clearTimeout(timer);
      kill(true);
      if (!settled) {
        settled = true;
        reject(new Error(`backend command aborted: ${command}`));
      }
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (stdout.length > maxChars) {
        settled = true;
        clearTimeout(timer);
        kill(true);
        reject(new Error(`backend output exceeded ${maxChars} chars: ${command}`));
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (stderr.length > maxChars) stderr = stderr.slice(-maxChars / 2);
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killer) clearTimeout(killer);
      reject(new BackendSpawnError(command, err.message));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killer) clearTimeout(killer);
      opts.signal?.removeEventListener("abort", onAbort);
      if (code === 0) {
        resolve({ stdout, stderr, durationMs: Date.now() - startedAt, command });
      } else {
        reject(
          new Error(
            `backend command exited with code ${code}: ${command}\nstderr: ${stderr.slice(-4000)}`,
          ),
        );
      }
    });
  });
}

/**
 * 流式按行读取 stdout（用于事件抽取的全量 -T fields 输出，内存有界）。
 * 空行跳过；返回是否被 abort 提前终止。
 */
export async function streamLines(
  bin: string,
  args: string[],
  onLine: (line: string) => void,
  opts: RunOptions & { maxLineChars?: number } = {},
): Promise<{ stderr: string; command: string }> {
  const timeoutMs = opts.timeoutMs ?? 300_000;
  const maxLineChars = opts.maxLineChars ?? 4 * 1024 * 1024;
  const command = `${bin} ${args.join(" ")}`;

  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true });
    let stderr = "";
    let line = "";
    let settled = false;
    let killer: NodeJS.Timeout | undefined;
    let aborted = false;

    const kill = (graceful: boolean) => {
      if (child.killed || child.exitCode !== null) return;
      try {
        child.kill(graceful ? "SIGTERM" : "SIGKILL");
      } catch {
        /* already gone */
      }
    };

    const timer = setTimeout(() => {
      kill(true);
      killer = setTimeout(() => kill(false), SIGKILL_GRACE_MS);
      settled = true;
      reject(new BackendTimeoutError(command, timeoutMs, stderr));
    }, timeoutMs);

    const onAbort = () => {
      aborted = true;
      clearTimeout(timer);
      kill(true);
      if (!settled) {
        settled = true;
        resolve({ stderr, command });
      }
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      if (aborted) return;
      const parts = (line + chunk.toString("utf8")).split("\n");
      line = parts.pop() ?? "";
      for (const l of parts) if (l.length) {
        if (l.length <= maxLineChars) onLine(l);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new BackendSpawnError(command, err.message));
    });
    child.on("close", (code) => {
      if (settled && !aborted) return;
      clearTimeout(timer);
      if (killer) clearTimeout(killer);
      opts.signal?.removeEventListener("abort", onAbort);
      if (aborted) return;
      if (line.length && line.length <= maxLineChars) onLine(line);
      settled = true;
      if (code === 0) resolve({ stderr, command });
      else
        reject(
          new Error(
            `backend command exited with code ${code}: ${command}\nstderr: ${stderr.slice(-4000)}`,
          ),
        );
    });
  });
}
