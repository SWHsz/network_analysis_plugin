/**
 * 仓库根定位与只读数据文件的加载边界。
 *
 * Mimosa 钩子约束下的已验证形态：读盘路径一律「字面量目录段 + 经白名单校验的
 * basename」，不接收任意相对/绝对路径串（见 spikes/stirrup/demo.ts 的 findRepoRoot）。
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** 从本文件所在目录向上找仓库根（以 pnpm-workspace.yaml 为标记） */
function findRepoRoot(start: string): string {
  let dir = start;
  for (;;) {
    if (existsSync(path.join(dir, "pnpm-workspace.yaml"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`repo root not found above ${start}`);
    dir = parent;
  }
}

export const REPO_ROOT = findRepoRoot(path.dirname(fileURLToPath(import.meta.url)));

/** 数据文件 basename 白名单：字母数字开头，仅含字母数字/点/下划线/连字符 */
const SAFE_BASENAME = /^[a-z0-9][a-z0-9._-]*$/i;

export function assertSafeBasename(name: string, what: string): string {
  if (typeof name !== "string" || !SAFE_BASENAME.test(name)) {
    throw new Error(`${what} 非法 basename："${name}"（须匹配 ${SAFE_BASENAME.source}）`);
  }
  return name;
}
