import { homedir } from "node:os";
import path from "node:path";

/**
 * 缓存根目录：<root>/traffic-analysis-plugin/
 * 优先级：TRAFFIC_PLUGIN_CACHE > XDG_CACHE_HOME > ~/.cache（win: LOCALAPPDATA）
 */
export function resolveCacheRoot(explicit?: string): string {
  if (explicit) return explicit;
  const env = process.env;
  if (env.TRAFFIC_PLUGIN_CACHE) return env.TRAFFIC_PLUGIN_CACHE;
  if (env.XDG_CACHE_HOME) return path.join(env.XDG_CACHE_HOME, "traffic-analysis-plugin");
  if (env.LOCALAPPDATA) return path.join(env.LOCALAPPDATA, "traffic-analysis-plugin");
  return path.join(homedir(), ".cache", "traffic-analysis-plugin");
}
