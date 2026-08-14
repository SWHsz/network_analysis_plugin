import { access, constants, mkdir, readdir, rm, stat, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { platform } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { runBinary, streamLines } from "./spawn.js";
import { sha256File } from "../util.js";

const execFileP = promisify(execFile);

/** pin 的 tshark 版本；缓存 key 与 provenance 都依赖它 */
export const PINNED_TSHARK_VERSION = "4.4.18";

export interface DownloadEntry {
  url: string;
  /** 官方发布物校验和。null 表示未验证、不可用（回退 system） */
  sha256: string | null;
  archive: "dmg" | "tar.gz";
  /** 归档内 tshark 可执行文件的相对路径 */
  binaryRelPath: string;
}

/**
 * 下载清单。sha256 为「首次官方下载时固定」的 pin（TOFU），
 * 没有校验和的平台不启用下载，回退 system tshark。
 *
 * 注意：Wireshark CDN 只保留最近几个版本，URL 命名随版本线变化，
 * 此清单需要随官方发布轮换维护（版本下架 → resolve 报错并提示装 system 版）。
 */
export const DOWNLOAD_MANIFEST: Record<string, DownloadEntry> = {
  "darwin-arm64": {
    url: "https://2.na.dl.wireshark.org/osx/Wireshark%204.4.18%20Arm%2064.dmg",
    sha256: "7a9fc975f54f9df2d984d75123ad95fe336acc70e03dd468ecf6dadc5540b415",
    archive: "dmg",
    binaryRelPath: "Wireshark.app/Contents/MacOS/tshark",
  },
};

export interface BackendConfig {
  /** 用户显式指定的 tshark/capinfos 路径 */
  tsharkPath?: string;
  capinfosPath?: string;
  /** 允许首次使用时下载 pin 版本（默认 true） */
  autoDownload?: boolean;
  /** 每条 backend 命令的默认超时（毫秒） */
  timeoutMs?: number;
  /** 下载缓存目录，默认 <cacheRoot>/backends */
  backendsDir?: string;
}

export interface ResolvedBackend {
  tsharkPath: string;
  capinfosPath: string;
  version: string;
  source: "config" | "pinned" | "system";
}

export class BackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendUnavailableError";
  }
}

async function isFile(p: string): Promise<boolean> {
  try {
    const s = await stat(p);
    return s.isFile();
  } catch {
    return false;
  }
}

async function findOnPath(bin: string, extraDirs: string[]): Promise<string | undefined> {
  const pathDirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  for (const dir of [...pathDirs, ...extraDirs]) {
    const candidate = path.join(dir, bin);
    if (await isFile(candidate)) return candidate;
  }
  return undefined;
}

async function tsharkVersion(bin: string): Promise<string> {
  const res = await runBinary(bin, ["--version"], { timeoutMs: 15_000 });
  const m = /TShark \(Wireshark\)\s+(\d[\w.]*)/.exec(res.stdout);
  if (!m) throw new Error(`cannot parse tshark version from ${bin}`);
  return m[1]!;
}

/**
 * TsharkBackend：负责「如何获得事实」。
 * 解析顺序：config 显式路径 → 已下载的 pin 版本（可自动下载）→ system tshark。
 */
export class TsharkBackend {
  private resolved: ResolvedBackend | undefined;
  readonly defaultTimeoutMs: number;

  constructor(
    private config: BackendConfig = {},
  ) {
    this.defaultTimeoutMs = config.timeoutMs ?? 120_000;
  }

  private get backendsDir(): string {
    return this.config.backendsDir ?? path.join(process.env.TRAFFIC_PLUGIN_CACHE ?? "", "backends");
  }

  private pinnedDir(): string {
    return this.config.backendsDir
      ? path.join(this.config.backendsDir, `tshark-${PINNED_TSHARK_VERSION}`)
      : path.join(
          process.env.TRAFFIC_PLUGIN_CACHE ?? path.join(process.env.HOME ?? "~", ".cache", "traffic-analysis-plugin"),
          "backends",
          `tshark-${PINNED_TSHARK_VERSION}`,
        );
  }

  async resolve(): Promise<ResolvedBackend> {
    if (this.resolved) return this.resolved;

    // 1) 用户显式指定
    const configPath = this.config.tsharkPath;
    if (configPath) {
      if (!(await isFile(configPath))) {
        throw new BackendUnavailableError(`configured tsharkPath does not exist: ${configPath}`);
      }
      const capinfos = this.config.capinfosPath ?? path.join(path.dirname(configPath), "capinfos");
      if (!(await isFile(capinfos))) {
        throw new BackendUnavailableError(
          `capinfos not found next to configured tshark (${capinfos}); install Wireshark CLI tools`,
        );
      }
      this.resolved = {
        tsharkPath: configPath,
        capinfosPath: capinfos,
        version: await tsharkVersion(configPath),
        source: "config",
      };
      return this.resolved;
    }

    // 2) 已下载安装的 pin 版本（不触发下载）
    const entry = DOWNLOAD_MANIFEST[`${platform()}-${process.arch}`];
    const pinned = this.pinnedDir();
    const pinnedTshark = entry ? path.join(pinned, entry.binaryRelPath) : "";
    if (entry && (await isFile(pinnedTshark))) {
      const capinfos = path.join(path.dirname(pinnedTshark), "capinfos");
      if (await isFile(capinfos)) {
        this.resolved = {
          tsharkPath: pinnedTshark,
          capinfosPath: capinfos,
          version: await tsharkVersion(pinnedTshark),
          source: "pinned",
        };
        return this.resolved;
      }
    }

    // 3) system tshark（存在即用，不下载）
    const systemTshark = await findOnPath("tshark", [
      "/opt/homebrew/bin",
      "/usr/local/bin",
      "/Applications/Wireshark.app/Contents/MacOS",
      "C:\\Program Files\\Wireshark",
    ]);
    if (!systemTshark) {
      // 4) 系统没有 tshark：按「首次运行时下载」策略取 pin 版本
      if (entry && entry.sha256 && this.config.autoDownload !== false) {
        await this.downloadPinned(entry, pinned);
        const tsharkPath = path.join(pinned, entry.binaryRelPath);
        this.resolved = {
          tsharkPath,
          capinfosPath: path.join(path.dirname(tsharkPath), "capinfos"),
          version: await tsharkVersion(tsharkPath),
          source: "pinned",
        };
        return this.resolved;
      }
      throw new BackendUnavailableError(
        [
          "tshark backend not found.",
          this.config.autoDownload === false
            ? `autoDownload is disabled; install Wireshark (https://www.wireshark.org) or set tsharkPath.`
            : `No pinned download entry for ${platform()}-${process.arch}; install Wireshark (https://www.wireshark.org) or set tsharkPath.`,
        ].join(" "),
      );
    }
    const capinfos =
      (await findOnPath("capinfos", [])) ??
      path.join(path.dirname(systemTshark), "capinfos");
    if (!(await isFile(capinfos))) {
      throw new BackendUnavailableError(
        `tshark found at ${systemTshark} but capinfos is missing; install full Wireshark CLI tools`,
      );
    }
    this.resolved = {
      tsharkPath: systemTshark,
      capinfosPath: capinfos,
      version: await tsharkVersion(systemTshark),
      source: "system",
    };
    return this.resolved;
  }

  /** 预取 pin 版本（下载 + 校验 + 解包）。已安装则为 no-op。 */
  async ensurePinnedInstalled(): Promise<void> {
    const entry = DOWNLOAD_MANIFEST[`${platform()}-${process.arch}`];
    if (!entry || !entry.sha256) {
      throw new BackendUnavailableError(
        `no pinned download entry for ${platform()}-${process.arch}`,
      );
    }
    const pinned = this.pinnedDir();
    const tsharkPath = path.join(pinned, entry.binaryRelPath);
    const capinfos = path.join(path.dirname(tsharkPath), "capinfos");
    if ((await isFile(tsharkPath)) && (await isFile(capinfos))) return;
    await this.downloadPinned(entry, pinned);
  }

  /** 下载 pin 版本归档，校验 sha256 后解包。 */
  private async downloadPinned(entry: DownloadEntry, dest: string): Promise<void> {
    if (!entry.sha256) throw new BackendUnavailableError("no verified sha256 for pinned download");
    const tmp = path.join(dest, "..", `download-${Date.now()}`);
    await mkdir(path.dirname(tmp), { recursive: true });
    const archive = `${tmp}.archive`;

    // fetch() 流式落盘（Node >= 18）
    const res = await fetch(entry.url);
    if (!res.ok || !res.body) {
      throw new BackendUnavailableError(`failed to download tshark ${entry.url}: HTTP ${res.status}`);
    }
    const { createWriteStream } = await import("node:fs");
    const { Readable } = await import("node:stream");
    await new Promise<void>((resolve, reject) => {
      const ws = createWriteStream(archive);
      Readable.fromWeb(res.body as import("node:stream/web").ReadableStream)
        .pipe(ws)
        .on("finish", () => resolve())
        .on("error", reject);
    });

    const actual = await sha256File(archive);
    if (actual !== entry.sha256) {
      await rm(archive, { force: true });
      throw new BackendUnavailableError(
        `sha256 mismatch for ${entry.url}: expected ${entry.sha256}, got ${actual}`,
      );
    }

    await mkdir(dest, { recursive: true });
    if (entry.archive === "tar.gz") {
      await execFileP("tar", ["-xzf", archive, "-C", dest]);
    } else {
      // macOS dmg：指定固定挂载点（不解析 attach 的表格输出）→ 拷贝 .app → 卸载 → 清 quarantine
      const mountPoint = path.join(path.dirname(dest), `mount-${Date.now()}`);
      await mkdir(mountPoint, { recursive: true });
      await execFileP("hdiutil", [
        "attach",
        "-nobrowse",
        "-readonly",
        "-mountpoint",
        mountPoint,
        archive,
      ]);
      try {
        await execFileP("cp", ["-R", path.join(mountPoint, "Wireshark.app"), dest]);
        try {
          await execFileP("xattr", ["-dr", "com.apple.quarantine", path.join(dest, "Wireshark.app")]);
        } catch {
          /* quarantine 属性不存在时忽略 */
        }
      } finally {
        try {
          await execFileP("hdiutil", ["detach", mountPoint, "-force"]);
        } catch {
          /* 卸载失败不掩盖拷贝阶段的错误 */
        }
        await rm(mountPoint, { recursive: true, force: true });
      }
    }
    // 解包产物完整性校验：失败即清理，防止半成品被 resolve 命中
    if (!(await isFile(path.join(dest, entry.binaryRelPath)))) {
      await rm(dest, { recursive: true, force: true });
      throw new BackendUnavailableError(
        `pinned extraction incomplete: ${entry.binaryRelPath} missing after unpack`,
      );
    }
    await writeFile(
      path.join(dest, "PINNED.json"),
      JSON.stringify({ version: PINNED_TSHARK_VERSION, url: entry.url, sha256: entry.sha256 }, null, 2),
    );
    await rm(archive, { force: true });
  }

  runTshark(args: string[], opts: { timeoutMs?: number; signal?: AbortSignal } = {}) {
    return this.resolve().then((b) =>
      runBinary(b.tsharkPath, args, {
        timeoutMs: opts.timeoutMs ?? this.defaultTimeoutMs,
        signal: opts.signal,
      }),
    );
  }

  async streamTsharkLines(
    args: string[],
    onLine: (line: string) => void,
    opts: { timeoutMs?: number; signal?: AbortSignal } = {},
  ) {
    const b = await this.resolve();
    return streamLines(b.tsharkPath, args, onLine, {
      timeoutMs: opts.timeoutMs ?? Math.max(this.defaultTimeoutMs, 300_000),
      signal: opts.signal,
    });
  }

  async capinfos(file: string): Promise<string> {
    const b = await this.resolve();
    const res = await runBinary(b.capinfosPath, ["-T", "-t", "-u", "-c", "-d", "-a", "-e", file], {
      timeoutMs: 60_000,
    });
    return res.stdout;
  }

  /** 调试用：列出缓存 backends 目录 */
  async listBackends(): Promise<string[]> {
    try {
      return await readdir(this.backendsDir);
    } catch {
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.accessResolve();
      return true;
    } catch {
      return false;
    }
  }

  private async accessResolve(): Promise<void> {
    await this.resolve();
    await access(this.resolved!.tsharkPath, constants.X_OK);
  }
}
