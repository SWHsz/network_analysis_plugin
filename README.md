# traffic-analysis-plugin

帮助大模型（DSH / zcode 等 harness 中的 agent）**理解 pcap/pcapng 网络抓包文件**的插件。

核心边界：

> **Plugin 负责「看见什么、怎么查、证据从哪里来」；LLM 负责「这些观测意味着什么」。**
> 工具只输出 observation（可下钻到 frame），不输出「拥塞/攻击/网站慢」类结论。

```text
PCAP ──确定性索引/抽取──▶ Traffic Observation IR ──受约束 Query──▶ 有界 Observation ──▶ LLM 下钻推理 ──▶ Packet-level Evidence
```

## v0.2 能力（围绕三大目的）

| 目的 | 机制 |
|---|---|
| **省上下文** | 紧凑默认投影、12k 渲染预算（砍行不砍列）、`traffic_timeseries` 服务端分箱聚合替代全量帧转储；实测同等分析深度比 v0.1 的 bash 路径省 ~23x（`scripts/context-report.mjs`） |
| **结构化输入** | 5 族 11 种事件（tcp.analysis 家族 + HTTP 事务 + TLS 握手属性 version/cipher/sni）、metrics v3（rtt/吞吐/缺失段/payload/tls_app 字节）、attr.* 按类型校验的查询白名单、**frame scope** 按白名单字段过滤帧 |
| **可检验证据** | `traffic_evidence` 返回固定字段集的帧级原始记录（≤200 帧/次）供模型复核 claim；全部观测携带 frame 级 evidence + audit（backend 版本、query_hash、render_chars） |
| **长尾不锁死** | `traffic_raw_query(display_filter, fields, limit)` 有界逃生口：字段经 tshark 词表校验（附最近似候选）、结构化 argv（无 shell）、有界输出、调用进 audit——覆盖 IR 未预设的查询空间 |
| **有界 SQL（v0.5，S1 增配） | `traffic_sql`/`traffic_schema`：DuckDB-in-Parquet 只读查询层——宽表/attr 拍平/frame_refs 证据侧表/事务 view；语句与函数白名单（文件/系统副作用全拒）、行预算、超时 interrupt；现有 JSON 链路与 8 工具零改动（RFC-001 P7） |
| **协议深化（v0.4）** | `tls_certificate` 事件（CN/SAN，TLS≤1.2）、QUIC stream 模型（Conversation→Stream，`scope:"stream"`）、`traffic_http_timeline` HTTP 事务瀑布；升级路线由 `scripts/promotion-report.mjs` 从真实会话的 raw_query 频次数据驱动 |

## 仓库结构

```text
packages/
├── traffic-core/     # 纯 TS 库：指纹/轻索引/IR/事件抽取/Query/Backend（不依赖 harness）
└── dsh-plugin/       # DeepSeek Harness 插件：10 个 defineTool 的薄胶水
fixtures/             # 确定性测试 pcap（web-session / mid-capture / edge-cases）
docs/                 # 设计文档（见下）与样例规范
scripts/              # generate-samples / verify-pinned-download / dsh-runtime-smoke / context-report
```

## 工具面（DSH）

| 工具 | 语义 |
|---|---|
| `traffic_open(path)` | Capture Identity：指纹、格式、包数、时长。不解析包 |
| `traffic_overview(capture_id)` | 轻索引概览：协议分布、会话计数、top 会话 |
| `traffic_query(capture_id, query)` | 通用 AST 查询：scope∈{conversation,event}，AND-only，字段白名单 + attr.* |
| `traffic_inspect(capture_id, conversation_id)` | 单会话下钻：metrics + 事件时间线 + frame 证据 |
| `traffic_evidence(capture_id, frames\|event_ids)` | 帧级原始记录（固定字段集）复核，≤200 帧/次 |
| `traffic_timeseries(capture_id, conv, metric, bin_ms)` | bytes/packets/window/rtt/tls_bytes 双向分箱，bin∈[10,5000]ms，>500 箱自动加宽 |
| `traffic_raw_query(capture_id, fields, filter, limit)` | 有界逃生口：tshark display filter + 词表校验字段，IR 未覆盖的长尾查询 |
| `traffic_http_timeline(capture_id, conversation_id?)` | HTTP 事务瀑布（配对 + ASCII 时间线，仅明文 HTTP） |
| `traffic_sql(capture_id, sql, limit?)` | 有界只读 SQL（DuckDB）：白名单校验 + 行预算 + 证据约定（S1） |
| `traffic_schema(capture_id)` | SQL 目录：表/列/null 语义/证据可用性/行数（S1） |

典型 agent loop：`open → overview → query(conversation) → inspect → query(event) → evidence 复核`；
时序分析用 `timeseries`；HTTP 页面加载看 `http_timeline`；QUIC 用 `scope:"stream"`；
IR 没有的字段走 `raw_query`。十三轮完整转录见 `docs/samples/`。

`execute` 返回完整规范值（含 audit/provenance），DSH 的 `output.render` 输出有界表格文本
（`{returned,total,offset,truncated}` 信封 + 聚合 frame 列表上限 100）。

## Backend（tshark）策略

解析顺序：**config 显式路径 → 已下载的 pin 版本（4.4.18）→ system tshark →（都没有时）首次运行自动下载 pin 版**。

- 下载带 sha256 校验（TOFU pin），dmg 经 hdiutil 解包并清 quarantine；
- 缓存目录：`$TRAFFIC_PLUGIN_CACHE` > `$XDG_CACHE_HOME` > `~/.cache/traffic-analysis-plugin`；
- 每条 backend 命令带超时/AbortSignal/输出上限；
- **注意**：Wireshark CDN 会下架旧版本，`DOWNLOAD_MANIFEST` 需随官方发布轮换维护；
  下载不可用时回落 system tshark 并在错误信息中给出安装指引。
- 许可证：GPLv2 的 tshark 以独立子进程调用（进程边界分离），不构成衍生作品；勿以 ffi 链接 libwireshark。

性能模型：打开时仅 `capinfos` + `-z conv/phs`（秒级）；事件抽取是**单遍**全量
`-T fields`，按 `capture_id + plugin_version + tshark_version` 落盘缓存，之后所有查询不重扫 pcap。

## 开发

```sh
pnpm install
pnpm build          # traffic-core → dsh-plugin（拓扑序）
pnpm test           # vitest：解析器/查询引擎单测 + 真实 tshark 集成（无 tshark 自动 skip）
pnpm typecheck
pnpm smoke          # 用真实 @deepseek-ai/{cordis,schemastery,dsh-tools} 加载插件并执行六工具全链路
node scripts/context-report.mjs 23.pcap   # v0.2 vs v0.1(bash) 上下文开销对照
node scripts/promotion-report.mjs .       # 挖会话 raw_query 频次 → IR 升级路线图

# 生成/更新样例规范（docs/samples/）
node scripts/generate-samples.mjs
# 端到端验证 pin 下载链路（下载 ~150MB + 解包，需要几分钟）
node scripts/verify-pinned-download.mjs

# 重建测试 fixture（需 scapy）
python3 -m venv /tmp/scapy-venv && /tmp/scapy-venv/bin/pip install scapy
/tmp/scapy-venv/bin/python fixtures/generate.py
```

### 在 DSH 中启用（已在真实环境验证）

**方式一：profile patch 层（推荐，零依赖冲突）**——把插件写进目标 profile 的
`~/.dsh/profiles/<name>/cordis.patch.yml`（每次 boot 自动应用，不碰 node_modules）：

```yaml
- insert:
    - id: traffic-analysis
      name: /abs/path/to/network_analysis_plugin/packages/dsh-plugin/dist/index.js
```

重启 `dsh --profile <name>` 即生效；卸载 = 删掉该条目。绝对路径经 Node 向上
解析时，`@deepseek-ai/*` peer 依赖由 DSH 的全局安装（`~/node_modules`）提供。

**方式二：`dsh plugin add`（官方安装流）**：

```sh
dsh plugin --profile web add /abs/path/to/network_analysis_plugin/packages/dsh-plugin
dsh --profile web --dump-config   # 应出现 "# == dsh-traffic-analysis-plugin" 层
```

注意：要求执行 add 的 pnpm 与当初安装该 profile 的 pnpm **store 一致**
（不一致时报 "node_modules was installed with a different major version of pnpm"，
需在 profile 目录 `pnpm install` 迁移，或改用方式一）。

**坑位备忘（真实踩过）**：
- 新建 profile 只有 `dsh-base` 时没有可启动的 app——boot 后静默空闲（无监听无输出）。
  官方 app bundle（`dsh-web-app` 等）由 DSH CLI 自带的 node_modules 解析，把
  `@deepseek-ai/dsh-web-app` 加进 profile 的 `dsh.profile.bundles` 即可获得 web app；
  但不要尝试 `pnpm add` 它——部分官方 rc 包依赖未公开到 npm（`dsh-code-runtime-worker`）。
- launcher 旗标（`--patch` 等）必须在 app 参数（`--port` 等）之前，否则被 app 的
  commander 拒绝（`unknown option`）。
- 工具进入对话无需额外权限配置：`inject: ['tools']` + `defineTool` 注册即被
  agent loop 使用（官方 tool 教程同款模式）。

### 冒烟已验证的边界

- 插件在真实 DSH web 运行时中经 `--patch` 注入 boot 成功（无加载错误）；
- `scripts/dsh-runtime-smoke.mjs` 用真实 DSH 库驱动：Config schema（真实
  schemastery 校验 + 默认值）、四工具注册、execute + render 全链路、错误自纠路径；
- 编写 DSH 插件的三个易错点（本项目都踩过并修复）：
  1. `Schema` 从 **`@deepseek-ai/schemastery` 默认导入**（cordis 不导出它）；
  2. `output.schema` / `parameters` 是**严格 JSON Schema**：object 节点必须显式
     `additionalProperties: true|false`，否则 boot 即 UNSUPPORTED_SCHEMA；
  3. tsdown 默认把 `dependencies` 外部化——bundled 发布时依赖要放 `devDependencies`。

## 设计文档

| 文档 | 内容 |
|---|---|
| `docs/ir-schema.md` | IR 对象（Capture/Conversation/Event）、detection 语义、缓存新鲜度 |
| `docs/query-dsl.md` | AST 形状、字段白名单、null 语义、结果信封 |
| `docs/event-registry.md` | 3 族 5 种事件、抽取管线、扩展指南 |
| `docs/samples/` | 六轮 agent loop 的定稿样例（样例即规范） |

## 明确不做（v0.5 候选）

zcode MCP 胶水、tshark 二进制 npm 子包、QUIC/HTTP2 stream 层、跨 conversation
事务配对、OR 条件与任意表达式。
