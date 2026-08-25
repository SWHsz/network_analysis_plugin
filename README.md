# traffic-analysis-plugin

帮助大模型（DSH / zcode 等 harness 中的 agent）**理解 pcap/pcapng 网络抓包文件**的插件，附一套可复现的 pcap 问答基准 harness（`bench/`）。

核心边界：

> **Plugin 负责「看见什么、怎么查、证据从哪里来」；LLM 负责「这些观测意味着什么」。**
> 工具只输出 observation（可下钻到 frame），不输出「拥塞/攻击/网站慢」类结论。

```text
PCAP ──确定性索引/抽取──▶ Traffic Observation IR ──受约束 Query──▶ 有界 Observation ──▶ LLM 下钻推理 ──▶ Packet-level Evidence
```

## 能力总览（v0.5）

| 目的 | 机制 |
|---|---|
| **省上下文** | 紧凑默认投影、12k 渲染预算（砍行不砍列）、`traffic_timeseries` 服务端分箱聚合替代全量帧转储；实测同等分析深度比裸 bash 路径省 ~23x（`scripts/context-report.mjs`） |
| **结构化输入** | 6 族 12 种事件（tcp.analysis 家族 + DNS/TLS 属性 + HTTP 事务 + tls_certificate）、metrics v3（rtt/吞吐/缺失段/payload/tls_app 字节）、attr.* 按类型校验的查询白名单、frame scope 按白名单字段过滤帧 |
| **可检验证据** | `traffic_evidence` 返回固定字段集的帧级原始记录（≤200 帧/次）供模型复核 claim；全部观测携带 frame 级 evidence + audit（backend 版本、query_hash、render_chars） |
| **长尾不锁死** | `traffic_raw_query(display_filter, fields, limit)` 有界逃生口：字段经 tshark 词表校验（附最近似候选）、结构化 argv（无 shell）、有界输出、调用进 audit——覆盖 IR 未预设的查询空间 |
| **有界 SQL** | `traffic_sql`/`traffic_schema`：DuckDB-in-Parquet 只读查询层——宽表/attr 拍平/frame_refs 证据侧表/事务 view；语句与函数白名单（文件/系统副作用全拒）、行预算、超时 interrupt；与 JSON 查询链路并存 |
| **协议深化** | `tls_certificate` 事件（CN/SAN，TLS≤1.2）、QUIC stream 模型（Conversation→Stream，`scope:"stream"`）、`traffic_http_timeline` HTTP 事务瀑布 |

## 仓库结构

```text
packages/
├── traffic-core/     # 纯 TS 库：指纹/轻索引/IR/事件抽取/Query/SQL/Backend（不依赖 harness）
└── dsh-plugin/       # DeepSeek Harness 插件：10 个 defineTool 的薄胶水
fixtures/             # 确定性测试 pcap（web-session / mid-capture / edge-cases / tls-cert）
ground_truth/         # 生成器导出的 ground truth（*.gt.json，detection_basis: generator_intent）
bench/                # pcap-QA 基准 harness：题库/确定性判分器/两臂 runner/模板派生器
docs/                 # 设计文档与样例规范
scripts/              # generate-samples / verify-pinned-download / dsh-runtime-smoke / context-report / promotion-report / validate_gt
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
| `traffic_sql(capture_id, sql, limit?)` | 有界只读 SQL（DuckDB）：白名单校验 + 行预算 + 证据约定 |
| `traffic_schema(capture_id)` | SQL 目录：表/列/null 语义/证据可用性/行数 |

典型 agent loop：`open → overview → query(conversation) → inspect → query(event) → evidence 复核`；
时序分析用 `timeseries`；HTTP 页面加载看 `http_timeline`；QUIC 用 `scope:"stream"`；
IR 没有的字段走 `raw_query`。十三轮完整转录见 `docs/samples/`。

`execute` 返回完整规范值（含 audit/provenance），DSH 的 `output.render` 输出有界表格文本
（`{returned,total,offset,truncated}` 信封 + 聚合 frame 列表上限 100）。

## Bench：pcap-QA 基准 harness

`bench/` 回答一个问题：**怎么可复现地评测一个 LLM agent 分析 pcap 的能力**——判分全程确定性，不依赖 LLM judge。

三个核心机制：

1. **答案契约**。每道题声明 answer schema；被测 agent 的终答必须是符合 schema 的
   JSON（唯一 ```json fenced block），且每个事实字段自带 `evidence: [帧号]`。
   结构化让 claim 天然可枚举：正确率是查表比对（数值容差/枚举精确/集合三种匹配模式/
   record 逐字段），不是自由文本打分。
2. **gold 来自构造意图**。`ground_truth/*.gt.json` 由 `fixtures/generate.py` 在生成
   pcap 的同时导出（`detection_basis: generator_intent`）——"第 N 帧是重传"在生成时刻
   即为真值，不用被测系统的同款解析器反推 gold，避免循环论证。
3. **判分器先被 benchmark**。每题预置 known_good/known_bad canary 对（覆盖值错/
   证据帧错/格式错三种错误形态），判分器实跑结果必须与题目声明完全一致，
   任一不一致即阻塞——判分器自身有回归门禁。

目录与命令：

```text
bench/questions/        # 手写/起草题（信封校验 + canary 元评测全绿才入库）
bench/questions-auto/   # 模板派生批量题（provenance=generator，抽审后入库）
bench/src/scorer/       # 终答提取 → 契约校验 → 正确率/证据/幻觉判定 → §6.5 报告
bench/src/runner/       # 两臂 runner：共享最小 agent loop，唯一变量是工具面
bench/src/deriver/      # 模板派生器：gt facts → 批量题（含 canary 机械生成）
```

```sh
pnpm --filter bench test          # 判分器单测
node bench/src/schema/validate-questions.mjs   # 全库校验（手写 + 批量稿）
pnpm --filter bench canary        # canary 元评测 CLI（不一致即非零退出）
pnpm --filter bench derive        # gt → 批量题
pnpm --filter bench slice-q1      # 两臂各跑一次示例题（需 LLM API key）
pnpm --filter bench spike-sql     # SQL 查询层连通性验证
```

runner 说明：bash 臂（单 shell 工具）与 ast 臂（插件八工具）共享同一个基于
[Stirrup](https://github.com/ArtificialAnalysis/StirrupJS)（锁 1.0.7）的最小 agent loop，
同模型、同题面、同预算，便于归因工具面差异；每次工具调用的参数/耗时/渲染字符数落盘
transcript，接口注入 token 经本地记录代理实测。切片期保留"终答提取后人工确认再判分"
的半自动断点。

**遥测分账口径**：每轮上下文注入拆为两部分——`ρ_interface`（工具定义/接口描述，
记录代理逐请求实测，固定开销）与 `ρ_render`（工具返回内容投影，随查询可变）。
计量单位：chars 为原始事实，tokens 为 chars/4 估计（不做 tokenizer 精确对齐，
保证跨模型可比）。汇总见各 slice-summary 的 `rho_decomposition` 与 `interface_tax` 块。

**失败分类**：`format_error` 细分为 F6 协议不合规子类（`no_finish_call` 纯文本收尾 /
`finish_payload_invalid` payload 坏 / `no_tool_exploration` 零探索），`max_turns_exhausted`
单列；F7 工具绑定失败（必要参数空到达失败 ≥3 次/run 或同参连败 ≥3）优先于预算桶——
结果五分桶 `forensic_correct / forensic_wrong / protocol_noncompliance / budget_exhausted /
tool_binding_failure`，完成率报双口径（`completion_rate_excluding_F6` 为去除协议失败的
主口径）。多模型批次经 `--model` 路由（DeepSeek 直连或 opengo 转发），产物按模型分目录，
`bench/out/model-matrix.json`（v0.1 协议）与 `bench/out/model-matrix-v02.json`
（含 F7 重分类与复跑对照）聚合跨模型对比。

**v0.2 协议（臂 bash-v0.2 / ast-v0.5）**：每次工具调用在 transcript 记录 `rawArgs`
（executor 入口原始参数串，截断 2000）与 provider 响应体原始 tool_calls 参数（双侧
观测，用于区分 harness 丢参与模型发空参）；参数校验错误四段式回显（问题/收到参数/
空到达标注/期望形状，≤300 chars）；finish 工具描述携带与提取契约同形的已填 dummy
实例（防 schema 回声）。

**预算口径**：切片量级 fixture（≤32 包）统一 maxTurns=8 / maxTokens=4000（输出，含
推理 token）/ timeoutMs=180s，为终局实验参数——该量级下预算宽裕，耗尽即 agent 侧
低效信号；更大 capture 的实验须按规模重新推导预算，不沿用本值。

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
pnpm test           # vitest：解析器/查询引擎单测 + 真实 tshark 集成（无 tshark 自动 skip）+ bench 判分器单测
pnpm typecheck
pnpm smoke          # 用真实 @deepseek-ai/{cordis,schemastery,dsh-tools} 加载插件并执行十工具全链路（含 DuckDB SQL）
node scripts/context-report.mjs 23.pcap   # 结构化路径 vs 裸 bash 的上下文开销对照
node scripts/promotion-report.mjs .       # 挖会话 raw_query 频次 → IR 升级路线图

# 生成/更新样例规范（docs/samples/）
node scripts/generate-samples.mjs
# 端到端验证 pin 下载链路（下载 ~150MB + 解包，需要几分钟）
node scripts/verify-pinned-download.mjs

# 重建测试 fixture + ground truth（需 scapy；已验证 scapy==2.7.0 输出字节级可复现）
python3 -m venv /tmp/scapy-venv && /tmp/scapy-venv/bin/pip install scapy==2.7.0
/tmp/scapy-venv/bin/python fixtures/generate.py
# ground truth 导出：generate.py 只输出 stdout，由重定向落盘（脚本自身不写 JSON 文件）
/tmp/scapy-venv/bin/python fixtures/generate.py --emit-gt web-session > ground_truth/web-session.gt.json
/tmp/scapy-venv/bin/python fixtures/generate.py --emit-gt mid-capture > ground_truth/mid-capture.gt.json
/tmp/scapy-venv/bin/python fixtures/generate.py --emit-gt edge-cases > ground_truth/edge-cases.gt.json
/tmp/scapy-venv/bin/python fixtures/generate.py --emit-gt tls-cert > ground_truth/tls-cert.gt.json
# 约束：重新生成后 4 个 pcap 必须与已提交版本 sha256 一致；ground_truth/*.gt.json 是纯增量导出

# 校验 ground truth：schema/一致性（纯 stdlib）；--spotcheck 用 scapy 读回 pcap 做物理验证
python3 scripts/validate_gt.py
/tmp/scapy-venv/bin/python scripts/validate_gt.py --spotcheck 5
```

**ground truth 语义**：`ground_truth/*.gt.json` 的 gold 帧集来自 `fixtures/generate.py`
生成时刻的构造意图（`detection_basis: generator_intent`），不是事后用 tshark 反推。
帧号 = wrpcap 写入顺序（与 tshark 的 frame.number 一致）；facts 含会话表（含 bytes 线字节数）、
握手三元组、重传（含 of_frame 回链）、DNS 问答（qname/rcode/ttl/address）、HTTP 事务、
TCP 异常（乱序/缺失段/dup_ack/零窗口）；逐帧 intent 上下文与全部语义裁定见
`fixtures/generate.py` 头部注释。

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
| `docs/event-registry.md` | 6 族 12 种事件、抽取管线、扩展指南 |
| `docs/samples/` | 十三轮 agent loop 的定稿样例（样例即规范） |

## 明确不做（下一版候选）

zcode MCP 胶水、tshark 二进制 npm 子包、HTTP2 stream 层、跨 conversation
事务配对、OR 条件与任意表达式。
