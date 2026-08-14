# Traffic Observation IR — v0.1 Schema

> 边界原则：**Plugin 输出 observation（可下钻到 frame 的事实），LLM 负责解释。**
> IR 中不存在 `network_condition` / `congestion` / `attack` 之类的高级结论字段。

完整类型见 `packages/traffic-core/src/types.ts`（本文件是可读版，代码是权威）。

## 对象模型

```text
Capture ──┬── Endpoint（内嵌于 Conversation）
          ├── Conversation ── Event
          └── （PacketRef 仅以 evidence.frame_number 形式存在）
```

## Capture

`traffic_open` 的返回，建立 Capture Identity。

| 字段 | 类型 | 说明 |
|---|---|---|
| `capture_id` | string | 内容采样指纹（size+头部+尾部+内部均匀抽样块 → sha256 前 16 hex），`cap_` 前缀。同一文件重新打开得到同一 id |
| `path` / `format` / `size_bytes` | | 绝对路径；pcap/pcapng/unknown |
| `first_packet_epoch` / `last_packet_epoch` | number | epoch 秒（浮点） |
| `duration_ms` / `packet_count` | number | |
| `backend` | `{name:"tshark", version}` | provenance：同一 pcap 在不同 dissector 版本下解析可能不同 |
| `plugin_version` | string | |

## Conversation

两个 endpoint 之间的一次双向传输会话。**方向以 initiator（首个包的发送方）为基准**：
`forward = initiator → responder`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `conversation_id` | string | `conv:{tcp\|udp}:{stream}`，stream 为 backend 流编号（实现细节，仅作 id 不作语义） |
| `transport` | `tcp\|udp` | |
| `initiator` / `responder` | `{ip, port}` | |
| `direction_basis` | `handshake\|port_heuristic\|first_packet` | initiator 方向判定依据。handshake=观测到 SYN（可靠）；port_heuristic=无握手观测时按「知名端口(<1024)侧为 responder」推断（**猜测**，中途抓包常见，NAT/中转场景可能误判）；first_packet=端口无法区分时退化为首包方向 |
| `start_ms` / `duration_ms` | number | 相对捕获起点 |
| `packets` / `bytes` | `{forward, reverse}` | 双向计数 |
| `metrics` | ConversationMetrics | 派生指标（见下） |
| `protocol_tags` | string[] | 仅标记**实际观测到**的协议特征（`tcp`/`udp` + `tls`/`dns`，来自事件证据） |

### ConversationMetrics（v0.2 固定集合）

| 字段 | 来源 | 未观测时 |
|---|---|---|
| `retransmission_count` | 事件聚合 | 0 |
| `dns_query_count` | 事件聚合 | 0 |
| `tls_handshake_count` | ClientHello 计数 | 0 |
| `tcp_handshake_ms` | 首个 SYN → 握手完成的客户端 ACK | null |
| `tls_handshake_ms` | 首个 ClientHello → 首个 ServerHello | null |
| `rtt_median_ms` / `rtt_max_ms` | v0.2：`tcp.analysis.ack_rtt` 样本中位数/最大值（heuristic 投影） | null |
| `throughput_bps` | v0.2：bytes_total×8/duration | null（duration≤0） |
| `missing_segment_count` | v0.2：tcp_missing_segment 事件数 | 0 |
| `http_txn_count` | v0.2：http_request 事件数（事务以 request 计） | 0 |

null 与 0 语义不同：null 表示「未观测到」（如 UDP 会话的 TCP 握手），查询引擎对 null 的数值比较恒为假，仅 `ne` 匹配。

## Event

时间轴上的观测点，全局按时间排序，`event_id` 形如 `evt:000123`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `conversation_id` | string | 归属会话 |
| `type` | EventType | v0.1：`tcp_retransmission` / `dns_query` / `dns_response` / `tls_client_hello` / `tls_server_hello` |
| `time_ms` | number | 相对捕获起点 |
| `direction` | `initiator_to_responder` / `responder_to_initiator` / `unknown` | |
| `attributes` | object | 按 event registry 声明的形状（如 `{variant}`、`{dns_id,qname,rcode_num}`） |
| `detection` | string | **判定来源**。见下节 |
| `evidence` | `{kind:"frame", frame_number}` | 可下钻的物理证据 |

### detection：观测 ≠ ground truth

所有 event 都是 tshark dissector/heuristic 的**投影**：

- `tshark_tcp_analysis` —— 重传判定是启发式（`tcp.analysis.*`），乱序/重复 ACK 边界与其它工具可能有差异；
- `tshark_dns_dissector` / `tshark_tls_dissector` —— 协议 dissect 结果。

下游（LLM）引用 event 时应将其视为「tshark 在此 capture 中如此判定」，而非绝对事实。

## Evidence 与 Provenance

单事件：`evidence = {kind:"frame", frame_number}`。
聚合观测（如 inspect 的重传汇总）：`{kind:"aggregate", frames[], frame_count, truncated}`，
frame 列表上限 100（`AGGREGATE_FRAME_CAP`），超限置 `truncated:true`。

每个工具返回附带 `audit`：

```json
{
  "capture_id": "cap_…",
  "query_hash": "…",
  "backend": "tshark",
  "backend_version": "4.4.8",
  "plugin_version": "0.1.0",
  "backend_commands": ["…实际执行的命令摘要…"]
}
```

形成链条：**LLM claim → observation → event → frame**。

## 缓存与新鲜度

- 索引（`-z conv/phs`）、事件抽取（单遍 `-T fields` → `events.json`）、帧表
  （`frames.json`，固定字段集，供 traffic_evidence / traffic_timeseries）按
  capture_id 落盘：`<cacheRoot>/captures/cap_<id>/{index.json, events.json, frames.json, version}`；
- `version = plugin_version + tshark版本`，任一变化自动失效重建；
- 会话内并发去重（同一 session 的重复调用共享同一个 Promise）。

## 上下文开销度量（v0.2）

每次工具调用的 `audit.render_chars` 记录模型可见渲染字符数（execute 内用与
output.render 相同的函数计算）。`node scripts/context-report.mjs 23.pcap`
给出与 v0.1 真实会话 bash 路径的对照（v0.1：15 次 bash 输出 73477 字符；
v0.2 同等深度 ≈3.2k 字符，约 23x 节省）。
