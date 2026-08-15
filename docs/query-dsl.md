# Traffic Query DSL — v0.3

> 表达力 = **Filter + Projection + Ordering + Limit/Offset**。
> 条件之间**只支持 AND**；字段白名单制；不支持 OR / 任意表达式 / join / 函数。

## 查询 AST

```jsonc
{
  "scope": "conversation",        // "conversation" | "event" | "frame"
  "where": [                       // AND 语义
    { "field": "transport", "op": "eq", "value": "tcp" },
    { "field": "retransmission_count", "op": "gt", value: 0 }
  ],
  "select": ["conversation_id", "duration_ms"],   // 省略 = 紧凑默认投影
  "order_by": [{ "field": "duration_ms", "direction": "desc" }],
  "limit": 20,                     // 1..200，默认 50
  "offset": 0
}
```

操作符：`eq` `ne` `gt` `gte` `lt` `lte` `in`（数组值）`contains`（string/string[]）。
**未知 op 立即报错**（无 LIKE/regex）；`type`/`transport` 的值经枚举校验，
拼错即报错并列出全部合法值——杜绝「静默空集」浪费调用轮次。

**null 语义**：未观测的指标为 null（≠0）。null 参与数值比较恒为假，仅 `ne`
（及不含它的 `in`）匹配——防止「无握手观测」被当「0ms 握手」。

**错误返回**：校验失败信息包含该 scope 的完整字段白名单，模型可自纠。

## 紧凑默认投影（v0.2）

不指定 `select` 时输出收敛列集（显式 select 不受影响）：

- **conversation**（10 列）：conversation_id, transport, initiator_ip/port,
  responder_ip/port, duration_ms, bytes_total, retransmission_count, direction_basis
- **event**（5 列）：event_id, conversation_id, type, time_ms, frame_number

配合渲染预算（默认 12k 字符，超出砍行不砍列并标注）控制每步上下文开销；
`audit.render_chars` 记录每次调用的模型可见字符数。

## 字段白名单

### scope = conversation

| 字段 | 类型 | 备注 |
|---|---|---|
| `conversation_id` `transport` `direction_basis` | string | direction_basis: handshake/port_heuristic/first_packet |
| `initiator_ip` `initiator_port` `responder_ip` `responder_port` | string/number | |
| `start_ms` `duration_ms` | number | |
| `packets_forward/reverse/total` `bytes_forward/reverse/total` | number | |
| `retransmission_count` `dns_query_count` `tls_handshake_count` | number | 预计算聚合 |
| `tcp_handshake_ms` `tls_handshake_ms` | number | 可为 null |
| `rtt_median_ms` `rtt_max_ms` | number | v0.2：ack_rtt 启发式样本，可为 null |
| `throughput_bps` | number | v0.2：bytes_total*8/duration，可为 null |
| `missing_segment_count` `http_txn_count` | number | v0.2 |
| `payload_bytes_forward/reverse` | number | v0.3：Σtcp.len（不含头部） |
| `tls_app_bytes` | number | v0.3：Σtls.record.length，非 TLS 为 0 |
| `protocol_tags` | string[] | 用 `contains` 查 |

### scope = frame（v0.3）

来自缓存帧表（不扫 pcap）的白名单字段：`frame_number` `time_ms` `transport`
`ip_src/ip_dst` `src_port/dst_port` `conversation_id`（派生 `conv:{t}:{stream}`）
`tcp_seq_raw/tcp_ack_raw/tcp_len/tcp_flags/tcp_window` `ack_rtt_ms`
`tls_record_bytes` `analysis`（命中的 tcp.analysis 标志，用 `contains` 查）。

默认投影 7 列：frame_number, time_ms, ip_src, ip_dst, tcp_len, tcp_flags, analysis。

### scope = event

基础字段：`event_id` `conversation_id` `type` `direction` `time_ms` `frame_number`。

**attr.* 字段**（v0.2）：按注册表 `queryable` 声明生成，**要求 where 中给出
兼容的 `type eq/in` 条件**（按类型校验，不兼容时报错列出适用类型）：

| attr 字段 | 适用 type | 类型 |
|---|---|---|
| `attr.variant` | tcp_retransmission | string |
| `attr.dup_ack_count` | tcp_dup_ack | number |
| `attr.gap_bytes` / `attr.origin` | tcp_missing_segment | number / string |
| `attr.qname` | dns_query, dns_response | string |
| `attr.rcode_num` | dns_response | number |
| `attr.method` / `attr.host` / `attr.uri` | http_request | string |
| `attr.status_code` / `attr.content_type` | http_response | number / string |

```json
{
  "scope": "event",
  "where": [
    { "field": "type", "op": "eq", "value": "dns_response" },
    { "field": "attr.rcode_num", "op": "eq", "value": 3 }
  ]
}
```

## 结果信封（Context Shaper）

```json
{ "returned": 20, "total": 1831, "offset": 0, "truncated": true, "items": [ … ] }
```

`truncated:true` 时渲染附 `[TRUNCATED]` 提示。聚合 evidence 的 frame 列表
上限 100（`AGGREGATE_FRAME_CAP`）。

## 工具面（v0.3，7 个）

```text
traffic_open / traffic_overview        （Capture Identity / 轻索引概览）
traffic_query(AST)                     （通用入口）
traffic_inspect(conversation_id)       （单会话下钻 + 时间线）
traffic_evidence(frames|event_ids)     （帧级原始记录复核，≤200 帧/次，固定字段集）
traffic_timeseries(conv, metric, bin)  （bytes|packets|window|rtt|tls_bytes 双向分箱，bin∈[10,5000]ms，
                                        >500 箱自动加倍加宽并标 sampled）
traffic_raw_query(fields, filter, lim) （有界逃生口：字段经 tshark -G fields 词表校验，
                                        结构化 argv、行数≤500、单元格≤4k；无效字段（含 display_filter
                                        内的）报错并附词表最近似候选，一步自纠）
```

**逃生口哲学**：预设（IR 注册表）覆盖高频，AST 覆盖组合，raw_query 覆盖长尾——
模型不会被白名单锁死，但长尾路径同样有界、可审计、无注入面。

数据来自按 capture 缓存的单遍抽取（`events.json`）与帧表（`frames.json`），
查询不重扫 pcap。
