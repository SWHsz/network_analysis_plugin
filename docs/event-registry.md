# Event Registry — v0.3

注册表是事件类型的**单一来源**：`packages/traffic-core/src/events/registry.ts`。
抽取字段集合（`EXTRACTION_FIELDS`）、attributes 形状、detection 标注、查询白名单
（`EVENT_ATTR_FIELDS`，由 `queryable` 声明生成）、文档均由它派生。

## v0.3 的 5 族 11 种（TLS 族 attributes 扩展）

### TCP 分析族（detection: tshark_tcp_analysis）

| type | attributes | tshark 来源 | 说明 |
|---|---|---|---|
| `tcp_retransmission` | `{variant: plain\|fast\|spurious}` | `tcp.analysis.{retransmission, fast_retransmission, spurious_retransmission}` | 重传（启发式投影） |
| `tcp_out_of_order` | `{}` | `tcp.analysis.out_of_order` | 乱序到达。**触发条件苛刻**（Wireshark 要求迟到段在接收方最后 ACK 后 ~3ms 内且此前未见）——未标记 ≠ 没有乱序 |
| `tcp_dup_ack` | `{dup_ack_count}` | `tcp.analysis.duplicate_ack(_num)` | 重复 ACK 及其在系列中的序号 |
| `tcp_zero_window` | `{}` | `tcp.analysis.zero_window` | 零窗口通告 |
| `tcp_missing_segment` | `{gap_bytes, origin}` | `tcp.analysis.lost_segment` | 缺失段。gap_bytes 相对流内该方向已见最高连续序号；origin: `mid_stream`（中途缺口）/`capture_start`（抓包起点前已有数据）。**不标记不等于没丢包**（缺口两端都没被捕获时无从判定） |

### DNS 族 / TLS 族（v0.3 扩展 attributes）

- `dns_query` `{dns_id,qname,qtype}`、`dns_response` `{dns_id,qname,rcode_num}`；
- `tls_client_hello` `{version, sni, cipher_count}`（v0.3：sni 可推断目标站点；
  完整套件列表过长不入 IR，需要时走 traffic_raw_query）；
- `tls_server_hello` `{version, cipher}`（v0.3：cipher 如 0x1301）。

### HTTP 族（v0.2 新增，detection: tshark_http_dissector）

| type | attributes | tshark 来源 |
|---|---|---|
| `http_request` | `{method, host, uri}` | `http.request.method` `http.host` `http.request.uri` |
| `http_response` | `{status_code, content_type, resp_time_ms}` | `http.response.code` `http.content_type` `http.time` |

HTTP 事件经 TCP 重组还原（响应跨多个 TCP 段时事件帧号为重组完成帧）；
`resp_time_ms` 来自 `http.time`，未配对为 null。

## 抽取管线（单遍，v0.2 扩展）

一次 `tshark -T fields` 全量遍历同时产出：

1. **Conversation IR**（权威）：端点、方向计数、双向字节；
2. **metrics v2**：`rtt_median_ms`/`rtt_max_ms`（`tcp.analysis.ack_rtt` 样本，heuristic）、
   `throughput_bps`、`missing_segment_count`、`http_txn_count`（以 request 计）；
3. **全部事件**，全局按时间排序，`event_id` 稳定编号。

布尔标志判定按 occurrence 聚合拆分（`"1,1"` 亦为真）。SYN/SYNACK 建立方向序号基线
（SYN 占 1 序号），用于 gap 计算。结果按 `capture_id + plugin_version + tshark_version`
缓存落盘（`events.json`）。

第二次懒遍历（`frames.json`，固定字段集 `FRAMES_FIELDS`）为
`traffic_evidence`（帧级原始记录复核）与 `traffic_timeseries`（分箱聚合）服务。

## 扩展一种事件类型

1. `registry.ts`：`EventType` 加名字；`EVENT_REGISTRY` 加 spec
   （`queryable` 标记哪些 attributes 进 `attr.*` 查询白名单）；
2. `extract.ts` 的 feed()：写字段映射（协议相关，无法纯声明式）；
3. metrics 需要时在 `ConversationMetrics` 加字段并在 finish() 聚合；
4. where 白名单投影在 `query/ast.ts`；
5. 测试：fixtures/generate.py 加流量 + 断言。

基础设施成本按「一遍扫描」计，与事件种类数无关。

## 已知的判定边界（下游须知的诚实标注）

- 重传/乱序/缺失段全部是 tshark 启发式**投影**：out_of_order 触发条件苛刻
  （~3ms 时序窗 + 未见过 + fast-retrans 优先级），lost_segment 依赖缺口两端至少
  一端被捕获；
- `detection` 字段标明来源；LLM 引用应表述为「tshark 判定为 X」。

## 不做（v0.3 候选）

QUIC/HTTP2 stream 层、跨 conversation 事务配对、SACK 分析。
