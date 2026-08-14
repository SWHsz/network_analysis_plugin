# Event Registry — v0.1

注册表是事件类型的**单一来源**：`packages/traffic-core/src/events/registry.ts`。
抽取字段集合（`EXTRACTION_FIELDS`）、attributes 形状、detection 标注、文档均由它派生。

## v0.1 冻结的 5 种（3 族）

| type | detection | attributes | tshark 来源 |
|---|---|---|---|
| `tcp_retransmission` | tshark_tcp_analysis | `{variant: "plain"\|"fast"\|"spurious"}` | `tcp.analysis.{retransmission, fast_retransmission, spurious_retransmission}` |
| `dns_query` | tshark_dns_dissector | `{dns_id, qname, qtype}` | `dns.id` `dns.qry.name` `dns.qry.type` |
| `dns_response` | tshark_dns_dissector | `{dns_id, qname, rcode_num}` | + `dns.flags.response` `dns.flags.rcode` |
| `tls_client_hello` | tshark_tls_dissector | `{}` | `tls.handshake.type=1` |
| `tls_server_hello` | tshark_tls_dissector | `{}` | `tls.handshake.type=2` |

`detection` 的含义：这些事件是 tshark dissector/启发式的**投影**，不是 ground truth。
尤其重传判定在乱序/重复 ACK 边界上与其它实现（tcptrace、Zeek）可能有出入。
LLM 引用时应表述为「tshark 判定为重传」。

## 抽取管线（单遍）

一次 `tshark -T fields` 全量遍历同时产出：

1. **Conversation IR**（权威，覆盖轻索引的 conv 近似值）：端点、方向计数、双向字节；
2. **metrics**：TCP 握手耗时（SYN→客户端 ACK）、TLS 握手耗时（CH→SH）、各类事件计数；
3. **全部事件**，全局按时间排序，`event_id` 稳定编号。

结果按 `capture_id + plugin_version + tshark_version` 缓存落盘（`events.json`），
此后所有 event/conversation 查询走缓存，**不再扫 pcap**。

字段布局采用「名字→列号」映射（`COL`），与 `-e` 参数顺序解耦，
注册表加字段不会引发错位 bug。

## 扩展一种事件类型

1. `registry.ts`：`EventType` 联合类型加名字；`EVENT_REGISTRY` 加一条 spec
   （`type` / `detection` / `description` / `attributes` 形状 / `source.tsharkFields`）；
2. `extract.ts` 的 feed()：在对应字段上写映射逻辑（协议相关，无法纯声明式）；
3. 如需 conversation 级 metrics，在 `ConversationMetrics` 加字段并在 finish() 聚合；
4. 如需进入 where 白名单，在 `query/ast.ts` 的 `CONVERSATION_FIELDS`/`EVENT_FIELDS` 加投影；
5. 测试：fixtures/generate.py 加对应流量 + 集成断言。

基础设施成本按「一遍扫描」计，与事件种类数无关——`tcp.analysis.*` 家族
（out-of-order / dup-ack / zero-window …）在 v0.2 基本可以免费搭车加入。

## v0.1 明确不做

- QUIC/HTTP transaction 层（Stream/Transaction 对象在 IR 里预留位置，未实现）；
- attributes 进入 where 白名单；
- Raw Escape Hatch（`traffic_raw_query`）。
