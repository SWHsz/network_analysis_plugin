# Traffic Query DSL — v0.1

> v0.1 表达力 = **Filter + Projection + Ordering + Limit/Offset**。
> 条件之间**只支持 AND**；字段白名单制；不支持 OR / 任意表达式 / join / 函数。

## 查询 AST

```jsonc
{
  "scope": "conversation",        // "conversation" | "event"
  "where": [                       // AND 语义
    { "field": "transport", "op": "eq", "value": "tcp" },
    { "field": "retransmission_count", "op": "gt", "value": 0 }
  ],
  "select": ["conversation_id", "duration_ms"],   // 省略 = 全部默认字段
  "order_by": [{ "field": "duration_ms", "direction": "desc" }],
  "limit": 20,                     // 1..200，默认 50
  "offset": 0
}
```

操作符：`eq` `ne` `gt` `gte` `lt` `lte` `in`（数组值）`contains`（string/string[]）。

**null 语义**：metrics 中未观测的字段为 null（≠0）。null 参与数值比较恒为假，仅 `ne`（及不含它的 `in`）匹配。这防止模型把「无握手观测」当「0ms 握手」。

**错误返回**：校验失败时错误信息包含该 scope 的完整字段白名单，模型可自纠。

## 字段白名单

### scope = conversation

| 字段 | 类型 | 备注 |
|---|---|---|
| `conversation_id` `transport` | string | |
| `initiator_ip` `initiator_port` `responder_ip` `responder_port` | string/number | |
| `start_ms` `duration_ms` | number | |
| `packets_forward` `packets_reverse` `packets_total` | number | |
| `bytes_forward` `bytes_reverse` `bytes_total` | number | |
| `retransmission_count` `dns_query_count` `tls_handshake_count` | number | 预计算聚合（索引期物化，见 event-registry） |
| `tcp_handshake_ms` `tls_handshake_ms` | number | 可为 null |
| `protocol_tags` | string[] | 用 `contains` 查 |

### scope = event

| 字段 | 类型 | 备注 |
|---|---|---|
| `event_id` `conversation_id` `type` `direction` | string | |
| `time_ms` | number | 相对捕获起点 |
| `frame_number` | number | 证据下钻点 |

注意：`attributes`（qname/rcode 等）v0.1 **不进入** where 白名单——过滤 DNS 事件用 `type`，再在结果里看 attributes。放开 attributes 过滤是 v0.2 议题（需要按 type 校验字段）。

## 结果信封（Context Shaper）

```json
{ "returned": 20, "total": 1831, "offset": 0, "truncated": true, "items": [ … ] }
```

`truncated:true` 时模型应细化查询或翻页，渲染层会附 `[TRUNCATED]` 提示。
聚合 evidence 的 frame 列表上限 100，超限 `truncated:true` + 完整 `frame_count`。

## 与三层工具的关系

```text
traffic_overview / traffic_inspect   （Query Macro：固定 AST 形状）
traffic_query(AST)                    （通用入口）
```

全部经同一执行路径：`validateQuery` → 内存过滤（AND）→ 稳定排序 → 分页 → 投影。
事件/会话数据来自按 capture 缓存的单遍抽取（`events.json`），不重复扫描 pcap。
