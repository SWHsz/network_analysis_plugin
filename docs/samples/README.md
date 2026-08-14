# docs/samples — 样例即规范

`node scripts/generate-samples.mjs`（默认用 `fixtures/web-session.pcap`）生成的端到端转录。
每个文件是一轮工具调用的 `{tool, input, output}` 完整快照，作为：

1. **IR / DSL / 工具行为的对照规范**（实现改动后重新生成并 diff，应当只有时间戳/指纹类字段变化）；
2. **agent loop 的教学样例**（DSH 工具描述里引用的典型顺序即此六轮）。

| 文件 | 轮次 |
|---|---|
| `01-traffic_open.json` | 建立 Capture Identity（不解析包） |
| `02-traffic_overview.json` | 轻索引概览：协议分布 / 会话计数 / top 会话 |
| `03-traffic_query-…` | scope=conversation，`retransmission_count > 0`，按重传排序 |
| `04-traffic_inspect.json` | 下钻 top 会话：metrics + 事件时间线 + 聚合证据 |
| `05-traffic_query-…` | scope=event，单会话重传事件 → frame numbers |
| `06-traffic_query-…` | scope=event，DNS 应答（含 NXDOMAIN rcode 证据） |
| `light-index.json` | 轻索引全文（-z conv/phs 的解析结果） |
| `extraction-summary.json` | 权威 Conversation IR + 全部事件 |

fixture 的已知事实（生成脚本 `fixtures/generate.py` 决定，测试亦对照）：

- conv:tcp:0 = TLS 会话，TCP 握手 70ms、TLS 握手 145ms、3 次重传（frames 8/11/14）；
- conv:tcp:1 = 明文 HTTP，1 次重传（frame 26）；
- conv:udp:0 = DNS，2 组问答；`nonexistent.example` 为 NXDOMAIN（rcode_num=3）；
- conv:udp:1/2 = 噪声（无事件）。
