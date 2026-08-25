/**
 * finish 工具（v0.2 协议）：SIMPLE_FINISH_TOOL 的同构包装——parameters 与 executor
 * 原样保留（不改变语义），仅在 description 追加一个**已填 dummy 实例**。
 *
 * 背景：deepseek-v4-pro 的 F6 schema 回声（把 answer_schema 图纸当 payload 提交）。
 * 修复定位：schema 是图纸，实例是成品——接口给模型看成品的形状。
 * 红线：实例值必须显式 dummy，禁止出现任何真实题目的真实答案（泄漏 gold 即废基准）；
 * 两臂共用同一 finish 工具（loop 层），对称性由构造保证。
 */
import { SIMPLE_FINISH_TOOL } from "@stirrup/stirrup";

// 示例必须与提取契约同形：裸 answer_schema 节点形态（每字段 {value, evidence}）。
// 首版误用 question_id/answer 信封形态（RFC-002 §2.2 的提交协议），与 extractFinalAnswer
// 只认裸对象的实现矛盾——kimi 实测 6/6 照抄信封导致 protocol 失败，详见 v02-smoke-diagnosis.md。
const FINISH_EXAMPLE = `调用示例（值为示意，必须按当前题面的 answer_schema 替换字段名与值；顶层就是答案字段本身，不要包 question_id/answer 信封）：
{"example_field": {"value": 1, "evidence": [1, 2]}}`;

export const FINISH_TOOL_V02 = {
  ...SIMPLE_FINISH_TOOL,
  description:
    SIMPLE_FINISH_TOOL.description +
    " The reason MUST contain exactly one ```json fenced block holding the filled answer instance " +
    "(NOT the schema itself — never echo $schema/properties/x-kind documents). " +
    FINISH_EXAMPLE,
};
