/** 已终审的 E1 切片题集（--all 默认题集与回填重分类共用；顺序即任务书 Q1–Q5） */
export const SLICE_QUESTION_IDS = ["q-web-001", "q-web-002", "q-edge-001", "q-web-003", "q-web-004"] as const;

/** v0.1 臂名（旧数据读取用，勿改） */
export const ARM_NAMES_V01 = ["bash-v0.1", "ast-v0.4"] as const;

/** 当前协议版本与臂名（v0.2：rawArgs 遥测 + 四段式错误回显 + finish dummy 实例） */
export const PROTOCOL_VERSION = "v0.2";
export const ARM_NAMES = ["bash-v0.2", "ast-v0.5"] as const;
