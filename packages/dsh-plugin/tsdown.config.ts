import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  format: "esm",
  // 类型声明由 tsc --emitDeclarationOnly 生成（稳定文件名）
  // traffic-core 打进产物（workspace 协议在 DSH profile 内无法解析）；
  // @deepseek-ai/* 保持外部导入，由 DSH 宿主提供
  external: [/^@deepseek-ai\//],
});
