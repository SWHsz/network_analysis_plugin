/**
 * DSH 运行时模块的最小类型声明。
 *
 * @deepseek-ai/dsh-tools 的完整依赖树未发布到公共 npm（dsh-type-meta 为私有），
 * 因此本地开发用这里的最小面；真实运行由 DSH 宿主解析其自带副本。
 * 与官方文档（develop/basic/tool）中的 API 逐字对应。
 */
declare module "@deepseek-ai/cordis" {
  export interface Context {
    tools: { register(tool: unknown): void };
    /** 注册清理回调；插件卸载时调用返回值 */
    effect(dispose: () => void | (() => void)): void;
    on(event: string, listener: (...args: unknown[]) => void): void;
  }
}

declare module "@deepseek-ai/schemastery" {
  /** Schemastery schema 节点（链式构建器；官方 DSH 插件以默认导出 z 使用） */
  export interface SchemaNode {
    default(value: unknown): SchemaNode;
    description(text: string): SchemaNode;
    hidden?(): SchemaNode;
    [key: string]: unknown;
  }
  /** 校验器：把用户配置规范化为 T */
  export interface Schema<T> {
    (value: unknown, config?: unknown): T;
    [key: string]: unknown;
  }
  const z: {
    object<T>(shape: Record<string, SchemaNode>): Schema<T>;
    string(): SchemaNode;
    number(): SchemaNode;
    boolean(): SchemaNode;
    [key: string]: unknown;
  };
  export default z;
}

declare module "@deepseek-ai/dsh-tools" {
  export interface ToolParameterSpec {
    type: "string" | "number" | "boolean" | "object" | "array";
    required?: boolean;
    description?: string;
    properties?: Record<string, ToolParameterSpec>;
    [key: string]: unknown;
  }

  export interface ToolContentPart {
    type: "text";
    text: string;
  }

  export interface ToolDefinition<P, O> {
    name: string;
    description: string;
    parameters: Record<string, ToolParameterSpec>;
    output: {
      /** execute 返回值的规范 schema（供框架校验/程序消费） */
      schema: Record<string, unknown>;
      /** 将规范值转换为模型可见内容（Context Shaper 的宿主挂点） */
      render?: (args: P, value: O) => ToolContentPart[];
    };
    execute(args: P, ctx?: unknown): Promise<O>;
  }

  export function defineTool<P, O>(definition: ToolDefinition<P, O>): unknown;
}
