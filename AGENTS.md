# scan-secrets 仓库约定

## Scope

这是一个独立的 Secret 扫描工具仓库，不依赖上层 `ai-hub` 仓库。

## Build & Run

- 安装依赖：`npm install`
- 编译：`npm run build`
- 运行：`npm run scan -- --help`

## 代码风格

- 保持与 `tools/scan-secrets` 旧版 CLI 兼容（参数与输出格式）。
- 优先在 `src/secret-scan/*` 做检测逻辑改动。
- 插件加载、规则解析错误要保留可读错误信息。
