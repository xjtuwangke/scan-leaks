# scan-leaks

独立的秘密信息扫描工具，支持规则引擎 + entropy 高熵规则 + 插件探测器。

## 快速开始

```bash
cd ~/work/scan-leaks
npm install
npm run build
node dist/index.js --help
```

## 常用命令

```bash
# 扫描当前目录
node dist/index.js

# 扫描指定路径
node dist/index.js -p ./src

# 指定规则文件
node dist/index.js -r secret-scan-rules.example.yaml

# 加载规则目录/插件目录
node dist/index.js --rules-dir ./rules
node dist/index.js --plugin-dir ./plugins

# 仅扫描 git 变更文件
node dist/index.js --git-diff
node dist/index.js --git-diff main --git-diff-staged

# 输出 JSON / SARIF
node dist/index.js --json
node dist/index.js --sarif
node dist/index.js --output result.json --format json

# 缓存、基线与严格模式
node dist/index.js --cache --cache-path .ai-hub-secret-scan-cache.json
node dist/index.js --baseline .secret-scan-baseline.json
node dist/index.js --strict
```

## 入口脚本

- `npm run scan -- <args>`：运行扫描
- `node dist/index.js <args>`：直接运行编译产物
- `bin/scan-leaks`：发布后可直接执行（`npm link` 后可用）

## 规则与插件示例

仓库内提供：

- `secret-scan-rules.example.yaml`
- `secret-scan-plugin.example.js`

## 架构目录

- `src/index.ts`：CLI 入口
- `src/secret-scan/*`：扫描引擎（规则、输出、扫描、插件加载）
- `dist/`：`npm run build` 后生成
