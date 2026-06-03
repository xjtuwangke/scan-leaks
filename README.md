# scan-leaks

独立的秘密信息扫描工具，基于内置规则（regex + entropy）进行检测，支持 `summary`/`json`/`sarif` 三种输出。

## 快速开始

```bash
cd /Volumes/External/work/scan-leaks
npm install
npm run build
node dist/index.js --help
```

### 从 GitHub 直接用 npx 运行

仓库不要求先 `npm install` 或 `npm publish`，可直接执行：

```bash
npx github:xjtuwangke/scan-leaks -- --help

# 扫描当前目录
npx github:xjtuwangke/scan-leaks -- -p .

# 输出 SARIF 并写入文件
npx github:xjtuwangke/scan-leaks -- -p ./src --sarif --output report.sarif
```

说明：
- `npx github:xjtuwangke/scan-leaks -- <args>` 中的 `--` 用于把参数透传给 `scan-leaks` 命令。
- 本地开发时继续使用：

```bash
npm run build
node dist/index.js --help
```

## 常用命令

```bash
# 扫描当前目录
node dist/index.js

# 扫描指定路径
node dist/index.js -p ./src

# 仅扫描 git 变更文件
node dist/index.js --git-diff
node dist/index.js --git-diff main --git-diff-staged

# 输出 JSON / SARIF
node dist/index.js --json
node dist/index.js --sarif
node dist/index.js --output result.json --format json

# 缓存、基线与严格模式
node dist/index.js --cache --cache-path .scan-leaks-cache.json
node dist/index.js --baseline .scan-leaks-baseline.json
node dist/index.js --strict
```

> 当前版本已移除插件加载与自定义规则配置入口；扫描器默认只使用 `src/secret-scan/rules/` 内置规则。

## 测试用例（scan-case）

`tests/scan-case.test.mjs` 是基于 `node:test` 的集成测试，覆盖：

- 内置规则正向/反向检测
- `.gitignore` 例外规则（否定规则）
- `sarif` 输出字段与工具元信息
- `baseline` 抑制重复告警

### 测试案例目录结构

- `tests/fixtures/scan-case/.gitignore`
  - 规则文件：忽略 `ignored/`，但通过 `!ignored/allow.txt` 回退扫描该文件。
- `tests/fixtures/scan-case/positive-api.txt`
  - 正向示例：触发内置规则 `openai-api-key`。
- `tests/fixtures/scan-case/positive-entropy.txt`
  - 正向示例：触发内置高熵 base64 检测规则。
- `tests/fixtures/scan-case/negative-short.txt`
  - 反向示例：短串，不应命中。
- `tests/fixtures/scan-case/negative-noise.txt`
  - 反向示例：文本噪声，不应命中。
- `tests/fixtures/scan-case/ignored/blocked.txt`
  - 反向示例：受 `.gitignore` 的 `ignored/` 规则命中，应被排除。
- `tests/fixtures/scan-case/ignored/allow.txt`
  - 反向/正向混合示例：受否定规则放行后被扫描，可命中内置规则。

运行测试：

```bash
npm run build
npm test
```

## 源文件职责

- `src/index.ts`
  - CLI 入口：解析命令参数并调用扫描主流程。
- `src/secret-scan/index.ts`
  - 扫描/输出模块的统一导出入口。
- `src/secret-scan/types.ts`
  - 类型定义：扫描规则、命中结果、配置项、输出选项。
- `src/secret-scan/scanner.ts`
  - 扫描核心：文件收集、规则编译、regex/entropy 命中、缓存、git 差异、基线。
- `src/secret-scan/formatter.ts`
  - 负责 `summary`/`json`/`sarif` 的渲染与脱敏。
- `src/secret-scan/entropy.ts`
  - Shannon 熵计算逻辑。
- `src/secret-scan/rules/`
  - 拆分后的内置规则集合。
- `src/secret-scan/cache-path.ts`
  - `--cache`/`--cache-path` 行为与默认缓存路径。
- `src/logger.ts`
  - 控制台日志与格式化输出。

## 测试文件职责

- `tests/scan-case.test.mjs`
  - 验证内置规则的正向/反向命中、`.gitignore` 优先级、SARIF 与 baseline 行为。
- `tests/fixtures/scan-case/...`
  - 提供上述测试的所有输入样例文件。

## 入口方式

- `npm run scan -- <args>`：运行扫描
- `node dist/index.js <args>`：直接运行编译产物
- `bin/scan-leaks`：发布后可直接执行（`npm link` 后可用）
