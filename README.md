# scan-leaks

A standalone secret leakage scanner built on built-in regex and entropy rules.
Supports `summary`, `json`, and `sarif` output formats.

## Quick start

```bash
cd /Volumes/External/work/scan-leaks
npm install
npm run build
node dist/index.js --help
```

### Run directly from GitHub with npx

No local install or publish required. You can run it directly:

```bash
npx github:xjtuwangke/scan-leaks -- --help

# Scan current directory
npx github:xjtuwangke/scan-leaks -- -p .

# Output SARIF to a file
npx github:xjtuwangke/scan-leaks -- -p ./src --sarif --output report.sarif
```

Notes:
- `npx github:xjtuwangke/scan-leaks -- <args>` uses `--` to pass arguments
  through to `scan-leaks`.
- For local development, continue using:

```bash
npm run build
node dist/index.js --help
```

## Common commands

```bash
# Scan current directory
node dist/index.js

# Scan a specific path
node dist/index.js -p ./src

# Scan only git-changed files
node dist/index.js --git-diff
node dist/index.js --git-diff main --git-diff-staged

# Output JSON / SARIF
node dist/index.js --json
node dist/index.js --sarif
node dist/index.js --output result.json --format json

# Cache, baseline, and strict mode
node dist/index.js --cache --cache-path .scan-leaks-cache.json
node dist/index.js --baseline .scan-leaks-baseline.json
node dist/index.js --strict
```

> This version removes plugin loading and custom rule configuration entry points.
> The scanner uses only built-in rules from `src/secret-scan/rules/` by default.

## Test case set (`scan-case`)

`tests/scan-case.test.mjs` is a `node:test` integration test covering:

- Positive and negative matching for built-in rules
- `.gitignore` exception/negation behavior
- `sarif` output fields and tool metadata
- `baseline` duplicate suppression

### Fixture structure

- `tests/fixtures/scan-case/.gitignore`
  - Ignore `ignored/`, but re-include `!ignored/allow.txt`.
- `tests/fixtures/scan-case/positive-api.txt`
  - Positive sample: triggers the built-in `openai-api-key` rule.
- `tests/fixtures/scan-case/positive-entropy.txt`
  - Positive sample: triggers the built-in high-entropy base64 rule.
- `tests/fixtures/scan-case/negative-short.txt`
  - Negative sample: short string, should not match.
- `tests/fixtures/scan-case/negative-noise.txt`
  - Negative sample: noisy text, should not match.
- `tests/fixtures/scan-case/ignored/blocked.txt`
  - Negative sample: matches `.gitignore` `ignored/`, should be skipped.
- `tests/fixtures/scan-case/ignored/allow.txt`
  - Mixed sample: excluded first, then re-included by negation and scanned.

Run tests:

```bash
npm run build
npm test
```

## Source file responsibilities

- `src/index.ts`
  - CLI entry: parses arguments and starts the scan flow.
- `src/secret-scan/index.ts`
  - Unified exports for scan and output modules.
- `src/secret-scan/types.ts`
  - Type definitions for rules, findings, config, and output options.
- `src/secret-scan/scanner.ts`
  - Core scan pipeline: file collection, rule compilation, regex/entropy matching,
    cache, git diff, and baselines.
- `src/secret-scan/formatter.ts`
  - Renders and redacts results for `summary`/`json`/`sarif`.
- `src/secret-scan/entropy.ts`
  - Shannon entropy calculation.
- `src/secret-scan/rules/`
  - Split built-in rule modules.
- `src/secret-scan/cache-path.ts`
  - `--cache`/`--cache-path` behavior and default cache path.
- `src/logger.ts`
  - Console logging and formatted output.

## Test file responsibilities

- `tests/scan-case.test.mjs`
  - Verifies positive/negative rule matches, `.gitignore` precedence, SARIF and baseline.
- `tests/fixtures/scan-case/...`
  - Provides all fixture inputs for the above tests.

## Entry points

- `npm run scan -- <args>`: run scanner
- `node dist/index.js <args>`: run compiled output directly
- `bin/scan-leaks`: available after publish / `npm link`
