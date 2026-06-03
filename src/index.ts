#!/usr/bin/env node

import { Command } from 'commander';
import path from 'path';
import { outputScanResult, runSecretScan } from './secret-scan';
import { resolveCachePath } from './secret-scan/cache-path';
import { c } from './logger';

const program = new Command();

program
  .name('scan-leaks')
  .description('Standalone secrets scanner with built-in detectors')
  .option('-p, --path <path>', 'Target directory or file', process.cwd())
  .option('--no-gitignore', 'Ignore .gitignore filtering')
  .option('-i, --ignore <pattern...>', 'Additional ignore patterns', [])
  .option('--max-size <bytes>', 'Maximum file size to scan', '1048576')
  .option('--binary', 'Include binary files')
  .option('--concurrency <number>', 'Worker count', '4')
  .option('--git-diff [base]', 'Only scan git-changed files. Optionally provide base ref')
  .option('--no-git-diff-staged', 'Exclude staged files in git-diff mode')
  .option('--no-git-diff-untracked', 'Exclude untracked files in git-diff mode')
  .option('--baseline <path>', 'Baseline JSON to suppress known findings')
  .option('--cache', 'Enable incremental cache with default path')
  .option('--cache-path <path>', 'Enable cache with custom cache file path')
  .option('--json', 'Output JSON to STDOUT')
  .option('--sarif', 'Output SARIF to STDOUT')
  .option('--format <name>', 'Output format name (summary/json/sarif)')
  .option('--output <path>', 'Write scan result to file')
  .option('--no-redact', 'Disable secret redaction in output')
  .option('--entropy-threshold <number>', 'Override entropy threshold for entropy-based rules')
  .option('--entropy-window-size <number>', 'Override entropy window size for entropy-based rules')
  .option('--strict', 'Fail when rule configuration errors are reported')
  .action(async (cmdOptions) => {
    try {
      const maxSize = Number.parseInt(cmdOptions.maxSize, 10);
      const concurrency = Number.parseInt(cmdOptions.concurrency, 10);
      let entropyThreshold: number | undefined;
      if (cmdOptions.entropyThreshold !== undefined) {
        entropyThreshold = Number.parseFloat(cmdOptions.entropyThreshold);
        if (!Number.isFinite(entropyThreshold) || entropyThreshold <= 0) {
          c.error('--entropy-threshold must be a positive number');
          process.exit(1);
        }
      }

      let entropyWindowSize: number | undefined;
      if (cmdOptions.entropyWindowSize !== undefined) {
        entropyWindowSize = Number.parseInt(cmdOptions.entropyWindowSize, 10);
        if (!Number.isFinite(entropyWindowSize) || entropyWindowSize <= 0) {
          c.error('--entropy-window-size must be a positive integer');
          process.exit(1);
        }
      }

      if (!Number.isFinite(maxSize) || maxSize <= 0) {
        c.error('--max-size must be a positive number');
        process.exit(1);
      }

      if (!Number.isFinite(concurrency) || concurrency <= 0) {
        c.error('--concurrency must be a positive number');
        process.exit(1);
      }

      if (cmdOptions.json && cmdOptions.sarif) {
        c.error('Use either --json or --sarif, not both');
        process.exit(1);
      }

      const target = path.resolve(cmdOptions.path || process.cwd());
      const cachePath = resolveCachePath(target, cmdOptions);
      const result = await runSecretScan({
        rootPath: target,
        useDefaultRules: true,
        useGitIgnore: cmdOptions.gitignore,
        ignorePatterns: cmdOptions.ignore || [],
        maxFileSizeBytes: maxSize,
        includeBinary: cmdOptions.binary,
        concurrency,
        gitDiff: cmdOptions.gitDiff !== undefined
          ? {
            enabled: true,
            base: typeof cmdOptions.gitDiff === 'string' ? cmdOptions.gitDiff : null,
            includeStaged: cmdOptions.gitDiffStaged,
            includeUntracked: cmdOptions.gitDiffUntracked,
          }
          : {
            enabled: false,
        },
        entropyThreshold,
        entropyWindowSize,
        baselinePath: cmdOptions.baseline ? path.resolve(cmdOptions.baseline) : null,
        cachePath,
      });

      await outputScanResult(result, {
        json: cmdOptions.json,
        sarif: cmdOptions.sarif,
        output: cmdOptions.output,
        format: cmdOptions.format,
        redact: cmdOptions.redact,
      });

      if (result.findings.length > 0) {
        process.exitCode = 1;
      }
      if (cmdOptions.strict && result.errors && result.errors.length > 0) {
        process.exitCode = 2;
      }
    } catch (error) {
      c.error(`scan-leaks failed: ${error}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
