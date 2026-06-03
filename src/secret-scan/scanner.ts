import * as fs from 'fs-extra';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { DEFAULT_SECRET_RULES } from './rules';
import { calculateEntropy } from './entropy';
import { CompiledSecretRule, SecretFinding, SecretRuleConfig, SecretScanConfig, SecretScanResult } from './types';

const execFileAsync = promisify(execFile);

interface RuleMatchContext {
  path: string;
  line: number;
  lineText: string;
  lineOffset: number;
}

interface RuleWithRegex extends CompiledSecretRule {
  regex: RegExp;
}

type IgnoreRule = {
  regex: RegExp;
  negate: boolean;
};

function toPosix(filePath: string): string {
  return filePath.split(path.sep).join('/');
}

function toRelativePosix(base: string, target: string): string {
  const relative = path.relative(base, target);
  return toPosix(relative === '' ? '.' : relative);
}

function globBody(pattern: string): string {
  let output = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];
    const afterNext = pattern[index + 2];

    if (char === '*' && next === '*') {
      if (afterNext === '/') {
        output += '(?:.*/)?';
        index += 2;
      } else {
        output += '.*';
        index += 1;
      }
      continue;
    }

    if (char === '*') {
      output += '[^/]*';
      continue;
    }

    if (char === '?') {
      output += '[^/]';
      continue;
    }

    output += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return output;
}

function globToRegex(pattern: string): RegExp {
  const normalized = pattern.trim().replace(/^\/+|\/+$/g, '');
  if (!normalized) {
    return /$a/;
  }

  const body = globBody(normalized);
  if (!normalized.includes('/')) {
    return new RegExp(`(^|.*/)${body}(/.*)?$`);
  }
  return new RegExp(`^${body}$`);
}

function globToGitIgnoreRegex(pattern: string): RegExp {
  const raw = pattern.trim();
  if (!raw) {
    return /$a/;
  }
  const anchored = raw.startsWith('/');
  const directoryOnly = raw.endsWith('/');

  const normalized = raw.replace(/^\/+|\/+$/g, '');
  if (!normalized) {
    return /$a/;
  }

  const body = globBody(normalized);
  const hasSlash = normalized.includes('/');
  let expr = '';

  if (anchored) {
    expr = `^${body}`;
    expr += directoryOnly
      ? '(?:/.*)?$'
      : '$';
    return new RegExp(expr);
  }

  if (hasSlash) {
    if (directoryOnly) {
      expr = `(^|/)${body}(?:/.*)?$`;
    } else {
      expr = `(^|/)${body}$`;
    }
    return new RegExp(expr);
  }

  expr = `(^|.*/)${body}(/.*)?$`;
  return new RegExp(expr);
}

export function createFingerprint(ruleId: string, filePath: string, line: number, match: string): string {
  return crypto.createHash('sha1')
    .update(`${ruleId}|${filePath}|${line}|${match}`)
    .digest('hex');
}

function hashValue(value: string): string {
  return crypto.createHash('sha1').update(value).digest('hex');
}

interface CachedScanEntry {
  mtimeMs: number;
  size: number;
  hash: string;
  signature: string;
  findings: SecretFinding[];
}

interface ScanCache {
  schema: 1;
  signature: string;
  entries: Record<string, CachedScanEntry>;
}

function makeScanSignature(config: SecretScanConfig, rules: SecretRuleConfig[]): string {
  return hashValue(JSON.stringify({
    scannerSchema: 2,
    useDefaultRules: config.useDefaultRules,
    baselinePath: config.baselinePath || null,
    entropyThreshold: config.entropyThreshold || null,
    entropyWindowSize: config.entropyWindowSize || null,
    rulesCount: rules.length,
    rules: rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      severity: rule.severity,
      type: rule.type || 'regex',
      pattern: rule.pattern,
      flags: rule.flags,
      keywords: rule.keywords || [],
      paths: rule.paths || [],
      allowlist: rule.allowlist || [],
      entropy: rule.entropy || null,
    })),
  }));
}

async function loadScanCache(cachePath: string | null): Promise<ScanCache | null> {
  if (!cachePath) return null;
  try {
    if (!(await fs.pathExists(cachePath))) {
      return { schema: 1, signature: '', entries: {} };
    }
    const raw = await fs.readFile(cachePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || parsed.schema !== 1 || !parsed.entries) {
      return { schema: 1, signature: '', entries: {} };
    }
    return parsed as ScanCache;
  } catch {
    return { schema: 1, signature: '', entries: {} };
  }
}

async function saveScanCache(cachePath: string | null, cache: ScanCache): Promise<void> {
  if (!cachePath) return;
  await fs.ensureDir(path.dirname(cachePath));
  await fs.writeFile(cachePath, JSON.stringify(cache, null, 2), 'utf8');
}

function defaultCachePath(config: SecretScanConfig, rootPath: string): string | null {
  if (!config.cachePath) return null;
  if (path.isAbsolute(config.cachePath)) return config.cachePath;
  return path.join(rootPath, config.cachePath);
}

function compileRule(rule: SecretRuleConfig, errors: string[]): CompiledSecretRule | null {
  try {
    const flags = rule.flags ? rule.flags : '';
    const withGlobal = flags.includes('g') ? flags : `${flags}g`;
    return {
      config: rule,
      regex: new RegExp(rule.pattern as string, withGlobal),
    };
  } catch (error) {
    errors.push(`Invalid regex for secret rule ${rule.id}: ${error}`);
    return null;
  }
}

function applyEntropyOverrides(
  rule: SecretRuleConfig,
  entropyThreshold?: number,
  entropyWindowSize?: number,
): SecretRuleConfig {
  if (rule.type !== 'entropy' || !rule.entropy) {
    return rule;
  }

  const entropy = { ...rule.entropy };
  let changed = false;

  if (typeof entropyThreshold === 'number' && Number.isFinite(entropyThreshold) && entropyThreshold > 0) {
    entropy.entropy_threshold = entropyThreshold;
    changed = true;
  }

  if (typeof entropyWindowSize === 'number' && Number.isFinite(entropyWindowSize) && entropyWindowSize > 0) {
    entropy.window_size = entropyWindowSize;
    changed = true;
  }

  if (!changed) {
    return rule;
  }

  return {
    ...rule,
    entropy,
  };
}

function hasKeyword(lineText: string, keywords?: string[]): boolean {
  if (!keywords || keywords.length === 0) return true;
  const lower = lineText.toLowerCase();
  return keywords.some((keyword) => lower.includes(keyword.toLowerCase()));
}

function isAllowed(lineText: string, allowlist?: string[]): boolean {
  if (!allowlist || allowlist.length === 0) return true;
  const text = lineText.toLowerCase();
  return !allowlist.some((item) => text.includes(item.toLowerCase()));
}

function getCharset(ruleConfig: SecretRuleConfig): string {
  if (!ruleConfig.entropy || ruleConfig.entropy.charset === 'base64') {
    return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  }
  if (ruleConfig.entropy.charset === 'hex') {
    return 'abcdefABCDEF0123456789';
  }
  if (ruleConfig.entropy.charset === 'alnum') {
    return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  }
  return '';
}

async function isBinaryFile(filePath: string): Promise<boolean> {
  const sample = await fs.readFile(filePath);
  const sampleLength = Math.min(sample.length, 8192);
  for (let i = 0; i < sampleLength; i++) {
    if (sample[i] === 0) return true;
  }
  return false;
}

function compileIgnoreMatcher(basePath: string, useGitIgnore: boolean, extraPatterns: string[]): { test: (target: string) => boolean } {
  const defaultPatterns = ['.git', '.gitignore', '.idea', '.vscode', 'node_modules', 'dist', 'build', 'coverage', 'tmp', 'out'];
  const rules: IgnoreRule[] = defaultPatterns.map((pattern) => ({ regex: globToRegex(pattern), negate: false }));
  for (const extraPattern of extraPatterns) {
    if (!extraPattern) continue;
    rules.push({ regex: globToRegex(extraPattern), negate: false });
  }
  if (useGitIgnore) {
    const gitignorePath = path.join(basePath, '.gitignore');
    if (fs.pathExistsSync(gitignorePath)) {
      const lines = fs.readFileSync(gitignorePath, 'utf8').split('\n');
      for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const negate = trimmed.startsWith('!');
        const pattern = negate ? trimmed.slice(1).trim() : trimmed;
        if (!pattern) continue;
        rules.push({ regex: globToGitIgnoreRegex(pattern), negate });
      }
    }
  }

  return {
    test: (target: string): boolean => {
      let matched = false;
      for (const rule of rules) {
        if (rule.regex.test(target)) {
          matched = !rule.negate;
        }
      }
      return matched;
    },
  };
}

function compileIgnoreMatchers(
  basePath: string,
  useGitIgnore: boolean,
  extraPatterns: string[]
): { file: (filePath: string) => boolean } {
  const matcher = compileIgnoreMatcher(basePath, useGitIgnore, extraPatterns);
  return {
    file: (filePath: string): boolean => {
      const relative = path.isAbsolute(filePath) ? toRelativePosix(basePath, filePath) : toPosix(filePath);
      return matcher.test(relative);
    },
  };
}

function shouldApplyPathRule(rule: SecretRuleConfig, filePath: string): boolean {
  if (!rule.paths || rule.paths.length === 0) return true;
  const relative = toPosix(filePath);
  return rule.paths.some((pattern) => globToRegex(pattern).test(relative));
}

async function runGitCommand(cwd: string, args: string[]): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync('git', ['-C', cwd, ...args], {
      encoding: 'buffer',
      maxBuffer: 1024 * 1024 * 8,
    });
    return stdout
      .toString('utf8')
      .split('\0')
      .filter((line) => line.length > 0);
  } catch {
    return [];
  }
}

async function resolveGitDiffFiles(
  rootPath: string,
  rootWarn: string[],
  options?: {
    enabled: boolean;
    base?: string | null;
    includeStaged?: boolean;
    includeUntracked?: boolean;
  }
): Promise<string[]> {
  if (!options || !options.enabled) {
    return [];
  }

  const base = options.base;
  let changed: string[] = [];

  if (base) {
    changed = await runGitCommand(rootPath, ['diff', '--name-only', '-z', base]);
  } else {
    const unstaged = await runGitCommand(rootPath, ['diff', '--name-only', '-z']);
    const staged = options.includeStaged === false ? [] : await runGitCommand(rootPath, ['diff', '--name-only', '-z', '--cached']);
    const untracked = options.includeUntracked === false ? [] : await runGitCommand(rootPath, ['ls-files', '--others', '--exclude-standard', '-z']);
    changed = [...unstaged, ...staged, ...untracked];
  }

  if (changed.length === 0) {
    rootWarn.push(`No git diff entries found${base ? ` for base ${base}` : ''}`);
  }

  const fileSet = new Set<string>();
  for (const entry of changed) {
    const absolutePath = path.join(rootPath, entry);
    if (!(await fs.pathExists(absolutePath))) continue;
    const stat = await fs.stat(absolutePath);
    if (!stat.isFile()) continue;
    fileSet.add(absolutePath);
  }
  return [...fileSet];
}

async function loadBaselineFingerprints(pathname?: string | null): Promise<Set<string>> {
  if (!pathname) return new Set();
  if (!(await fs.pathExists(pathname))) return new Set();

  try {
    const raw = await fs.readFile(pathname, 'utf8');
    const parsed = JSON.parse(raw);
    const findings: Array<{ fingerprint?: string }> = Array.isArray(parsed) ? parsed : parsed?.findings || [];
    return new Set(findings.map((f) => f.fingerprint).filter((item): item is string => Boolean(item)));
  } catch {
    return new Set();
  }
}

async function collectFiles(
  rootPath: string,
  ignore: { file: (filePath: string) => boolean },
  maxFileSizeBytes: number,
  includeBinary: boolean,
  files: string[]
): Promise<string[]> {
  const entries = await fs.readdir(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootPath, entry.name);
    if (ignore.file(fullPath)) {
      continue;
    }

    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;
      await collectFiles(fullPath, ignore, maxFileSizeBytes, includeBinary, files);
      continue;
    }

    if (!entry.isFile()) continue;
    const stat = await fs.stat(fullPath);
    if (stat.size > maxFileSizeBytes) continue;
    if (!includeBinary && (await isBinaryFile(fullPath))) continue;
    files.push(fullPath);
  }
  return files;
}

function buildFindingsFromRegex(
  rule: RuleWithRegex,
  context: RuleMatchContext,
  findings: SecretFinding[]
): void {
  const { config, regex } = rule;
  const line = context.lineText;
  regex.lastIndex = 0;
  let match = regex.exec(line);
  while (match) {
    const matched = match[0];
    const column = context.lineOffset + (match.index || 0) + 1;
    if (!hasKeyword(line, config.keywords) || !isAllowed(line, config.allowlist)) {
      match = regex.exec(line);
      continue;
    }
    findings.push({
      rule_id: config.id,
      rule_name: config.name,
      severity: config.severity,
      path: context.path,
      line: context.line,
      column,
      match: matched,
      snippet: context.lineText,
      fingerprint: createFingerprint(config.id, context.path, context.line, matched),
      detector: 'regex',
    });
    if (matched.length === 0) {
      regex.lastIndex += 1;
    }
    match = regex.exec(line);
  }
}

function buildFindingsFromEntropy(
  rule: RuleWithRegex,
  context: RuleMatchContext,
  findings: SecretFinding[]
): void {
  if (!rule.config.entropy || !rule.config.entropy.enabled) return;
  const minLength = rule.config.entropy.min_length || 20;
  const threshold = rule.config.entropy.entropy_threshold || 4.5;
  const configuredWindowSize = rule.config.entropy.window_size;
  const hasWindowSize = typeof configuredWindowSize === 'number' && Number.isFinite(configuredWindowSize) && configuredWindowSize > 0;
  const windowSize = hasWindowSize ? Math.max(configuredWindowSize, minLength) : 0;
  const charset = getCharset(rule.config);
  const line = context.lineText;
  rule.regex.lastIndex = 0;
  let match = rule.regex.exec(line);
  while (match) {
    const value = match[0];
    const matchStart = match.index || 0;
    if (value.length < minLength) {
      match = rule.regex.exec(line);
      continue;
    }
    if (!hasKeyword(line, rule.config.keywords) || !isAllowed(line, rule.config.allowlist)) {
      match = rule.regex.exec(line);
      continue;
    }

    const emitEntropyFinding = (candidate: string, columnOffset: number): void => {
      if (candidate.length < minLength) return;
      const entropy = calculateEntropy(candidate, charset);
      if (entropy < threshold) return;
      findings.push({
        rule_id: rule.config.id,
        rule_name: rule.config.name,
        severity: rule.config.severity,
        path: context.path,
        line: context.line,
        column: context.lineOffset + matchStart + columnOffset + 1,
        match: candidate,
        snippet: line,
        fingerprint: createFingerprint(rule.config.id, context.path, context.line, candidate),
        entropy,
        detector: 'entropy',
      });
    };

    if (hasWindowSize && value.length >= windowSize) {
      if (value.length === windowSize) {
        emitEntropyFinding(value, 0);
      } else {
        for (let windowStart = 0; windowStart <= value.length - windowSize; windowStart += 1) {
          emitEntropyFinding(value.slice(windowStart, windowStart + windowSize), windowStart);
        }
      }
    } else {
      emitEntropyFinding(value, 0);
    }
    if (value.length === 0) {
      rule.regex.lastIndex += 1;
    }
    match = rule.regex.exec(line);
  }
}

async function scanFile(
  filePath: string,
  rootPath: string,
  rules: RuleWithRegex[],
  content: string,
  lines: string[],
  errors: string[],
): Promise<SecretFinding[]> {
  const relativePath = toRelativePosix(rootPath, filePath);
  const findings: SecretFinding[] = [];

  for (const rule of rules) {
    if (!shouldApplyPathRule(rule.config, relativePath)) continue;
    if (!rule.regex) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context: RuleMatchContext = {
        path: relativePath,
        line: i + 1,
        lineText: line,
        lineOffset: 0,
      };
      if (rule.config.type === 'entropy') {
        buildFindingsFromEntropy(rule, context, findings);
      } else {
        buildFindingsFromRegex(rule, context, findings);
      }
    }
  }

  return findings;
}

interface CacheReadResult {
  findings: SecretFinding[];
  fromCache: boolean;
}

async function scanFileWithCache(
  filePath: string,
  rootPath: string,
  rules: RuleWithRegex[],
  baseline: Set<string>,
  cache: ScanCache | null,
  signature: string,
  useCache: boolean,
  errors: string[],
): Promise<CacheReadResult> {
  const relativePath = toRelativePosix(rootPath, filePath);
  let content: string;
  try {
    content = await fs.readFile(filePath, 'utf8');
  } catch {
    return { findings: [], fromCache: false };
  }

  const hash = hashValue(content);
  let stat: fs.Stats;
  try {
    stat = await fs.stat(filePath);
  } catch {
    return { findings: [], fromCache: false };
  }

  const cacheEntry = useCache ? cache?.entries[relativePath] : undefined;
  if (useCache && cacheEntry
    && cacheEntry.signature === signature
    && cacheEntry.mtimeMs === stat.mtimeMs
    && cacheEntry.size === stat.size
    && cacheEntry.hash === hash
  ) {
    return {
      findings: cacheEntry.findings.filter((item) => !baseline.has(item.fingerprint)),
      fromCache: true,
    };
  }

  const findings = await scanFile(filePath, rootPath, rules, content, content.split('\n'), errors);
  if (useCache && cache) {
    cache.entries[relativePath] = {
      mtimeMs: stat.mtimeMs,
      size: stat.size,
      hash,
      signature,
      findings,
    };
  }

  return {
    findings: findings.filter((item) => !baseline.has(item.fingerprint)),
    fromCache: false,
  };
}

export async function runSecretScan(config: SecretScanConfig): Promise<SecretScanResult> {
  const scanTarget = path.resolve(config.rootPath || process.cwd());
  const stat = await fs.stat(scanTarget);
  const isSingleFile = stat.isFile();
  const rootPath = isSingleFile ? path.dirname(scanTarget) : scanTarget;
  const warnings: string[] = [];
  const errors: string[] = [];
  const rawRules = config.useDefaultRules
    ? DEFAULT_SECRET_RULES.map((rule) => applyEntropyOverrides(
      rule,
      config.entropyThreshold,
      config.entropyWindowSize,
    ))
    : [];

  const compiledRules = rawRules
    .map((rule) => compileRule(rule, errors))
    .filter((rule): rule is RuleWithRegex => Boolean(rule && rule.regex));
  const signature = makeScanSignature(config, rawRules);
  const ignore = compileIgnoreMatchers(rootPath, config.useGitIgnore, config.ignorePatterns);
  const baseline = await loadBaselineFingerprints(config.baselinePath || null);
  const useCache = Boolean(config.cachePath);
  const cachePath = defaultCachePath(config, rootPath);
  const cache = await loadScanCache(cachePath);
  let cacheMisses = 0;
  let cacheHits = 0;
  const normalizedCachePath = cachePath ? path.resolve(cachePath) : null;
  const isCachePath = (filePath: string): boolean => (
    Boolean(normalizedCachePath) && path.resolve(filePath) === normalizedCachePath
  );

  if (useCache) {
    if (cache) {
      if (cache.signature && cache.signature !== signature) {
        warnings.push(`Cache signature changed, rebuilding cache: ${cache.signature} -> ${signature}`);
      }
      cache.signature = signature;
      warnings.push(`Incremental cache enabled: ${cachePath}`);
    }
  }

  const filePaths: string[] = isSingleFile
    ? (ignore.file(scanTarget) || isCachePath(scanTarget) ? [] : [scanTarget])
    : config.gitDiff?.enabled
      ? await resolveGitDiffFiles(rootPath, warnings, config.gitDiff)
      : await collectFiles(rootPath, ignore, config.maxFileSizeBytes, config.includeBinary, []);

  const filteredFiles = isSingleFile
    ? filePaths
    : filePaths.filter((filePath) => !ignore.file(filePath) && !isCachePath(filePath));

  if (filteredFiles.length === 0) {
    return {
      generated_at: new Date().toISOString(),
      scanned_path: isSingleFile ? scanTarget : rootPath,
      total_files: 0,
      findings: [],
      warnings: warnings.length > 0 ? warnings : undefined,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  const results: SecretFinding[] = [];
  const concurrency = Math.max(1, config.concurrency || 4);
  let nextIndex = 0;

  const worker = async (): Promise<void> => {
    while (nextIndex < filteredFiles.length) {
      const filePath = filteredFiles[nextIndex++];
      const fileFindings = await scanFileWithCache(
        filePath,
        rootPath,
        compiledRules,
        baseline,
        useCache ? cache : null,
        signature,
        useCache,
        errors,
      );
      if (fileFindings.fromCache) {
        cacheHits += 1;
      } else {
        cacheMisses += 1;
      }
      if (fileFindings.findings.length === 0) {
        continue;
      }
      results.push(...fileFindings.findings);
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  if (useCache && cache) {
    warnings.push(`scan cache hits: ${cacheHits}, misses: ${cacheMisses}`);
    await saveScanCache(cachePath, cache);
  }

  return {
    generated_at: new Date().toISOString(),
    scanned_path: isSingleFile ? scanTarget : rootPath,
    total_files: filteredFiles.length,
    findings: results,
    warnings: warnings.length > 0 ? warnings : undefined,
    errors: errors.length > 0 ? errors : undefined,
  };
}
