import * as fs from 'fs-extra';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import YAML from 'yaml';
import { DEFAULT_SECRET_RULES } from './default-rules';
import { calculateEntropy } from './entropy';
import { DetectorContext, CompiledSecretRule, SecretDetectorPlugin, SecretFinding, SecretRuleConfig, SecretScanConfig, SecretScanResult } from './types';
import { loadDetectorPlugins, runPluginDetectors } from './plugin-loader';

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

const RULE_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const RULE_TYPES = new Set(['regex', 'entropy']);
const ENTROPY_CHARSETS = new Set(['base64', 'hex', 'alnum', 'any']);

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

interface PluginFileSignature {
  path: string;
  hash: string;
}

function makeScanSignature(config: SecretScanConfig, rules: SecretRuleConfig[], pluginFiles: PluginFileSignature[]): string {
  return hashValue(JSON.stringify({
    scannerSchema: 2,
    useDefaultRules: config.useDefaultRules,
    baselinePath: config.baselinePath || null,
    rulesDirs: (config.rulesDirs || []).slice().sort(),
    pluginDirs: (config.detectorPluginDirs || []).slice().sort(),
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
    pluginFiles,
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

async function collectRuleConfigFiles(dir: string, files: string[]): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectRuleConfigFiles(fullPath, files);
      continue;
    }
    if (!entry.isFile()) continue;
    const lower = fullPath.toLowerCase();
    if (lower.endsWith('.json') || lower.endsWith('.yml') || lower.endsWith('.yaml')) {
      files.push(fullPath);
    }
  }
}

function normalizeRulePayload(raw: unknown): unknown[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (Array.isArray((raw as { rules?: unknown[] }).rules)) {
    return (raw as { rules: unknown[] }).rules;
  }
  return [];
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isPositiveNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

function validateRuleConfig(raw: unknown, source: string, index: number, errors: string[]): SecretRuleConfig | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    errors.push(`Invalid rule in ${source} at index ${index}: expected object`);
    return null;
  }

  const rule = raw as Record<string, unknown>;
  const id = rule.id;
  const name = rule.name;
  const severity = rule.severity;
  const type = rule.type ?? 'regex';
  const pattern = rule.pattern;

  const prefix = `Invalid rule ${typeof id === 'string' ? id : `<index ${index}>`} in ${source}`;
  if (typeof id !== 'string' || id.trim().length === 0) {
    errors.push(`${prefix}: id must be a non-empty string`);
    return null;
  }
  if (typeof name !== 'string' || name.trim().length === 0) {
    errors.push(`${prefix}: name must be a non-empty string`);
    return null;
  }
  if (typeof severity !== 'string' || !RULE_SEVERITIES.has(severity)) {
    errors.push(`${prefix}: severity must be one of critical/high/medium/low`);
    return null;
  }
  if (typeof type !== 'string' || !RULE_TYPES.has(type)) {
    errors.push(`${prefix}: type must be regex or entropy`);
    return null;
  }
  if (typeof pattern !== 'string' || pattern.length === 0) {
    errors.push(`${prefix}: pattern must be a non-empty string`);
    return null;
  }
  if (rule.description !== undefined && typeof rule.description !== 'string') {
    errors.push(`${prefix}: description must be a string`);
    return null;
  }
  if (rule.flags !== undefined && typeof rule.flags !== 'string') {
    errors.push(`${prefix}: flags must be a string`);
    return null;
  }
  if (rule.keywords !== undefined && !isStringArray(rule.keywords)) {
    errors.push(`${prefix}: keywords must be a string array`);
    return null;
  }
  if (rule.paths !== undefined && !isStringArray(rule.paths)) {
    errors.push(`${prefix}: paths must be a string array`);
    return null;
  }
  if (rule.allowlist !== undefined && !isStringArray(rule.allowlist)) {
    errors.push(`${prefix}: allowlist must be a string array`);
    return null;
  }
  if (rule.entropy !== undefined) {
    if (!rule.entropy || typeof rule.entropy !== 'object' || Array.isArray(rule.entropy)) {
      errors.push(`${prefix}: entropy must be an object`);
      return null;
    }
    const entropy = rule.entropy as Record<string, unknown>;
    if (entropy.enabled !== undefined && typeof entropy.enabled !== 'boolean') {
      errors.push(`${prefix}: entropy.enabled must be boolean`);
      return null;
    }
    for (const key of ['min_length', 'window_size', 'entropy_threshold']) {
      if (entropy[key] !== undefined && !isPositiveNumber(entropy[key])) {
        errors.push(`${prefix}: entropy.${key} must be a positive number`);
        return null;
      }
    }
    if (entropy.charset !== undefined && (typeof entropy.charset !== 'string' || !ENTROPY_CHARSETS.has(entropy.charset))) {
      errors.push(`${prefix}: entropy.charset must be one of base64/hex/alnum/any`);
      return null;
    }
  }

  return rule as unknown as SecretRuleConfig;
}

async function loadRuleConfig(rulePath?: string | null, errors?: string[]): Promise<SecretRuleConfig[]> {
  if (!rulePath) return [];
  try {
    const data = await fs.readFile(rulePath, 'utf8');
    const lower = rulePath.toLowerCase();
    const raw = lower.endsWith('.yaml') || lower.endsWith('.yml') ? YAML.parse(data) : JSON.parse(data);
    return normalizeRulePayload(raw)
      .map((rule, index) => validateRuleConfig(rule, rulePath, index, errors || []))
      .filter((rule): rule is SecretRuleConfig => Boolean(rule));
  } catch (error) {
    errors?.push(`Failed to load rule config ${rulePath}: ${error}`);
    return [];
  }
}

async function loadRuleConfigsFromDirs(ruleDirs: string[] | undefined, errors?: string[]): Promise<SecretRuleConfig[]> {
  if (!ruleDirs || ruleDirs.length === 0) return [];
  const allRuleFiles: string[] = [];

  for (const rawDir of ruleDirs) {
    const dir = path.resolve(rawDir);
    if (!(await fs.pathExists(dir))) {
      errors?.push(`Rule directory not found: ${dir}`);
      continue;
    }
    await collectRuleConfigFiles(dir, allRuleFiles);
  }

  const allRules: SecretRuleConfig[] = [];
  for (const filePath of allRuleFiles) {
    const rules = await loadRuleConfig(filePath, errors);
    allRules.push(...rules);
  }
  return allRules;
}

async function collectPluginSignatureFiles(dir: string, files: string[]): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectPluginSignatureFiles(fullPath, files);
      continue;
    }
    if (!entry.isFile()) continue;
    const lower = fullPath.toLowerCase();
    if (lower.endsWith('.js') || lower.endsWith('.mjs') || lower.endsWith('.cjs')) {
      files.push(fullPath);
    }
  }
}

async function loadPluginFileSignatures(pluginDirs: string[] | undefined, errors?: string[]): Promise<PluginFileSignature[]> {
  if (!pluginDirs || pluginDirs.length === 0) return [];
  const files: string[] = [];
  for (const rawDir of pluginDirs) {
    const pluginDir = path.resolve(rawDir);
    if (!(await fs.pathExists(pluginDir))) continue;
    await collectPluginSignatureFiles(pluginDir, files);
  }

  const signatures: PluginFileSignature[] = [];
  for (const filePath of files.sort()) {
    try {
      const content = await fs.readFile(filePath);
      signatures.push({
        path: filePath,
        hash: crypto.createHash('sha1').update(content).digest('hex'),
      });
    } catch (error) {
      errors?.push(`Failed to read detector plugin for cache signature ${filePath}: ${error}`);
    }
  }
  return signatures;
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
  const patterns = [...defaultPatterns, ...extraPatterns];
  const regexps = patterns.map(globToRegex);
  const gitignorePatterns: RegExp[] = [];
  if (useGitIgnore) {
    const gitignorePath = path.join(basePath, '.gitignore');
    if (fs.pathExistsSync(gitignorePath)) {
      const lines = fs.readFileSync(gitignorePath, 'utf8').split('\n');
      for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        if (trimmed.startsWith('!')) continue;
        gitignorePatterns.push(globToRegex(trimmed));
      }
    }
  }

  return {
    test: (target: string): boolean => {
      return [...regexps, ...gitignorePatterns].some((pattern) => pattern.test(target));
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
  const charset = getCharset(rule.config);
  const line = context.lineText;
  rule.regex.lastIndex = 0;
  let match = rule.regex.exec(line);
  while (match) {
    const value = match[0];
    if (value.length < minLength) {
      match = rule.regex.exec(line);
      continue;
    }
    if (!hasKeyword(line, rule.config.keywords) || !isAllowed(line, rule.config.allowlist)) {
      match = rule.regex.exec(line);
      continue;
    }
    const entropy = calculateEntropy(value, charset);
    if (entropy >= threshold) {
      const column = context.lineOffset + (match.index || 0) + 1;
      findings.push({
        rule_id: rule.config.id,
        rule_name: rule.config.name,
        severity: rule.config.severity,
        path: context.path,
        line: context.line,
        column,
        match: value,
        snippet: line,
        fingerprint: createFingerprint(rule.config.id, context.path, context.line, value),
        entropy,
        detector: 'entropy',
      });
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
  plugins: SecretDetectorPlugin[],
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

  if (plugins.length > 0) {
    const detectorContext: DetectorContext = { absolutePath: filePath, relativePath, rootPath, content, lines };
    const pluginFindings = await runPluginDetectors(detectorContext, plugins, errors);
    findings.push(...pluginFindings);
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
  plugins: SecretDetectorPlugin[],
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

  const findings = await scanFile(filePath, rootPath, rules, plugins, content, content.split('\n'), errors);
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
  const rawRules = [
    ...(config.useDefaultRules ? DEFAULT_SECRET_RULES : []),
    ...(await loadRuleConfig(config.rulesPath || null, errors)),
    ...(await loadRuleConfigsFromDirs(config.rulesDirs || [], errors)),
  ];

  const compiledRules = rawRules
    .map((rule) => compileRule(rule, errors))
    .filter((rule): rule is RuleWithRegex => Boolean(rule && rule.regex));
  const pluginFileSignatures = await loadPluginFileSignatures(config.detectorPluginDirs || [], errors);
  const signature = makeScanSignature(config, rawRules, pluginFileSignatures);
  const ignore = compileIgnoreMatchers(rootPath, config.useGitIgnore, config.ignorePatterns);
  const baseline = await loadBaselineFingerprints(config.baselinePath || null);
  const pluginLoadResult = await loadDetectorPlugins(config.detectorPluginDirs || []);
  const plugins = pluginLoadResult.plugins;
  warnings.push(...pluginLoadResult.warnings);
  errors.push(...pluginLoadResult.errors);
  const useCache = Boolean(config.cachePath);
  const cachePath = defaultCachePath(config, rootPath);
  const cache = await loadScanCache(cachePath);
  let cacheMisses = 0;
  let cacheHits = 0;
  const normalizedCachePath = cachePath ? path.resolve(cachePath) : null;
  const isCachePath = (filePath: string): boolean => (
    Boolean(normalizedCachePath) && path.resolve(filePath) === normalizedCachePath
  );

  if (plugins.length > 0) {
    warnings.push(`Loaded ${plugins.length} detector plugin(s)`);
  }
  if (config.rulesDirs && config.rulesDirs.length > 0) {
    warnings.push(`Loaded rule directory: ${config.rulesDirs.join(', ')}`);
  }
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
        plugins,
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
