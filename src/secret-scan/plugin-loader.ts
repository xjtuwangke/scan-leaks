import * as fs from 'fs-extra';
import * as path from 'path';
import * as crypto from 'crypto';
import * as vm from 'vm';
import { createRequire } from 'module';
import { pathToFileURL } from 'url';
import {
  DetectorContext,
  DetectorFinding,
  SecretDetectorPlugin,
  SecretFinding,
  RuleSeverity,
} from './types';

type RawDetectorEntry = {
  id: string;
  name?: string;
  scan: (context: DetectorContext) => Promise<DetectorFinding[]> | DetectorFinding[];
};

type RawPluginExport = {
  id?: string;
  name?: string;
  scan?: RawDetectorEntry['scan'];
  detectors?: RawDetectorEntry[];
};

export interface PluginLoadResult {
  plugins: SecretDetectorPlugin[];
  warnings: string[];
  errors: string[];
}

function makeFingerprint(ruleId: string, filePath: string, line: number, match: string): string {
  return crypto.createHash('sha1')
    .update(`${ruleId}|${filePath}|${line}|${match}`)
    .digest('hex');
}

function collectPluginFiles(root: string, files: string[]): void {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      collectPluginFiles(fullPath, files);
      continue;
    }
    if (!entry.isFile()) continue;
    if (fullPath.endsWith('.js') || fullPath.endsWith('.mjs') || fullPath.endsWith('.cjs')) {
      files.push(fullPath);
    }
  }
}

function buildDetector(entry: RawDetectorEntry | undefined, fallbackSource: string): SecretDetectorPlugin | null {
  if (!entry || !entry.id || typeof entry.scan !== 'function') return null;
  return {
    id: entry.id,
    name: entry.name,
    scan: entry.scan,
  };
}

function normalizePluginExport(
  raw: unknown,
  source: string
): SecretDetectorPlugin[] {
  if (typeof raw === 'function') {
    return [
      {
        id: path.basename(source, path.extname(source)),
        scan: raw as RawDetectorEntry['scan'],
      },
    ];
  }

  const moduleExport = raw as RawPluginExport;
  const detectors: SecretDetectorPlugin[] = [];
  if (moduleExport && typeof moduleExport === 'object') {
    const single = buildDetector({
      id: moduleExport.id || path.basename(source, path.extname(source)),
      name: moduleExport.name,
      scan: moduleExport.scan as RawDetectorEntry['scan'],
    }, source);
    if (single) {
      detectors.push(single);
    }
    if (Array.isArray(moduleExport.detectors)) {
      for (const item of moduleExport.detectors) {
        const detector = buildDetector(item, source);
        if (detector) detectors.push(detector);
      }
    }
  }
  return detectors;
}

function toSecretFinding(finding: DetectorFinding, plugin: SecretDetectorPlugin, context: DetectorContext): SecretFinding | null {
  if (!finding.match || finding.match.length === 0) return null;

  const line = Math.max(1, Number(finding.line || 1));
  const column = Math.max(1, Number(finding.column || 1));
  const match = String(finding.match);
  const snippet = finding.snippet || context.lines[line - 1] || '';
  const severity = (finding.severity as RuleSeverity) || 'medium';
  const ruleId = finding.rule_id || plugin.id;

  return {
    rule_id: ruleId,
    rule_name: finding.rule_name || plugin.name || plugin.id,
    severity,
    path: context.relativePath,
    line,
    column,
    match,
    snippet,
    fingerprint: makeFingerprint(ruleId, context.relativePath, line, match),
    entropy: finding.entropy,
    detector: finding.detector || plugin.id,
  };
}

async function loadPluginModule(filePath: string): Promise<Record<string, unknown>> {
  const moduleExt = path.extname(filePath).toLowerCase();

  if (moduleExt === '.mjs') {
    const dynamicImport = new Function('specifier', 'return import(specifier);');
    const stat = await fs.stat(filePath);
    const fileUrl = `${pathToFileURL(filePath).toString()}?mtime=${stat.mtimeMs}`;
    return (await dynamicImport(fileUrl)) as Record<string, unknown>;
  }

  const code = await fs.readFile(filePath, 'utf8');
  const pluginModule = { exports: {} as Record<string, unknown> };
  const localRequire = createRequire(filePath);
  const wrapper = `(function (exports, require, module, __filename, __dirname) { ${code}\n})`;
  const script = new vm.Script(wrapper, { filename: filePath });
  const compiled = script.runInThisContext() as (
    exports: Record<string, unknown>,
    require: NodeRequire,
    module: { exports: Record<string, unknown> },
    filename: string,
    dirname: string
  ) => void;
  compiled(pluginModule.exports, localRequire, pluginModule, filePath, path.dirname(filePath));
  return pluginModule.exports;
}

export async function loadDetectorPlugins(directories: string[] | undefined): Promise<PluginLoadResult> {
  if (!directories || directories.length === 0) {
    return { plugins: [], warnings: [], errors: [] };
  }

  const plugins: SecretDetectorPlugin[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];

  for (const rawDir of directories) {
    const pluginDir = path.resolve(rawDir);
    if (!fs.pathExistsSync(pluginDir)) {
      errors.push(`Plugin directory not found: ${pluginDir}`);
      continue;
    }
    const files: string[] = [];
    collectPluginFiles(pluginDir, files);

    for (const filePath of files) {
      try {
        const loaded = await loadPluginModule(filePath);
        const normalized = normalizePluginExport((loaded.default as Record<string, unknown>) || loaded, filePath);
        if (normalized.length === 0) {
          errors.push(`No valid detector exported by plugin: ${filePath}`);
        }
        plugins.push(...normalized);
      } catch (error) {
        errors.push(`Failed to load detector plugin ${filePath}: ${error}`);
      }
    }
  }

  return { plugins, warnings, errors };
}

export async function runPluginDetectors(
  context: DetectorContext,
  plugins: SecretDetectorPlugin[],
  errors?: string[]
): Promise<SecretFinding[]> {
  const results: SecretFinding[] = [];
  for (const plugin of plugins) {
    try {
      const found = await Promise.resolve(plugin.scan(context));
      for (const rawFinding of found || []) {
        const item = toSecretFinding(rawFinding, plugin, context);
        if (item) {
          results.push(item);
        }
      }
    } catch (error) {
      errors?.push(`Detector plugin ${plugin.id} failed on ${context.relativePath}: ${error}`);
    }
  }
  return results;
}
