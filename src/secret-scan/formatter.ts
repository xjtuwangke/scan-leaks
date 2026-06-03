import * as fs from 'fs-extra';
import * as path from 'path';
import { c } from '../logger';
import { SecretScanResult, ScanOutputOptions, SecretFinding } from './types';

export interface ScanOutputRenderer {
  name: string;
  render: (result: SecretScanResult) => string;
}

const outputFormatters: Record<string, ScanOutputRenderer> = {};
const REDACTED = '[REDACTED]';

function createRenderer(name: string, render: (result: SecretScanResult) => string): ScanOutputRenderer {
  return { name, render };
}

function registerBuiltinFormat(name: string, render: (result: SecretScanResult) => string): void {
  outputFormatters[name] = createRenderer(name, render);
}

function normalizeFormatName(format: string): string {
  return format.trim().toLowerCase();
}

export function registerScanOutputFormatter(format: string, render: (result: SecretScanResult) => string): void {
  const normalized = normalizeFormatName(format);
  outputFormatters[normalized] = createRenderer(normalized, render);
}

export function getScanOutputFormatter(format: string = 'summary'): ScanOutputRenderer | undefined {
  const normalized = normalizeFormatName(format);
  return outputFormatters[normalized];
}

export function listScanOutputFormats(): string[] {
  return Object.keys(outputFormatters).sort();
}

function redactValue(value: string): string {
  if (!value) return value;
  if (value.length <= 8) return REDACTED;
  return `${value.slice(0, 4)}...${REDACTED}...${value.slice(-4)}`;
}

function redactSnippet(snippet: string, match: string, redactedMatch: string): string {
  if (!snippet || !match) return snippet;
  return snippet.split(match).join(redactedMatch);
}

export function redactScanResult(result: SecretScanResult): SecretScanResult {
  return {
    ...result,
    findings: result.findings.map((finding) => {
      const redactedMatch = redactValue(finding.match);
      return {
        ...finding,
        match: redactedMatch,
        snippet: redactSnippet(finding.snippet, finding.match, redactedMatch),
      };
    }),
  };
}

export function printSecretScanSummary(result: SecretScanResult): void {
  const sorted = [...result.findings].sort((a, b) => b.line - a.line);
  const grouped = {
    critical: result.findings.filter((f) => f.severity === 'critical').length,
    high: result.findings.filter((f) => f.severity === 'high').length,
    medium: result.findings.filter((f) => f.severity === 'medium').length,
    low: result.findings.filter((f) => f.severity === 'low').length,
  };

  c.header('Secret Scan Result');
  c.bullet('Scanned files', `${result.total_files}`);
  c.bullet('Findings', `${result.findings.length}`);
  c.bullet('Critical', `${grouped.critical}`);
  c.bullet('High', `${grouped.high}`);
  c.bullet('Medium', `${grouped.medium}`);
  c.bullet('Low', `${grouped.low}`);

  if (result.warnings && result.warnings.length > 0) {
    c.bullet('Warnings', `${result.warnings.length}`);
    for (const warning of result.warnings) {
      c.warning(warning);
    }
  }

  if (result.errors && result.errors.length > 0) {
    c.bullet('Errors', `${result.errors.length}`);
    for (const error of result.errors) {
      c.error(error);
    }
  }

  if (result.findings.length > 0) {
    c.header('Top findings (first 20)');
    for (const item of sorted.slice(0, 20)) {
      c.sub(`${item.path}:${item.line}:${item.column} [${item.severity}] ${item.rule_id}`);
      c.dim(`  ${item.snippet.trim()}`);
    }
  } else {
    c.success('No findings');
  }
}

export function toSarif(result: SecretScanResult) {
  const rules = Array.from(
    new Map(result.findings.map((finding) => [
      finding.rule_id,
      {
        id: finding.rule_id,
        shortDescription: { text: finding.rule_id },
        fullDescription: { text: finding.rule_name },
        helpUri: '',
        defaultConfiguration: {
          level: finding.severity === 'low' ? 'note' : finding.severity === 'medium' ? 'warning' : 'error',
        },
      },
    ])).values()
  );
  const ruleIndex = new Map(rules.map((rule, index) => [rule.id, index]));
  const findings = result.findings.map((finding) => ({
    ruleId: finding.rule_id,
    ruleIndex: ruleIndex.get(finding.rule_id) || 0,
    level: finding.severity === 'low' ? 'note' : finding.severity === 'medium' ? 'warning' : 'error',
    message: {
      text: `${finding.rule_name}: ${finding.match}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.path },
          region: {
            startLine: finding.line,
            startColumn: finding.column,
          },
        },
      },
    ],
  }));

  return {
    version: '2.1.0',
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/schema',
    runs: [
      {
        tool: {
          driver: {
            name: 'ai-hub-secret-scan',
            version: '1.0.0',
            rules,
          },
        },
        results: findings,
      },
    ],
  };
}

registerBuiltinFormat('summary', (result) => {
  const sorted = [...result.findings].sort((a, b) => b.line - a.line);
  const grouped = {
    critical: result.findings.filter((f) => f.severity === 'critical').length,
    high: result.findings.filter((f) => f.severity === 'high').length,
    medium: result.findings.filter((f) => f.severity === 'medium').length,
    low: result.findings.filter((f) => f.severity === 'low').length,
  };

  let output = '';
  output += `Secret Scan Result\n`;
  output += `Scanned files: ${result.total_files}\n`;
  output += `Findings: ${result.findings.length}\n`;
  output += `Critical: ${grouped.critical}\n`;
  output += `High: ${grouped.high}\n`;
  output += `Medium: ${grouped.medium}\n`;
  output += `Low: ${grouped.low}\n`;

  if (result.warnings && result.warnings.length > 0) {
    output += `Warnings: ${result.warnings.length}\n`;
  }

  if (result.errors && result.errors.length > 0) {
    output += `Errors: ${result.errors.length}\n`;
  }

  if (result.findings.length > 0) {
    output += 'Top findings (first 20):\n';
    for (const item of sorted.slice(0, 20)) {
      output += `${item.path}:${item.line}:${item.column} [${item.severity}] ${item.rule_id}\n`;
      output += `  ${item.snippet.trim()}\n`;
    }
  } else {
    output += 'No findings\n';
  }

  return output.trimEnd();
});

registerBuiltinFormat('json', (result) => JSON.stringify(result, null, 2));
registerBuiltinFormat('sarif', (result) => JSON.stringify(toSarif(result), null, 2));

const legacyOutputMode = (options: Pick<ScanOutputOptions, 'json' | 'sarif' | 'format'>): string => {
  if (options.json) return 'json';
  if (options.sarif) return 'sarif';
  return options.format || 'summary';
};

export async function outputScanResult(result: SecretScanResult, options: ScanOutputOptions): Promise<void> {
  const format = legacyOutputMode(options);
  const renderer = getScanOutputFormatter(format);

  if (!renderer) {
    throw new Error(`Unsupported output format: ${format}`);
  }

  const displayResult = options.redact === false ? result : redactScanResult(result);
  const body = renderer.render(displayResult);
  if (options.output) {
    await fs.ensureDir(path.dirname(options.output));
    await fs.writeFile(options.output, body, 'utf8');
    c.info(`${format.toUpperCase()} output saved: ${options.output}`);
  } else if (format === 'summary') {
    printSecretScanSummary(displayResult);
  } else {
    console.log(body);
  }
}
