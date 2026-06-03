export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface EntropyOptions {
  enabled?: boolean;
  min_length?: number;
  window_size?: number;
  entropy_threshold?: number;
  charset?: 'base64' | 'hex' | 'alnum' | 'any';
}

export interface SecretRuleConfig {
  id: string;
  name: string;
  description?: string;
  severity: RuleSeverity;
  type?: 'regex' | 'entropy';
  pattern?: string;
  flags?: string;
  keywords?: string[];
  paths?: string[];
  allowlist?: string[];
  entropy?: EntropyOptions;
}

export interface SecretScanConfig {
  rootPath: string;
  useDefaultRules: boolean;
  useGitIgnore: boolean;
  ignorePatterns: string[];
  maxFileSizeBytes: number;
  includeBinary: boolean;
  concurrency: number;
  entropyThreshold?: number;
  entropyWindowSize?: number;
  baselinePath?: string | null;
  cachePath?: string | null;
  gitDiff?: {
    enabled: boolean;
    base?: string | null;
    includeStaged?: boolean;
    includeUntracked?: boolean;
  };
}

export interface SecretFinding {
  rule_id: string;
  rule_name: string;
  severity: RuleSeverity;
  path: string;
  line: number;
  column: number;
  match: string;
  snippet: string;
  fingerprint: string;
  entropy?: number;
  detector: 'regex' | 'entropy' | string;
}

export interface SecretScanResult {
  generated_at: string;
  scanned_path: string;
  total_files: number;
  findings: SecretFinding[];
  warnings?: string[];
  errors?: string[];
}

export interface ScanOutputOptions {
  json?: boolean;
  sarif?: boolean;
  output?: string;
  format?: string;
  redact?: boolean;
}

export interface CompiledSecretRule {
  config: SecretRuleConfig;
  regex?: RegExp;
}
