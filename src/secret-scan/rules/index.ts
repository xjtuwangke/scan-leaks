import { SecretRuleConfig } from '../types';
import { awsAccessKeyIdRule } from './aws-access-key-id';
import { awsSecretAccessKeyRule } from './aws-secret-access-key';
import { genericHighEntropyBase64Rule } from './generic-high-entropy-base64';
import { genericHighEntropyHexRule } from './generic-high-entropy-hex';
import { githubPatRule } from './github-pat';
import { jwtTokenRule } from './jwt-token';
import { openaiApiKeyRule } from './openai-api-key';
import { privateKeyMarkerRule } from './private-key-marker';

export const DEFAULT_SECRET_RULES: SecretRuleConfig[] = [
  awsAccessKeyIdRule,
  awsSecretAccessKeyRule,
  githubPatRule,
  openaiApiKeyRule,
  genericHighEntropyBase64Rule,
  genericHighEntropyHexRule,
  privateKeyMarkerRule,
  jwtTokenRule,
];
