import { SecretRuleConfig } from '../types';

export const githubPatRule: SecretRuleConfig = {
  id: 'github-pat',
  name: 'GitHub Personal Access Token',
  description: 'GitHub PAT pattern',
  severity: 'critical',
  pattern: 'ghp_[A-Za-z0-9_]{36}',
  keywords: ['github', 'token', 'ghp_'],
};
