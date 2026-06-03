import { SecretRuleConfig } from '../types';

export const awsSecretAccessKeyRule: SecretRuleConfig = {
  id: 'aws-secret-access-key',
  name: 'AWS Secret Access Key',
  description: 'AWS secret key pattern',
  severity: 'critical',
  pattern: '[A-Za-z0-9/+=]{40}',
  flags: 'g',
  keywords: ['aws', 'secret', 'access', 'key'],
};
