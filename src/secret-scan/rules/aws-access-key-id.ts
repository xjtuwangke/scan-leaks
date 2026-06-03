import { SecretRuleConfig } from '../types';

export const awsAccessKeyIdRule: SecretRuleConfig = {
  id: 'aws-access-key-id',
  name: 'AWS Access Key ID',
  description: 'AWS access key pattern',
  severity: 'high',
  pattern: 'AKIA[0-9A-Z]{16}',
  flags: 'i',
  keywords: ['aws', 'access', 'key', 'id'],
};
