import { SecretRuleConfig } from '../types';

export const genericHighEntropyBase64Rule: SecretRuleConfig = {
  id: 'generic-high-entropy-base64',
  name: 'High Entropy Base64 Secret',
  description: 'Base64-like secret-like token',
  severity: 'medium',
  type: 'entropy',
  pattern: '[A-Za-z0-9+/=]{24,}',
  entropy: {
    enabled: true,
    min_length: 24,
    entropy_threshold: 4.3,
    window_size: 64,
    charset: 'base64',
  },
  keywords: ['secret', 'token', 'key', 'password', 'auth'],
};
