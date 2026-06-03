import { SecretRuleConfig } from '../types';

export const genericHighEntropyHexRule: SecretRuleConfig = {
  id: 'generic-high-entropy-hex',
  name: 'High Entropy Hex Secret',
  description: 'Hex secret-like token',
  severity: 'medium',
  type: 'entropy',
  pattern: '[A-Fa-f0-9]{32,}',
  entropy: {
    enabled: true,
    min_length: 32,
    entropy_threshold: 3.7,
    window_size: 64,
    charset: 'hex',
  },
  keywords: ['secret', 'token', 'api', 'passwd', 'credential', 'key'],
};
