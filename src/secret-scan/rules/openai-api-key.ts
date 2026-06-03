import { SecretRuleConfig } from '../types';

export const openaiApiKeyRule: SecretRuleConfig = {
  id: 'openai-api-key',
  name: 'OpenAI API Key',
  description: 'OpenAI API key',
  severity: 'critical',
  pattern: 'sk-[a-zA-Z0-9]{20,}',
  keywords: ['openai', 'api', 'key', 'sk-'],
};
