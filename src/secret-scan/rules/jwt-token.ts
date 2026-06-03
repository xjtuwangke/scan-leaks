import { SecretRuleConfig } from '../types';

export const jwtTokenRule: SecretRuleConfig = {
  id: 'jwt-token',
  name: 'JWT Token',
  description: 'JSON Web Token value',
  severity: 'high',
  pattern: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
  flags: 'g',
  keywords: ['jwt', 'token', 'bearer'],
};
