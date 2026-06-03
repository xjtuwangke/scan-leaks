import { SecretRuleConfig } from '../types';

export const privateKeyMarkerRule: SecretRuleConfig = {
  id: 'private-key-marker',
  name: 'Private Key Marker',
  description: 'Private key block header',
  severity: 'critical',
  pattern: '-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
  flags: 'i',
  paths: ['*.pem', '*.key', '*.p12', '*.pkcs12', '*.jks'],
};
