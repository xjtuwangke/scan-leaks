export function calculateEntropy(value: string, alphabet: string): number {
  if (!value || value.length === 0) return 0;
  const total = value.length;
  const buckets: Record<string, number> = {};

  for (const ch of value) {
    buckets[ch] = (buckets[ch] || 0) + 1;
  }

  let entropy = 0;
  for (const key of Object.keys(buckets)) {
    const frequency = buckets[key] / total;
    entropy -= frequency * Math.log2(frequency);
  }

  const alphabetSize = alphabet ? alphabet.length : 0;
  if (alphabetSize <= 1) {
    return entropy;
  }

  const maxEntropy = Math.log2(alphabetSize);
  return Math.min(entropy, maxEntropy || entropy);
}
