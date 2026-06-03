import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist', 'index.js');
const FIXTURE_DIR = path.join(ROOT, 'tests', 'fixtures', 'scan-case');

function runScan(args) {
  const child = spawnSync(process.execPath, [DIST, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    windowsHide: true,
  });

  return {
    code: child.status ?? 1,
    stdout: child.stdout || '',
    stderr: child.stderr || '',
  };
}

function runJsonScan(args) {
  const { code, stdout, stderr } = runScan([...args, '--json']);
  if (code !== 0 && code !== 1) {
    assert.fail(`scan failed (${code}): ${stderr || stdout}`);
  }
  return JSON.parse(stdout);
}

function hasFinding(findings, matcher) {
  return findings.some(matcher);
}

test('case: built-in rules detect positives and keep negatives out', () => {
  const result = runJsonScan(['-p', FIXTURE_DIR]);

  assert.ok(result.findings.length > 0, 'expected findings from positive samples');
  assert.ok(hasFinding(result.findings, (item) => item.path === 'positive-api.txt'));
  assert.ok(hasFinding(result.findings, (item) => item.path === 'positive-entropy.txt'));
  assert.ok(hasFinding(result.findings, (item) => item.path === 'positive-jwt.txt'));

  assert.equal(hasFinding(result.findings, (item) => item.path === 'low-entropy-base64.txt'), false);
  const customEntropyResult = runJsonScan(['-p', FIXTURE_DIR, '--entropy-threshold', '0.1']);
  assert.equal(hasFinding(customEntropyResult.findings, (item) => item.path === 'low-entropy-base64.txt'), true);

  assert.equal(hasFinding(result.findings, (item) => item.path === 'ignored/blocked.txt'), false);
  assert.equal(hasFinding(result.findings, (item) => item.path === 'negative-short.txt'), false);
  assert.equal(hasFinding(result.findings, (item) => item.path === 'negative-noise.txt'), false);
});

test('case: SARIF output is valid and uses package metadata', async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(ROOT, 'package.json'), 'utf8'));
  const { code, stdout, stderr } = runScan(['-p', FIXTURE_DIR, '--sarif']);
  if (code !== 0 && code !== 1) {
    assert.fail(`sarif scan failed (${code}): ${stderr || stdout}`);
  }
  const sarif = JSON.parse(stdout);

  assert.equal(sarif.runs[0].tool.driver.name, pkg.name);
  assert.equal(sarif.runs[0].tool.driver.version, pkg.version);
  assert.ok(Array.isArray(sarif.runs[0].results));
});

test('case: baseline file should suppress previously seen fingerprints', async () => {
  const first = runJsonScan(['-p', FIXTURE_DIR]);
  const baseline = { findings: first.findings.map((item) => ({ fingerprint: item.fingerprint })) };
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scan-leaks-case-'));
  const baselinePath = path.join(tmpDir, 'baseline.json');
  try {
    await fs.writeFile(baselinePath, JSON.stringify(baseline, null, 2), 'utf8');
    const second = runJsonScan(['-p', FIXTURE_DIR, '--baseline', baselinePath]);
    assert.equal(second.findings.length, 0);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
