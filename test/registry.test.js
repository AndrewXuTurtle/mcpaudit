import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditPackage } from '../src/registry.js';

/**
 * npm publishes a placeholder when its security team removes a package for
 * malware. Detecting that is the highest-confidence signal this tool has: not
 * "this looks risky" but "npm confirmed this was malicious". Verified against
 * the real `cloude-code` and `cloude` takedowns, which impersonated Claude Code
 * and appear in Microsoft Defender's MCP supply-chain signature.
 */
const held = {
  'dist-tags': { latest: '0.0.1-security' },
  time: { created: '2026-02-20T00:00:00Z', '0.0.1-security': '2026-02-20T00:00:00Z' },
  versions: { '0.0.1-security': { description: 'security holding package', scripts: {} } },
};

const healthy = {
  'dist-tags': { latest: '2.1.220' },
  time: { created: '2025-01-01T00:00:00Z', '2.1.220': '2026-07-01T00:00:00Z' },
  versions: { '2.1.220': { description: 'a real package', scripts: {} } },
};

// auditPackage reaches the network for download counts; stub fetch so these
// assertions stay deterministic and offline.
function withRegistry(meta, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => ({
    ok: true,
    json: async () => (String(url).includes('api.npmjs.org') ? { downloads: 10 } : meta),
  });
  return fn().finally(() => { globalThis.fetch = real; });
}

test('a security-held package is reported CRITICAL', async () => {
  await withRegistry(held, async () => {
    const { findings } = await auditPackage('cloude-code');
    const f = findings.find((x) => x.id === 'MCP-SUP-007');
    assert.ok(f, 'expected MCP-SUP-007');
    assert.equal(f.severity, 'critical');
    assert.equal(f.confidence, 'certain');
  });
});

test('an ordinary package is not mistaken for a security hold', async () => {
  await withRegistry(healthy, async () => {
    const { findings } = await auditPackage('@anthropic-ai/claude-code@2.1.220');
    assert.ok(!findings.some((x) => x.id === 'MCP-SUP-007'));
  });
});
