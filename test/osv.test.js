import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditAdvisories } from '../src/osv.js';

const stub = (vulns) => async () => ({ vulns });

test('a malware advisory is CRITICAL and certain', async () => {
  const out = await auditAdvisories('cloude-code', '0.0.1-security', 'npm', {
    query: stub([{ id: 'MAL-2026-954', summary: 'Malicious code in cloude-code (npm)' }]),
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'MCP-ADV-001');
  assert.equal(out[0].severity, 'critical');
  assert.equal(out[0].confidence, 'certain');
});

test('a normal advisory maps its declared severity and names the fixed version', async () => {
  const out = await auditAdvisories('@modelcontextprotocol/server-filesystem', '2025.1.14', 'npm', {
    query: stub([{
      id: 'GHSA-hc55-p739-j48w',
      summary: 'path validation bypass',
      database_specific: { severity: 'HIGH' },
      affected: [{ ranges: [{ events: [{ introduced: '2025.1.14' }, { fixed: '2025.7.1' }] }] }],
    }]),
  });
  assert.equal(out[0].id, 'MCP-ADV-002');
  assert.equal(out[0].severity, 'high');
  assert.match(out[0].why, /Fixed in 2025\.7\.1/);
  assert.match(out[0].fix, /2025\.7\.1/);
});

test('an unaffected version produces no findings', async () => {
  // OSV filters server-side when given a version, so a patched release returns
  // an empty list. Querying without a version would return historical advisories
  // and report long-fixed issues as live ones.
  const out = await auditAdvisories('@modelcontextprotocol/server-filesystem', '2026.7.10', 'npm', {
    query: stub([]),
  });
  assert.deepEqual(out, []);
});

test('the resolved version is sent to OSV so filtering happens server-side', async () => {
  let sent = null;
  await auditAdvisories('pkg', '1.2.3', 'npm', { query: async (b) => { sent = b; return { vulns: [] }; } });
  assert.deepEqual(sent, { package: { name: 'pkg', ecosystem: 'npm' }, version: '1.2.3' });
});

test('an advisory with no published fix says so rather than inventing one', async () => {
  const out = await auditAdvisories('pkg', '1.0.0', 'npm', {
    query: stub([{ id: 'GHSA-x', summary: 's', database_specific: { severity: 'MODERATE' }, affected: [] }]),
  });
  assert.equal(out[0].severity, 'medium');
  assert.match(out[0].why, /No fixed version is published/);
});

test('a network failure degrades to no findings rather than throwing', async () => {
  const out = await auditAdvisories('pkg', '1.0.0', 'npm', { query: async () => null });
  assert.deepEqual(out, []);
});
