import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditPypiPackage, normalize } from '../src/pypi.js';

const ids = (f) => f.map((x) => x.id);
const noStats = async () => null;

const pkg = (over = {}) => ({
  info: { name: 'x', version: '1.0.0', author: '', summary: '', ...over.info },
  releases: over.releases ?? { '1.0.0': [{ upload_time_iso_8601: '2025-01-01T00:00:00Z' }] },
  urls: over.urls ?? [{ packagetype: 'bdist_wheel' }],
});

const noAdvisories = async () => [];

const audit = (name, meta) =>
  auditPypiPackage(`pypi:${name}`, {
    resolveMeta: async () => meta,
    resolveStats: noStats,
    resolveAdvisories: noAdvisories,
  });

test('PEP 503: separators are equivalent, so a package is not a typosquat of itself', async () => {
  assert.equal(normalize('mcp_server_fetch'), normalize('mcp-server-fetch'));
  const { findings } = await audit('mcp_server_fetch', pkg());
  assert.ok(!ids(findings).includes('MCP-PY-001'), 'underscore form must not be flagged');
});

test('a known first-party package is not flagged', async () => {
  const { findings } = await audit('mcp-server-git', pkg({ info: { author: 'Anthropic, PBC.' } }));
  assert.deepEqual(ids(findings), []);
});

test('a genuine near-miss name is flagged', async () => {
  const { findings } = await audit('mcp-server-ftch', pkg());
  assert.ok(ids(findings).includes('MCP-PY-001'));
});

test('an unrelated package claiming a first-party author is flagged', async () => {
  const { findings } = await audit('some-tool', pkg({ info: { author: 'Anthropic, PBC.' } }));
  assert.ok(ids(findings).includes('MCP-PY-002'));
});

test('sdist-only is flagged; shipping a wheel is not', async () => {
  const sdistOnly = await audit('thing', pkg({ urls: [{ packagetype: 'sdist' }] }));
  assert.ok(ids(sdistOnly.findings).includes('MCP-PY-004'));

  const withWheel = await audit('thing', pkg({ urls: [{ packagetype: 'sdist' }, { packagetype: 'bdist_wheel' }] }));
  assert.ok(!ids(withWheel.findings).includes('MCP-PY-004'));
});

test('a yanked version is reported', async () => {
  const { findings } = await audit('thing', pkg({ info: { yanked: true, yanked_reason: 'broken' } }));
  assert.ok(ids(findings).includes('MCP-PY-005'));
});

test('an unreachable package yields no findings rather than throwing', async () => {
  const { findings, unreachable } = await auditPypiPackage('pypi:nope', {
    resolveMeta: async () => null, resolveStats: noStats, resolveAdvisories: noAdvisories,
  });
  assert.deepEqual(findings, []);
  assert.ok(unreachable);
});
