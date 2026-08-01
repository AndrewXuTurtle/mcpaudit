import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refuteBackwardsImpersonation } from '../src/registry.js';

/**
 * Regression guard for accusing the innocent.
 *
 * A sweep of 1,267 lookalike names surfaced `cp-remote` (first published 2014)
 * and `mp-remote` (2020) as near-matches for `mcp-remote`. Both predate the
 * Model Context Protocol by years; they are unrelated packages that happen to
 * sit one deletion away. Edit distance alone would have branded two uninvolved
 * maintainers as supply-chain attackers.
 */
const squat = () => ({
  id: 'MCP-SUP-002',
  severity: 'critical',
  title: 'Package name is 1 character away from "mcp-remote"',
  evidence: 'configured: cp-remote',
  impersonates: 'mcp-remote',
});

const resolver = (dates) => async (name) => dates[name] ?? null;

test('a package older than the one it resembles is not impersonating it', async () => {
  const out = await refuteBackwardsImpersonation(
    [squat()],
    '2014-03-10T00:00:00.000Z',
    resolver({ 'mcp-remote': '2025-04-01T00:00:00.000Z' }),
  );
  assert.deepEqual(out, []);
});

test('a package published after the original is still reported', async () => {
  const out = await refuteBackwardsImpersonation(
    [squat()],
    '2026-04-13T00:00:00.000Z',
    resolver({ 'mcp-remote': '2025-04-01T00:00:00.000Z' }),
  );
  assert.equal(out.length, 1);
});

test('an unresolvable original keeps the finding rather than dropping it silently', async () => {
  const out = await refuteBackwardsImpersonation(
    [squat()],
    '2014-03-10T00:00:00.000Z',
    resolver({}),
  );
  assert.equal(out.length, 1, 'unknown provenance must fail loud, not quiet');
});

test('findings unrelated to name similarity are never touched', async () => {
  const other = { id: 'MCP-CRED-001', severity: 'high', title: 'token in config', evidence: 'x' };
  const out = await refuteBackwardsImpersonation([other], '2014-03-10T00:00:00.000Z', resolver({}));
  assert.deepEqual(out, [other]);
});

test('no creation date for the candidate leaves findings unchanged', async () => {
  const f = [squat()];
  assert.deepEqual(await refuteBackwardsImpersonation(f, null, resolver({})), f);
});
