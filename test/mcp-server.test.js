import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle, TOOLS } from '../src/mcp-server.js';

test('initialize echoes a supported protocol version and identifies the server', async () => {
  const r = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
  assert.equal(r.result.protocolVersion, '2025-03-26', 'must speak the version the client asked for');
  assert.equal(r.result.serverInfo.name, 'mcpaudit');
  assert.ok(r.result.capabilities.tools);
});

test('an unknown protocol version falls back to the newest supported one', async () => {
  const r = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '1999-01-01' } });
  assert.equal(r.result.protocolVersion, '2025-06-18');
});

test('notifications get no response', async () => {
  assert.equal(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
});

test('every tool declares a usable schema', async () => {
  const r = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(r.result.tools.length, TOOLS.length);
  for (const t of r.result.tools) {
    assert.ok(t.name && t.description, `${t.name} needs a description`);
    assert.equal(t.inputSchema.type, 'object');
  }
});

test('unknown methods return a JSON-RPC method-not-found error', async () => {
  const r = await handle({ jsonrpc: '2.0', id: 3, method: 'nope/nope' });
  assert.equal(r.error.code, -32601);
});

test('a failing tool reports in-band so the model can react', async () => {
  // Missing required argument. This must come back as isError content rather
  // than a protocol error, which the model would never see.
  const r = await handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'check_package', arguments: {} } });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /mcpaudit failed/);
});

test('an unknown tool name is an in-band error too', async () => {
  const r = await handle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'not_a_tool', arguments: {} } });
  assert.equal(r.result.isError, true);
});

/**
 * Regression: the CLI silently ignored --mcp and ran a normal audit, printing
 * human-readable text to stdout. stdout IS the JSON-RPC transport, so every
 * client would have failed on the first byte — and the documented install
 * command would have been broken for anyone who copied it from a listing.
 */
test('the CLI recognises --mcp rather than treating it as an unknown flag', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../bin/cli.js', import.meta.url), 'utf8');
  assert.match(src, /a === '--mcp'/, '--mcp must be parsed');
  assert.match(src, /if \(opts\.mcp\)/, '--mcp must be dispatched before any audit runs');
  // The dispatch has to precede --help/--version handling, or a bare flag order
  // could print help to the transport.
  assert.ok(src.indexOf('if (opts.mcp)') < src.indexOf('if (opts.help)'), 'mcp dispatch must come first');
});
