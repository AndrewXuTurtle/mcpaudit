#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { runAudit } from '../src/index.js';
import { renderTerminal, renderMarkdown } from '../src/report.js';

const HELP = `
  mcpaudit — audit your MCP servers before they audit you

  Usage
    npx mcpaudit [config-path] [options]

  Options
    --mcp           Run as an MCP server over stdio, so an agent can audit its
                    own configuration. See README for client setup.
    --deep          Download each package from the registry and read its source.
                    Nothing is installed and nothing is executed.
    --paranoid      Include lower-confidence findings (more noise, fewer misses).
    --json          Emit machine-readable JSON.
    --markdown      Emit a Markdown report.
    -o, --out FILE  Write the report to a file instead of stdout.
    --fail-on SEV   Exit non-zero at or above this severity. Default: high.
                    One of: critical, high, medium, low, none.
    -h, --help      Show this message.

  Examples
    npx mcpaudit                        Scan every MCP config on this machine
    npx mcpaudit --deep                 Also read the package sources
    npx mcpaudit --markdown -o audit.md Save a shareable report
    npx mcpaudit --fail-on critical     Use in CI

  Exit codes
    0  clean, or findings below the --fail-on threshold
    1  findings at or above the threshold
    2  the scan itself failed
`;

function parseArgs(argv) {
  const opts = { deep: false, paranoid: false, json: false, markdown: false, out: null, failOn: 'high', path: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--mcp') opts.mcp = true;
    else if (a === '--deep') opts.deep = true;
    else if (a === '--paranoid') opts.paranoid = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--markdown' || a === '--md') opts.markdown = true;
    else if (a === '-o' || a === '--out') opts.out = argv[++i];
    else if (a === '--fail-on') opts.failOn = String(argv[++i] || 'high').toLowerCase();
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (!a.startsWith('-')) opts.path = a;
  }
  return opts;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.mcp) {
    // Serve MCP over stdio. Never write to stdout here — it is the transport.
    const { serve } = await import('../src/mcp-server.js');
    serve();
    return new Promise(() => {});
  }

  if (opts.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (opts.version) {
    const { default: pkg } = await import('../package.json', { with: { type: 'json' } });
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }

  const quiet = opts.json || opts.markdown || opts.out;
  const result = await runAudit({
    path: opts.path,
    deep: opts.deep,
    paranoid: opts.paranoid,
    onProgress: quiet
      ? undefined
      : (name) => {
          if (process.stderr.isTTY) process.stderr.write(`\r  scanning ${name}…`.padEnd(60));
        },
  });
  if (!quiet && process.stderr.isTTY) process.stderr.write('\r'.padEnd(62) + '\r');

  const body = opts.json
    ? JSON.stringify(result, (k, v) => (k === 'raw' ? undefined : v), 2)
    : opts.markdown
      ? renderMarkdown(result)
      : renderTerminal(result);

  if (opts.out) {
    await writeFile(opts.out, body.endsWith('\n') ? body : `${body}\n`);
    process.stdout.write(`Report written to ${opts.out}\n`);
  } else {
    process.stdout.write(body.endsWith('\n') ? body : `${body}\n`);
  }

  if (opts.failOn === 'none') return 0;
  const threshold = SEVERITY_ORDER.indexOf(opts.failOn);
  if (threshold === -1) return 0;
  const tripped = SEVERITY_ORDER.slice(0, threshold + 1).some((s) => result.summary.counts[s] > 0);
  return tripped ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`mcpaudit failed: ${err?.stack || err}\n`);
    process.exit(2);
  });
