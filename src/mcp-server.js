/**
 * mcpaudit as an MCP server.
 *
 * Lets an agent audit its own configuration: "is anything I'm connected to
 * unsafe?" answered in the same session, rather than requiring the user to
 * remember to run a CLI.
 *
 * The protocol is implemented directly rather than via the official SDK. A
 * security scanner that pulls in a dependency tree to report on dependency
 * trees undermines its own claim, and the wire format here is JSON-RPC 2.0 over
 * newline-delimited stdio — small enough to own.
 */
import { runAudit } from './index.js';
import { auditServer, POSSIBLE } from './checks.js';
import { auditPackage, refuteBackwardsImpersonation } from './registry.js';
import { auditPypiPackage } from './pypi.js';
import { auditAdvisories } from './osv.js';

/** Protocol revisions this server knows how to speak, newest first. */
const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];

const TOOLS = [
  {
    name: 'audit_mcp_configs',
    description:
      'Audit every MCP server configured on this machine for tool poisoning, credential exposure, over-broad privilege, supply-chain impersonation, and published security advisories. Discovers configs for Claude Desktop, Claude Code, Cursor, Windsurf and VS Code automatically. Read-only: nothing is installed and no server is started.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Audit one specific config file instead of discovering them.' },
        deep: { type: 'boolean', description: 'Also download each package tarball and read its source statically. Slower; nothing is executed.', default: false },
        paranoid: { type: 'boolean', description: 'Include lower-confidence findings.', default: false },
      },
    },
  },
  {
    name: 'check_package',
    description:
      'Check a single package before installing it as an MCP server. Reports impersonation of official publisher scopes, packages npm removed for malware, install hooks, unpinned-version risk, and published advisories affecting the resolved version.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Package name, e.g. "@modelcontextprotocol/server-filesystem" or "mcp-server-git".' },
        ecosystem: { type: 'string', enum: ['npm', 'pypi'], description: 'Registry to look in. Defaults to npm.', default: 'npm' },
        deep: { type: 'boolean', description: 'Download and statically read the package source.', default: false },
      },
      required: ['name'],
    },
  },
  {
    name: 'check_advisories',
    description:
      'Look up published security advisories for a package at a specific version, via OSV.dev (GitHub Advisory Database, PyPA, and registry malware feeds). Advisories are matched against the version given, so a patched release returns nothing.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Package name.' },
        version: { type: 'string', description: 'Exact version in use. Without it, every historical advisory is returned rather than the ones that apply.' },
        ecosystem: { type: 'string', enum: ['npm', 'PyPI'], default: 'npm' },
      },
      required: ['name'],
    },
  },
];

/** Render findings for a model: compact, evidence-first, no ANSI. */
function formatFindings(findings, header) {
  if (!findings.length) return `${header}\nNo issues found.`;
  const lines = [header, ''];
  for (const f of findings) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}  (${f.id}, confidence: ${f.confidence})`);
    lines.push(`  evidence: ${f.evidence}`);
    lines.push(`  why: ${f.why}`);
    lines.push(`  fix: ${f.fix}`);
    lines.push('');
  }
  return lines.join('\n');
}

async function callTool(name, args = {}) {
  if (name === 'audit_mcp_configs') {
    const result = await runAudit({ path: args.path, deep: !!args.deep, paranoid: !!args.paranoid });
    const { summary } = result;
    const parts = [
      `Scanned ${summary.servers} MCP server(s) across ${summary.configs} config file(s).`,
      summary.findings
        ? `${summary.findings} finding(s): ${Object.entries(summary.counts).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ')}`
        : 'No issues found.',
      '',
    ];
    for (const r of result.results) {
      parts.push(`── ${r.server.name}${r.package ? ` (${r.package})` : ''} — ${r.server.transport}`);
      parts.push(formatFindings(r.findings, ''));
    }
    return parts.join('\n');
  }

  if (name === 'check_package') {
    if (!args.name) throw new Error('name is required');
    const pypi = args.ecosystem === 'pypi';
    let { findings, meta } = pypi
      ? await auditPypiPackage(`pypi:${args.name}`)
      : await auditPackage(args.name, { deep: !!args.deep });

    // Registry checks alone miss the headline detections — homoglyph scopes,
    // typosquats, shell launches — because those are defined over a server
    // config rather than a bare name. Synthesise the config a user would write
    // so `check_package` answers the question it claims to.
    if (!pypi) {
      const synthetic = {
        name: args.name, source: {}, transport: 'stdio', command: 'npx',
        args: ['-y', args.name], env: {}, url: null, headers: {}, raw: {},
      };
      const configFindings = await refuteBackwardsImpersonation(
        auditServer(synthetic).filter((f) =>
          // MCP-SUP-001 (unpinned) and MCP-PRIV-002 (no explicit root) describe
          // the config I just invented, not the package being asked about.
          f.id !== 'MCP-SUP-001' && f.id !== 'MCP-PRIV-002' && f.confidence !== POSSIBLE),
        meta?.created,
      );
      findings = [...configFindings, ...findings];
    }
    const head = meta
      ? `${meta.name}@${meta.resolved}${meta.downloads != null ? ` — ${meta.downloads.toLocaleString()} downloads/month` : ''}${meta.ageDays != null ? `, ${meta.ageDays} days old` : ''}`
      : `${args.name} — not found on the registry`;
    return formatFindings(findings, head);
  }

  if (name === 'check_advisories') {
    if (!args.name) throw new Error('name is required');
    const findings = await auditAdvisories(args.name, args.version, args.ecosystem || 'npm');
    return formatFindings(
      findings,
      `${args.name}${args.version ? `@${args.version}` : ' (no version given — results are not version-filtered)'}`,
    );
  }

  throw new Error(`unknown tool: ${name}`);
}

/** Build a JSON-RPC response for one request. Returns null for notifications. */
async function handle(msg) {
  const { id, method, params } = msg ?? {};
  const isNotification = id === undefined || id === null;
  const ok = (result) => (isNotification ? null : { jsonrpc: '2.0', id, result });
  const err = (code, message) => (isNotification ? null : { jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize': {
      const asked = params?.protocolVersion;
      return ok({
        protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[0],
        capabilities: { tools: {} },
        serverInfo: { name: 'mcpaudit', version: '0.1.0' },
        instructions:
          'Audits MCP server configurations for tool poisoning, credential exposure, privilege scope, supply-chain impersonation and published advisories. Read-only — it never installs a package or starts a server.',
      });
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null;
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok({ tools: TOOLS });
    case 'tools/call': {
      try {
        const text = await callTool(params?.name, params?.arguments || {});
        return ok({ content: [{ type: 'text', text }], isError: false });
      } catch (e) {
        // Tool failures are reported in-band so the model can react, rather
        // than as protocol errors which it never sees.
        return ok({ content: [{ type: 'text', text: `mcpaudit failed: ${e.message}` }], isError: true });
      }
    }
    case 'resources/list':
      return ok({ resources: [] });
    case 'prompts/list':
      return ok({ prompts: [] });
    default:
      return err(-32601, `method not found: ${method}`);
  }
}

/** Read newline-delimited JSON-RPC from stdin and write responses to stdout. */
export function serve({ input = process.stdin, output = process.stdout, exit = () => process.exit(0) } = {}) {
  let buffer = '';
  // Tool calls are async — several reach the network. Exiting the moment stdin
  // closes drops any response still being computed, which is invisible against
  // a long-lived client but loses replies whenever input is piped in.
  let pending = 0;
  let ended = false;
  const settle = () => { if (ended && pending === 0) exit(); };

  input.setEncoding('utf8');

  input.on('data', async (chunk) => {
    buffer += chunk;
    // Hold one reference for the whole chunk. Counting per message let the
    // total reach zero between two messages that arrived together, which
    // tripped the exit check while later lines were still queued.
    pending++;
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;

      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        output.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } })}\n`);
        continue;
      }

      try {
        const res = await handle(msg);
        if (res) output.write(`${JSON.stringify(res)}\n`);
      } catch (e) {
        if (msg?.id !== undefined && msg?.id !== null) {
          output.write(`${JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: String(e?.message || e) } })}\n`);
        }
      }
    }
    pending--;
    settle();
  });

  input.on('end', () => { ended = true; settle(); });
}

export { handle, TOOLS };
