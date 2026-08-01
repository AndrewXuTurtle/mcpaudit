import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * Where each MCP client keeps its server config.
 *
 * Clients disagree on both the path and the shape of the file, so every entry
 * declares which top-level key holds the server map. VS Code uses `servers`;
 * everyone else settled on `mcpServers`.
 */
function candidatePaths() {
  const home = homedir();
  const os = platform();

  const claudeDesktop =
    os === 'darwin'
      ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
      : os === 'win32'
        ? join(process.env.APPDATA || join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
        : join(home, '.config', 'Claude', 'claude_desktop_config.json');

  return [
    { client: 'Claude Desktop', path: claudeDesktop, keys: ['mcpServers'] },
    { client: 'Claude Code (global)', path: join(home, '.claude.json'), keys: ['mcpServers'], nested: 'projects' },
    { client: 'Cursor (global)', path: join(home, '.cursor', 'mcp.json'), keys: ['mcpServers'] },
    { client: 'Windsurf', path: join(home, '.codeium', 'windsurf', 'mcp_config.json'), keys: ['mcpServers'] },
    { client: 'Cursor (project)', path: resolve('.cursor', 'mcp.json'), keys: ['mcpServers'] },
    { client: 'VS Code (project)', path: resolve('.vscode', 'mcp.json'), keys: ['servers', 'mcpServers'] },
    { client: 'Project .mcp.json', path: resolve('.mcp.json'), keys: ['mcpServers'] },
  ];
}

/**
 * Strip comments and trailing commas. VS Code writes JSONC, and hand-edited
 * configs routinely carry a trailing comma that JSON.parse rejects — failing
 * the whole scan over that would be a bad reason to miss a malicious server.
 */
function parseLoose(text) {
  try {
    return JSON.parse(text);
  } catch {
    const stripped = text
      .replace(/"(?:[^"\\]|\\.)*"|\/\*[\s\S]*?\*\/|\/\/[^\n\r]*/g, (m) => (m.startsWith('"') ? m : ''))
      .replace(/,(\s*[}\]])/g, '$1');
    return JSON.parse(stripped);
  }
}

/**
 * Normalize one raw server entry into a common shape, so every check downstream
 * can reason about "a server" without caring which client declared it.
 */
function normalize(name, raw, source) {
  const transport = raw.url || raw.serverUrl
    ? (raw.type === 'sse' || String(raw.url || '').includes('/sse') ? 'sse' : 'http')
    : 'stdio';

  return {
    name,
    source,
    transport,
    command: raw.command ?? null,
    args: Array.isArray(raw.args) ? raw.args : [],
    env: raw.env && typeof raw.env === 'object' ? raw.env : {},
    url: raw.url ?? raw.serverUrl ?? null,
    headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : {},
    raw,
  };
}

function collect(obj, keys, source, out) {
  for (const key of keys) {
    const map = obj?.[key];
    if (!map || typeof map !== 'object') continue;
    for (const [name, raw] of Object.entries(map)) {
      if (raw && typeof raw === 'object') out.push(normalize(name, raw, source));
    }
  }
}

/**
 * Find every MCP server configured on this machine.
 * Unreadable or malformed files are reported rather than thrown, so one broken
 * config never hides the rest.
 */
export async function discoverServers(explicitPath) {
  const targets = explicitPath
    ? [{ client: 'explicit', path: resolve(explicitPath), keys: ['mcpServers', 'servers'], nested: 'projects' }]
    : candidatePaths();

  const servers = [];
  const scanned = [];
  const errors = [];

  for (const target of targets) {
    if (!existsSync(target.path)) continue;
    let data;
    try {
      data = parseLoose(await readFile(target.path, 'utf8'));
    } catch (err) {
      errors.push({ path: target.path, message: err.message });
      continue;
    }
    scanned.push({ client: target.client, path: target.path });

    collect(data, target.keys, { client: target.client, path: target.path }, servers);

    // Claude Code stores a separate server map per project directory.
    if (target.nested && data?.[target.nested] && typeof data[target.nested] === 'object') {
      for (const [projectPath, project] of Object.entries(data[target.nested])) {
        collect(project, target.keys, { client: `${target.client} → ${projectPath}`, path: target.path }, servers);
      }
    }
  }

  return { servers: dedupe(servers), scanned, errors };
}

/**
 * The same server is frequently configured in several clients at once. Collapse
 * those into one finding set but remember every place it was declared, so the
 * user knows how many surfaces they have to fix.
 */
function dedupe(servers) {
  const seen = new Map();
  for (const s of servers) {
    const key = `${s.name}|${s.command}|${s.args.join(' ')}|${s.url}`;
    const existing = seen.get(key);
    if (existing) existing.alsoIn.push(s.source);
    else seen.set(key, { ...s, alsoIn: [] });
  }
  return [...seen.values()];
}
