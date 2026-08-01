/**
 * Findings carry a confidence tier as well as a severity.
 *
 * This is the whole design argument of mcpaudit. Independent testing put
 * YARA-style MCP scanners around a 78% false-positive rate, and a scanner that
 * is wrong four times out of five gets uninstalled. So `possible` findings are
 * withheld unless the user asks for them with --paranoid, and every finding has
 * to point at the exact evidence that produced it.
 */
export const CERTAIN = 'certain';
export const LIKELY = 'likely';
export const POSSIBLE = 'possible';

/** Publishers whose packages are first-party and not worth typosquat-flagging. */
const TRUSTED_SCOPES = [
  '@modelcontextprotocol/',
  '@anthropic-ai/',
  '@github/',
  '@cloudflare/',
  '@stripe/',
  '@sentry/',
  '@upstash/',
  '@notionhq/',
];

/** Well-known server package names, used as the typosquat reference set. */
const KNOWN_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-everything',
  'mcp-remote',
  'firecrawl-mcp',
];

/**
 * Credential families. Grouping matters more than counting: a server holding
 * one API key is normal, whereas one holding cloud + payment + database keys is
 * a single process whose compromise hands over everything at once.
 */
const SECRET_FAMILIES = [
  { family: 'cloud', highValue: true, re: /^(AWS_|AZURE_|GCP_|GOOGLE_APPLICATION_CREDENTIALS|DIGITALOCEAN_|LINODE_)/i },
  { family: 'source-control', highValue: true, re: /^(GITHUB_|GITLAB_|BITBUCKET_)/i },
  { family: 'payment', highValue: true, re: /^(STRIPE_|PAYPAL_|SQUARE_|BRAINTREE_|LEMONSQUEEZY_)/i },
  { family: 'database', highValue: true, re: /^(DATABASE_URL|POSTGRES_|MYSQL_|MONGO|REDIS_|SUPABASE_|PLANETSCALE_)/i },
  { family: 'ssh-and-keys', highValue: true, re: /(PRIVATE_KEY|SSH_|_PEM$|SIGNING_KEY)/i },
  { family: 'ai-provider', highValue: false, re: /^(OPENAI_|ANTHROPIC_|GEMINI_|GOOGLE_API|COHERE_|MISTRAL_|GROQ_|HUGGINGFACE)/i },
  { family: 'comms', highValue: false, re: /^(SLACK_|DISCORD_|TWILIO_|SENDGRID_|RESEND_|POSTMARK_|MAILGUN_)/i },
  { family: 'search-and-data', highValue: false, re: /^(BRAVE_|SERP|TAVILY_|FIRECRAWL_|EXA_)/i },
];

/** Value shapes that identify a literal secret pasted into a config file. */
const SECRET_VALUE_SHAPES = [
  { label: 'GitHub token', re: /^gh[pousr]_[A-Za-z0-9]{16,}$/ },
  { label: 'OpenAI key', re: /^sk-[A-Za-z0-9_-]{20,}$/ },
  { label: 'Anthropic key', re: /^sk-ant-[A-Za-z0-9_-]{20,}$/ },
  { label: 'AWS access key id', re: /^AKIA[0-9A-Z]{16}$/ },
  { label: 'Stripe key', re: /^[rs]k_(live|test)_[A-Za-z0-9]{16,}$/ },
  { label: 'Slack token', re: /^xox[baprs]-[A-Za-z0-9-]{10,}$/ },
  { label: 'Google API key', re: /^AIza[0-9A-Za-z_-]{35}$/ },
  { label: 'JSON web token', re: /^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./ },
];

/**
 * Instruction shapes that only make sense if text is trying to steer an agent
 * rather than describe a tool. Kept deliberately narrow — prose like "ignore
 * whitespace" must not trip these.
 */
const INJECTION_PATTERNS = [
  { id: 'override', re: /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|messages?)\b/i },
  { id: 'exfiltrate', re: /\b(send|post|upload|transmit|forward|exfiltrate)\b[^.]{0,60}\b(\.env|credentials?|secrets?|api[\s_-]?keys?|private[\s_-]?key|ssh[\s_-]?key|password)/i },
  { id: 'covert', re: /\b(do\s*not|don't|never)\s+(tell|inform|mention|reveal|show|disclose)\s+(the\s+)?(user|human|operator)\b/i },
  { id: 'read-secrets', re: /\b(read|open|cat|load|access)\b[^.]{0,40}(~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|shadow file)/i },
  { id: 'persona-hijack', re: /\byou\s+are\s+now\s+(a|an|in)\b|\bnew\s+system\s+prompt\b|<\s*system\s*>/i },
  { id: 'tool-shadow', re: /\bwhen\s+(calling|using|invoking)\b[^.]{0,50}\b(instead|rather than|always use)\b/i },
];

/** Characters with no business inside a tool description. */
const INVISIBLE_CHARS = /[​-‏‪-‮⁠-⁤﻿­]/g;

const finding = (o) => ({ confidence: LIKELY, ...o });

const redact = (v) => {
  const s = String(v);
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
};

/**
 * Fold characters that are easy to mistake for one another, so `paypa1` and
 * `paypal` compare as identical rather than as one edit apart. Without this a
 * homoglyph swap is indistinguishable from an honest typo.
 */
function deconfuse(s) {
  return s
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[1|!]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5/g, 's')
    .replace(/[_.]/g, '-');
}

/** Levenshtein, bounded — we only care about distances of 1–2. */
function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Recover the npm package a stdio server actually launches. */
export function packageFromServer(server) {
  const { command, args } = server;
  if (!command) return null;
  const cmd = String(command).toLowerCase();

  if (cmd.endsWith('npx') || cmd.endsWith('npx.cmd') || cmd === 'bunx' || cmd === 'pnpm' || cmd === 'yarn') {
    for (const arg of args) {
      if (typeof arg !== 'string' || arg.startsWith('-')) continue;
      if (['dlx', 'exec', 'create'].includes(arg)) continue;
      return arg;
    }
  }
  if (cmd.endsWith('uvx') || cmd.endsWith('pipx')) {
    const pkg = args.find((a) => typeof a === 'string' && !a.startsWith('-'));
    return pkg ? `pypi:${pkg}` : null;
  }
  return null;
}

/** Split "@scope/name@1.2.3" into its name and version specifier. */
export function splitSpec(spec) {
  if (!spec) return { name: null, version: null };
  const scoped = spec.startsWith('@');
  const at = spec.indexOf('@', scoped ? 1 : 0);
  if (at === -1) return { name: spec, version: null };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/* ------------------------------------------------------------------ checks */

function checkCredentials(server) {
  const out = [];
  const families = new Map();

  for (const [key, value] of Object.entries(server.env)) {
    for (const { family, highValue, re } of SECRET_FAMILIES) {
      if (re.test(key)) {
        if (!families.has(family)) families.set(family, { highValue, keys: [] });
        families.get(family).keys.push(key);
        break;
      }
    }

    // A literal secret in the config file sits in plaintext on disk, gets caught
    // by backups, and is readable by anything the user runs.
    if (typeof value === 'string' && !/^\$\{?[A-Z_]/.test(value)) {
      for (const { label, re } of SECRET_VALUE_SHAPES) {
        if (re.test(value.trim())) {
          out.push(finding({
            id: 'MCP-CRED-001',
            severity: 'high',
            confidence: CERTAIN,
            title: `${label} stored in plaintext in config`,
            evidence: `${key} = ${redact(value)}`,
            why: 'The value is a live credential written directly into a config file rather than referenced from the environment. Anything that can read the file — a backup, a sync client, another MCP server with filesystem access — can read the key.',
            fix: `Replace the literal with a reference such as "${key}": "\${${key}}" and export the real value from your shell profile or a secret manager. Then rotate this credential, since it has been on disk in cleartext.`,
          }));
          break;
        }
      }
    }
  }

  const highValue = [...families.entries()].filter(([, v]) => v.highValue);
  if (families.size >= 3 || highValue.length >= 2) {
    const list = [...families.entries()].map(([f, v]) => `${f} (${v.keys.join(', ')})`).join('; ');
    out.push(finding({
      id: 'MCP-CRED-002',
      severity: highValue.length >= 2 ? 'high' : 'medium',
      confidence: LIKELY,
      title: `Blast radius: ${families.size} credential families in one process`,
      evidence: list,
      why: 'MCP servers hold every credential you give them in a single process environment. One compromised or malicious server therefore yields all of these at once — this is the mechanism behind the 2026 infostealer campaigns against MCP packages, which harvested browser passwords, cloud tokens, SSH keys and API keys in one pass.',
      fix: 'Give each server only the credentials it actually needs, and prefer narrowly-scoped tokens over account-wide ones. If this server does not need the high-value families listed above, remove them.',
    }));
  }
  return out;
}

function checkPrivilege(server) {
  const out = [];
  const argv = server.args.map(String);
  const name = (server.name || '').toLowerCase();
  const pkg = (packageFromServer(server) || '').toLowerCase();
  const isFilesystemServer = /filesystem|files|fs\b/.test(`${name} ${pkg}`);

  // A filesystem server touching the filesystem is not a finding. Its *scope*
  // is. Flagging the former is exactly the noise that gets scanners uninstalled.
  const roots = argv.filter((a) => /^(\/|~|\$HOME|[A-Za-z]:\\)/.test(a) && !a.startsWith('-'));
  for (const root of roots) {
    const normalized = root.replace(/^~/, '$HOME');
    const isWholeDisk = normalized === '/' || /^[A-Za-z]:\\?$/.test(normalized);
    const isHomeRoot = /^\$HOME\/?$/.test(normalized) || normalized === process.env.HOME;
    if (isWholeDisk || isHomeRoot) {
      out.push(finding({
        id: 'MCP-PRIV-001',
        severity: 'high',
        confidence: CERTAIN,
        title: isWholeDisk ? 'Server is granted the entire filesystem' : 'Server is granted your whole home directory',
        evidence: `argument: ${root}`,
        why: `That scope includes ~/.ssh, ~/.aws/credentials, browser profiles, and every .env file you own. Any prompt injection reaching this server — from a web page it fetches, a file it reads, or another server's tool description — can read all of it.`,
        fix: 'Scope the server to the specific project directories it needs, e.g. ~/code/my-project instead of the whole home directory.',
      }));
    }
  }

  if (isFilesystemServer && roots.length === 0 && server.transport === 'stdio') {
    out.push(finding({
      id: 'MCP-PRIV-002',
      severity: 'medium',
      confidence: POSSIBLE,
      title: 'Filesystem server started without an explicit root',
      evidence: `command: ${server.command} ${argv.join(' ')}`.trim(),
      why: 'With no directory argument, the effective root depends on the working directory the client happens to launch it from, which is not something you control or can audit.',
      fix: 'Pass the allowed directories explicitly as arguments.',
    }));
  }

  const shellish = /\b(bash|sh|zsh|cmd|powershell|pwsh|eval|exec)\b/;
  if (shellish.test(String(server.command || '')) || argv.some((a) => /-c$|--command$/.test(a))) {
    out.push(finding({
      id: 'MCP-PRIV-003',
      severity: 'high',
      confidence: LIKELY,
      title: 'Server launches through a shell',
      evidence: `command: ${server.command} ${argv.join(' ')}`.trim(),
      why: 'A shell in the launch path turns any string the agent controls into potential command execution, and removes the argument boundaries that would otherwise contain an injection.',
      fix: 'Invoke the server binary directly with an argument array rather than going through a shell.',
    }));
  }
  return out;
}

function checkTransport(server) {
  const out = [];
  if (server.transport === 'stdio' || !server.url) return out;

  let url;
  try {
    url = new URL(server.url);
  } catch {
    return out;
  }

  const isLoopback = ['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(url.hostname);

  if (url.protocol === 'http:' && !isLoopback) {
    out.push(finding({
      id: 'MCP-NET-001',
      severity: 'high',
      confidence: CERTAIN,
      title: 'Remote server contacted over plaintext HTTP',
      evidence: server.url,
      why: 'Requests and responses — including any bearer token in the headers and every tool result — travel unencrypted and can be read or rewritten by anything on the network path. Rewriting a tool description in transit is a complete agent takeover.',
      fix: 'Switch the URL to https://, or tunnel it if the endpoint genuinely cannot serve TLS.',
    }));
  }

  const hasAuth = Object.keys(server.headers).some((h) => /^(authorization|x-api-key|x-auth|api-key|cookie)$/i.test(h));
  if (!hasAuth && !isLoopback) {
    out.push(finding({
      id: 'MCP-NET-002',
      severity: 'medium',
      confidence: LIKELY,
      title: 'Remote server configured without an auth header',
      evidence: `${server.url} — headers: ${Object.keys(server.headers).join(', ') || 'none'}`,
      why: 'Either the endpoint is unauthenticated, meaning anyone who finds it can drive it, or it authenticates some other way that this config does not record. Both are worth confirming before an agent trusts its output.',
      fix: 'Confirm how this endpoint authenticates. If it is genuinely open, treat everything it returns as untrusted input.',
    }));
  }

  for (const [key, value] of Object.entries(server.headers)) {
    if (typeof value === 'string' && /^(bearer\s+)?(gh[pousr]_|sk-|xox|eyJ)/i.test(value.trim())) {
      out.push(finding({
        id: 'MCP-NET-003',
        severity: 'high',
        confidence: CERTAIN,
        title: 'Live token hardcoded in a request header',
        evidence: `${key}: ${redact(value)}`,
        why: 'The token is stored in cleartext in the config file rather than resolved from the environment at launch.',
        fix: 'Move the token into an environment variable and reference it, then rotate it.',
      }));
    }
  }
  return out;
}

function checkSupplyChain(server) {
  const out = [];
  const spec = packageFromServer(server);
  if (!spec) return out;
  if (spec.startsWith('pypi:')) return out;

  const { name, version } = splitSpec(spec);
  if (!name) return out;

  const trusted = TRUSTED_SCOPES.some((s) => name.startsWith(s));

  // npm enforces scope ownership, so a typo *inside* a scope nobody else can
  // publish to is impossible. The real attack is a lookalike scope — swapping a
  // homoglyph so `@modelcontextprotoco1/` reads as the official one at a glance.
  if (!trusted && name.startsWith('@')) {
    const scope = name.slice(0, name.indexOf('/') + 1);
    for (const known of TRUSTED_SCOPES) {
      // Compare literally first, then folded. A homoglyph swap collapses to
      // distance ZERO once folded, so requiring d > 0 here would skip exactly
      // the attack this check exists for.
      const d = editDistance(deconfuse(scope), deconfuse(known));
      if (scope !== known && d <= 2) {
        out.push(finding({
          id: 'MCP-SUP-006',
          severity: 'critical',
          confidence: LIKELY,
          title: `Publisher scope impersonates "${known}"`,
          evidence: `configured scope: ${scope}`,
          impersonates: known + name.slice(name.indexOf('/') + 1),
          why: 'The scope is not the official one but is visually near-identical to it. Because npm will not let anyone else publish under the real scope, imitating it is the only way to make a hostile package look first-party — and a lookalike scope is far more convincing than a misspelled package name.',
          fix: `This is almost certainly not the publisher you intended. Reinstall from the official docs, and treat every credential this server held as compromised.`,
        }));
        break;
      }
    }
  }

  // Rug-pull: the package published today is not the one you reviewed.
  if (!version || version === 'latest' || /^[\^~*]/.test(version)) {
    out.push(finding({
      id: 'MCP-SUP-001',
      severity: trusted ? 'low' : 'medium',
      confidence: CERTAIN,
      title: 'Server runs an unpinned package version',
      evidence: `${server.command} ${server.args.join(' ')}`.trim(),
      why: 'Every launch fetches whatever the registry serves at that moment. A maintainer change, an account takeover, or a deliberate "rug pull" — publishing benign code, waiting for adoption, then shipping a malicious version — lands on your machine automatically and with no review.',
      fix: `Pin the version, e.g. ${name}@1.2.3, and update deliberately.`,
    }));
  }

  if (!trusted) {
    for (const known of KNOWN_PACKAGES) {
      const d = editDistance(deconfuse(name), deconfuse(known));
      if (name !== known && d <= 2) {
        out.push(finding({
          id: 'MCP-SUP-002',
          severity: 'critical',
          confidence: LIKELY,
          title: d === 0
            ? `Package name is visually identical to "${known}"`
            : `Package name is ${d} character${d > 1 ? 's' : ''} away from "${known}"`,
          evidence: `configured: ${name}`,
          impersonates: known,
          why: 'Near-identical names are the standard delivery route for trojanized MCP packages — the 2026 SmartLoader campaign built a whole fake developer ecosystem, complete with five GitHub accounts, to make one look legitimate before shipping an infostealer.',
          fix: `Confirm character by character that you meant ${name} and not ${known}. If in doubt, uninstall and reinstall from the publisher's own documentation.`,
        }));
        break;
      }
    }
  }
  return out;
}

/** Scan free text — a tool description, README, or source string — for agent-directed instructions. */
export function scanText(text, where) {
  const out = [];
  if (typeof text !== 'string' || !text) return out;

  const invisible = text.match(INVISIBLE_CHARS);
  if (invisible) {
    out.push(finding({
      id: 'MCP-POIS-001',
      severity: 'critical',
      confidence: CERTAIN,
      title: 'Invisible characters hidden in agent-visible text',
      evidence: `${where}: ${invisible.length} zero-width/bidi character(s) (${[...new Set(invisible)].map((c) => 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')).join(', ')})`,
      why: 'These characters render as nothing to you but are read verbatim by the model. They are the standard way to conceal instructions inside a tool description — the tool-poisoning technique that MCP scanners were built for.',
      fix: 'Treat this server as hostile until the publisher explains the characters. Strip them and inspect what the text says without them.',
    }));
  }

  const cleaned = text.replace(INVISIBLE_CHARS, '');
  for (const { id, re } of INJECTION_PATTERNS) {
    const m = cleaned.match(re);
    if (m) {
      out.push(finding({
        id: 'MCP-POIS-002',
        severity: 'critical',
        confidence: LIKELY,
        title: `Agent-directed instruction in ${where}`,
        evidence: `[${id}] …${cleaned.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40).replace(/\s+/g, ' ').trim()}…`,
        why: 'Tool descriptions are supposed to describe what a tool does, for a human deciding whether to use it. Text that instead issues commands to the model is trying to steer the agent behind your back.',
        fix: 'Do not run this server. Report the package to the registry it came from.',
      }));
    }
  }
  return out;
}

/** Run every static check against one server. */
export function auditServer(server) {
  const findings = [
    ...checkCredentials(server),
    ...checkPrivilege(server),
    ...checkTransport(server),
    ...checkSupplyChain(server),
  ];

  // The config itself is agent-visible in some clients, so it is in scope too.
  for (const [key, value] of Object.entries(server.env)) {
    if (typeof value === 'string' && value.length > 24) findings.push(...scanText(value, `env.${key}`));
  }
  for (const arg of server.args) {
    if (typeof arg === 'string' && arg.length > 24) findings.push(...scanText(arg, 'launch arguments'));
  }

  return findings;
}
