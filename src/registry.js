import { gunzipSync } from 'node:zlib';
import { scanText, splitSpec, CERTAIN, LIKELY, POSSIBLE } from './checks.js';
import { auditAdvisories } from './osv.js';

const REGISTRY = 'https://registry.npmjs.org';
const DOWNLOADS = 'https://api.npmjs.org/downloads/point/last-month';

const finding = (o) => ({ confidence: LIKELY, ...o });

async function getJSON(url, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Minimal tar reader.
 *
 * Pulling in a tar library to audit supply-chain risk would mean trusting a
 * dependency tree to tell you whether to trust a dependency tree. The format is
 * 512-byte headers followed by padded data, so we read it directly.
 */
function untar(buf) {
  const files = [];
  let offset = 0;
  let longName = null;

  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const sizeField = header.subarray(124, 136).toString('utf8').replace(/[\0 ]/g, '');
    const size = parseInt(sizeField, 8) || 0;
    const type = String.fromCharCode(header[156]);
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');

    offset += 512;
    const data = buf.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;

    // GNU long-name entries carry the real path in their payload.
    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0.*$/, '');
      continue;
    }
    if (type === '0' || type === '\0') {
      const full = longName || (prefix ? `${prefix}/${name}` : name);
      longName = null;
      files.push({ path: full.replace(/^package\//, ''), data });
    } else {
      longName = null;
    }
  }
  return files;
}

/**
 * Anything that moves data off the machine. Reading the environment is only
 * alarming if the result can leave, so several patterns below are gated on one
 * of these appearing nearby.
 */
const EGRESS = /\bfetch\s*\(|https?\.request|axios|node-fetch|XMLHttpRequest|WebSocket|net\.(connect|Socket)|dgram|\.post\s*\(|\.send\s*\(|sendBeacon/;

/** How far around a match to look when testing context. */
const WINDOW = 600;

/**
 * Source patterns that indicate exfiltration or execution rather than ordinary work.
 *
 * `refute` suppresses a match outright when a known-benign idiom explains it.
 * `needsEgress` demands that data actually have somewhere to go before the
 * finding is raised. Both exist because the first version of this file flagged
 * the `debug` package — vendored into thousands of dependency trees — as
 * critical environment exfiltration in two of the thirty most-installed MCP
 * servers. Pattern matching without context is how scanners end up at a 78%
 * false-positive rate.
 */
const SOURCE_PATTERNS = [
  {
    id: 'env-sweep',
    severity: 'critical',
    confidence: LIKELY,
    re: /(JSON\.stringify\s*\(\s*process\.env|Object\.(entries|keys|assign)\s*\(\s*process\.env\s*\)|\{\s*\.\.\.process\.env\s*\})/,
    // `Object.keys(process.env).filter(...)` is config lookup, not a sweep.
    refute: /Object\.(keys|entries)\s*\(\s*process\.env\s*\)\s*\.\s*(filter|find|some|every|forEach|includes)/,
    needsEgress: true,
    title: 'Code serializes the entire environment and can transmit it',
    why: 'Reading one named variable is normal; capturing the whole environment as a blob within reach of a network call is how every credential in the process gets packaged for sending somewhere.',
  },
  {
    id: 'credential-paths',
    severity: 'critical',
    confidence: LIKELY,
    // Agent credential stores belong on this list as much as ~/.ssh does.
    // `~/.claude/.credentials.json` holds Claude Code OAuth tokens and
    // `~/.claude.json` holds every MCP server's API keys — a single read of the
    // pair yields more than most infostealer target lists. Added after reviewing
    // a package that uploads exactly those two files to a third-party endpoint.
    // Match path COMPONENTS, not whole paths. Real code builds these with
    // path.join(CLAUDE_DIR, ".credentials.json"), so the literal string
    // ".claude/.credentials.json" never appears in the source — a whole-path
    // pattern missed the very package this rule was written for.
    re: /(\.ssh\/id_[rd]sa|\.aws\/credentials|\.config\/gcloud|Login Data|Local State|key3\.db|logins\.json|wallet\.dat|\.credentials\.json|\.claude\.json|claude_desktop_config\.json|mcp\.json|windsurf)/,
    // A denylist naming these paths is protecting them, not harvesting them.
    refute: /\b(deny|denied|denylist|blocklist|blacklist|block|exclude|excluded|forbidden|restricted|protected|sensitive|never|refuse|reject|guard)\b/i,
    title: 'Code references credential or wallet file paths',
    why: 'These exact paths are the target list used by infostealers: SSH private keys, cloud credentials, browser password stores and crypto wallets.',
  },
  {
    id: 'remote-exec',
    severity: 'critical',
    confidence: LIKELY,
    re: /(child_process[\s\S]{0,80}(curl|wget|bash\s+-c|powershell)|eval\s*\(\s*(await\s*)?(fetch|require\s*\(\s*['"]https?)|new\s+Function\s*\(\s*(await|.*fetch))/,
    title: 'Code executes content fetched at runtime',
    why: 'Downloading code and running it means the audited package and the running package are not the same thing — the payload can change after review, or be served only to some machines.',
  },
  {
    id: 'hardcoded-egress',
    severity: 'high',
    confidence: POSSIBLE,
    re: /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/,
    title: 'Code posts to a hardcoded IP address',
    why: 'Legitimate services are reached by hostname. A bare IP avoids DNS logging and domain reputation.',
  },
  {
    id: 'obfuscation',
    severity: 'high',
    confidence: POSSIBLE,
    re: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{160,}['"]\s*,\s*['"]base64['"]\s*\)/,
    title: 'Large base64 blob decoded in source',
    why: 'A long encoded literal is a common way to keep a payload out of casual reading and out of naive scanners.',
  },
];

/**
 * Apply the source patterns to one file's text, with context gating.
 *
 * Exported so the refutation rules are directly testable: the regressions this
 * guards against are false positives, which are invisible unless asserted on.
 */
export function scanSource(text, path = 'source') {
  const out = [];
  for (const p of SOURCE_PATTERNS) {
    const m = text.match(p.re);
    if (!m) continue;

    const context = text.slice(Math.max(0, m.index - WINDOW), m.index + m[0].length + WINDOW);

    // A known-benign idiom in range explains the match away entirely.
    if (p.refute && p.refute.test(context)) continue;

    // Captured data that cannot leave the process is not exfiltration.
    if (p.needsEgress && !EGRESS.test(context)) continue;

    out.push(finding({
      id: `MCP-SRC-${p.id}`,
      severity: p.severity,
      confidence: p.confidence,
      title: p.title,
      evidence: `${path}: …${text.slice(Math.max(0, m.index - 30), m.index + m[0].length + 30).replace(/\s+/g, ' ').trim().slice(0, 160)}…`,
      why: p.why,
      fix: 'Read this file before running the server. If the behaviour is not explained by the package documentation, do not run it.',
    }));
  }
  return out;
}

/** Files worth reading. Skips maps and vendored bundles that produce only noise. */
const isScannable = (p) =>
  /\.(js|mjs|cjs|ts|json|md)$/i.test(p) && !/\.min\.js$/i.test(p) && !/(^|\/)(test|tests|__tests__)\//i.test(p);

/** Look up when a package first appeared on the registry. */
async function defaultResolveCreated(pkgName) {
  const meta = await getJSON(`${REGISTRY}/${encodeURIComponent(pkgName).replace(/^%40/, '@')}`);
  return meta?.time?.created ?? null;
}

/**
 * Drop name-similarity findings where the flagged package is OLDER than the
 * package it supposedly imitates. Impersonation cannot run backwards in time.
 *
 * This exists because a sweep of 1,267 lookalike names surfaced `cp-remote`
 * (published 2014) and `mp-remote` (2020) as near-matches for `mcp-remote`.
 * Both predate MCP itself by years — they are unrelated packages that happen to
 * sit one deletion away. Reporting them would have accused two uninvolved
 * maintainers of supply-chain fraud on the strength of an edit distance.
 */
export async function refuteBackwardsImpersonation(findings, created, resolveCreated = defaultResolveCreated) {
  if (!created) return findings;
  const candidateAge = new Date(created).getTime();
  const out = [];

  for (const f of findings) {
    if (!f.impersonates || !['MCP-SUP-002', 'MCP-SUP-006', 'MCP-PY-001'].includes(f.id)) {
      out.push(f);
      continue;
    }
    const originalCreated = await resolveCreated(f.impersonates);
    const originalAge = originalCreated ? new Date(originalCreated).getTime() : null;

    // Unknown original: keep the finding rather than silently dropping it.
    if (originalAge === null || candidateAge >= originalAge) out.push(f);
  }
  return out;
}

/**
 * Fetch a package from npm and inspect it statically. Nothing is executed and
 * nothing is installed — the tarball is read in memory.
 */
export async function auditPackage(spec, { deep = false } = {}) {
  const { name, version } = splitSpec(spec);
  if (!name || spec.startsWith('pypi:')) return { findings: [], meta: null };

  const findings = [];
  const meta = await getJSON(`${REGISTRY}/${encodeURIComponent(name).replace(/^%40/, '@')}`);
  if (!meta) return { findings, meta: null, unreachable: true };

  const latest = meta['dist-tags']?.latest;
  const resolved = version && meta.versions?.[version] ? version : latest;
  const vmeta = meta.versions?.[resolved];
  const created = meta.time?.created ? new Date(meta.time.created) : null;
  const published = meta.time?.[resolved] ? new Date(meta.time[resolved]) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / 86400000) : null;

  const dl = await getJSON(`${DOWNLOADS}/${encodeURIComponent(name).replace(/^%40/, '@')}`);
  const downloads = dl?.downloads ?? null;

  // Young + unpopular is the profile of a freshly-planted typosquat. Neither
  // signal alone means much, so they are only reported together.
  if (ageDays !== null && ageDays < 45 && downloads !== null && downloads < 500) {
    findings.push(finding({
      id: 'MCP-SUP-003',
      severity: 'high',
      confidence: LIKELY,
      title: `Package is ${ageDays} days old with ${downloads} downloads last month`,
      evidence: `${name}@${resolved} — first published ${created.toISOString().slice(0, 10)}`,
      why: 'A new package with almost no adoption has had very few eyes on it. This is the profile of a package planted to impersonate a better-known one, and it is the stage at which malicious MCP packages are typically caught.',
      fix: 'Confirm this package is the one the publisher documents, and read its source before granting it credentials.',
    }));
  }

  // When npm's security team removes a package for malware, it republishes a
  // placeholder in its place: version 0.0.1-security, description "security
  // holding package", maintainers stripped. Finding one of these in a config is
  // not a heuristic — it is npm stating that this package contained malicious
  // code. Nothing else this tool reports carries that weight.
  const heldByVersion = resolved === '0.0.1-security';
  const heldByDescription = /security holding package/i.test(vmeta?.description || '');
  if (heldByVersion || heldByDescription) {
    findings.push(finding({
      id: 'MCP-SUP-007',
      severity: 'critical',
      confidence: CERTAIN,
      title: 'npm removed this package for containing malicious code',
      evidence: `${name}@${resolved} — ${vmeta?.description || 'security holding package'}`,
      why: 'npm replaces packages its security team removes with a placeholder release, which is what is published under this name now. The package you configured contained malicious code and was taken down. If it ever ran on this machine, treat it as a compromise rather than a scare.',
      fix: `Remove ${name} from every MCP config, and check each client separately. Rotate every credential that was in reach of it — the environment it was given, plus anything readable from the directories it could access. See https://www.npmjs.com/advisories?search=${encodeURIComponent(name)} for the advisory.`,
    }));
  }

  if (vmeta?.deprecated) {
    findings.push(finding({
      id: 'MCP-SUP-004',
      severity: 'medium',
      confidence: CERTAIN,
      title: 'Package version is deprecated',
      evidence: String(vmeta.deprecated).slice(0, 160),
      why: 'Deprecated versions stop receiving security fixes while remaining installable.',
      fix: 'Move to the replacement the maintainer names, or to the current version.',
    }));
  }

  const scripts = vmeta?.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    if (scripts[hook]) {
      findings.push(finding({
        id: 'MCP-SUP-005',
        severity: 'high',
        confidence: CERTAIN,
        title: `Package runs a ${hook} script`,
        evidence: `"${hook}": ${String(scripts[hook]).slice(0, 200)}`,
        why: 'Install hooks execute the moment the package is fetched — before the server is ever started and before any tool description is reviewed. With npx and an unpinned version, this runs on every launch.',
        fix: 'Read the script. To install without running it, use `npm install --ignore-scripts`.',
      }));
    }
  }

  // Published advisories, matched against the exact version resolved above.
  findings.push(...await auditAdvisories(name, resolved, 'npm'));

  if (!deep) return { findings, meta: { name, resolved, ageDays, downloads, published, created } };

  const tarUrl = vmeta?.dist?.tarball;
  if (tarUrl) {
    try {
      const res = await fetch(tarUrl);
      if (res.ok) {
        const gz = Buffer.from(await res.arrayBuffer());
        const files = untar(gunzipSync(gz));

        for (const file of files) {
          if (!isScannable(file.path) || file.data.length > 2_000_000) continue;
          const text = file.data.toString('utf8');

          findings.push(...scanSource(text, file.path));

          // Tool descriptions are the payload surface for poisoning attacks.
          for (const m of text.matchAll(/description\s*[:=]\s*(['"`])([\s\S]{12,1200}?)\1/g)) {
            findings.push(...scanText(m[2], `${file.path} tool description`));
          }
        }
      }
    } catch {
      /* tarball unreachable — static metadata findings still stand */
    }
  }

  return { findings, meta: { name, resolved, ageDays, downloads, published, created } };
}
