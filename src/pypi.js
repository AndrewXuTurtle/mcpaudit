import { CERTAIN, LIKELY } from './checks.js';
import { auditAdvisories } from './osv.js';

const PYPI = 'https://pypi.org/pypi';
const STATS = 'https://pypistats.org/api/packages';

const finding = (o) => ({ confidence: LIKELY, ...o });

/** Widely-used Python MCP packages, used as the typosquat reference set. */
const KNOWN = [
  'mcp',
  'fastmcp',
  'mcp-server-fetch',
  'mcp-server-git',
  'mcp-server-time',
  'mcp-server-sqlite',
  'mcp-server-sentry',
  'mcp-server-postgres',
];

/** Publishers whose names appear on first-party MCP packages. */
const FIRST_PARTY_AUTHORS = [/anthropic/i, /model context protocol/i, /LF Projects/i];

/**
 * PEP 503 normalisation. On PyPI, runs of `-`, `_` and `.` are equivalent and
 * case is ignored, so `mcp_server_fetch` and `mcp-server-fetch` are literally
 * the same project. Comparing raw strings would report a package as a typosquat
 * of itself.
 */
export const normalize = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');

/** Fold visually confusable characters, as on the npm side. */
const deconfuse = (s) =>
  normalize(s).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[1|!]/g, 'l').replace(/0/g, 'o').replace(/5/g, 's');

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

/** Earliest upload across all releases — when the project first appeared. */
export function firstRelease(meta) {
  let earliest = null;
  for (const files of Object.values(meta?.releases || {})) {
    for (const f of files || []) {
      const t = f.upload_time_iso_8601 || f.upload_time;
      if (t && (!earliest || t < earliest)) earliest = t;
    }
  }
  return earliest;
}

/**
 * Audit a PyPI-hosted MCP server. Metadata only — nothing is downloaded,
 * installed, or executed.
 */
export async function auditPypiPackage(spec, {
  resolveMeta = (n) => getJSON(`${PYPI}/${n}/json`),
  resolveStats = (n) => getJSON(`${STATS}/${normalize(n)}/recent`),
} = {}) {
  const name = spec.replace(/^pypi:/, '').split(/[=<>~!\[]/)[0].trim();
  if (!name) return { findings: [], meta: null };

  const meta = await resolveMeta(name);
  if (!meta?.info) return { findings: [], meta: null, unreachable: true };

  const findings = [];
  const info = meta.info;
  const created = firstRelease(meta);
  const ageDays = created ? Math.floor((Date.now() - new Date(created).getTime()) / 86400000) : null;

  const stats = await resolveStats(name);
  const downloads = stats?.data?.last_month ?? null;

  const self = normalize(name);
  const isKnown = KNOWN.some((k) => normalize(k) === self);

  if (!isKnown) {
    for (const known of KNOWN) {
      // Same project under a different separator is not impersonation.
      if (normalize(known) === self) continue;
      const d = editDistance(deconfuse(name), deconfuse(known));
      if (d <= 2) {
        findings.push(finding({
          id: 'MCP-PY-001',
          severity: 'critical',
          confidence: LIKELY,
          title: d === 0
            ? `Package name is visually identical to "${known}"`
            : `Package name is ${d} character${d > 1 ? 's' : ''} away from "${known}"`,
          evidence: `configured: ${name}`,
          impersonates: known,
          why: 'Near-identical names on a public index are the standard delivery route for trojanized packages. `uvx` resolves and runs the package without an explicit install step, so a mistyped name executes immediately.',
          fix: `Confirm character by character that you meant ${name} and not ${known}.`,
        }));
        break;
      }
    }

    // Claiming a first-party author while not being a known first-party package.
    const author = `${info.author || ''} ${info.author_email || ''}`;
    if (FIRST_PARTY_AUTHORS.some((re) => re.test(author))) {
      findings.push(finding({
        id: 'MCP-PY-002',
        severity: 'high',
        confidence: LIKELY,
        title: 'Package claims a first-party author but is not a known first-party package',
        evidence: `author: ${author.trim().slice(0, 120)}`,
        why: 'Author metadata on PyPI is self-declared and unverified. Copying a recognised vendor name is the cheapest way to make an unrelated package look official.',
        fix: 'Verify the project URL against the vendor’s own documentation before trusting this package.',
      }));
    }
  }

  if (ageDays !== null && ageDays < 45 && downloads !== null && downloads < 500) {
    findings.push(finding({
      id: 'MCP-PY-003',
      severity: 'high',
      confidence: LIKELY,
      title: `Package is ${ageDays} days old with ${downloads} downloads last month`,
      evidence: `${name} — first released ${String(created).slice(0, 10)}`,
      why: 'A new package with almost no adoption has had very few eyes on it, and is the profile of one planted to impersonate a better-known project.',
      fix: 'Confirm this is the package the publisher documents before granting it credentials.',
    }));
  }

  // An sdist runs setup.py at install time; a wheel does not.
  const current = meta.urls || [];
  if (current.some((f) => f.packagetype === 'sdist') && !current.some((f) => f.packagetype === 'bdist_wheel')) {
    findings.push(finding({
      id: 'MCP-PY-004',
      severity: 'medium',
      confidence: CERTAIN,
      title: 'Package ships only a source distribution',
      evidence: `${name} ${info.version} — sdist only, no wheel`,
      why: 'Installing an sdist executes its build script on your machine, before the server is ever started. A wheel is installed by unpacking and cannot run code at install time.',
      fix: 'Prefer a version that publishes a wheel, or inspect the build script before installing.',
    }));
  }

  if (info.yanked) {
    findings.push(finding({
      id: 'MCP-PY-005',
      severity: 'medium',
      confidence: CERTAIN,
      title: 'Installed version has been yanked by its maintainer',
      evidence: String(info.yanked_reason || 'no reason given').slice(0, 160),
      why: 'Maintainers yank releases that are broken or unsafe. Yanked versions stay installable when pinned.',
      fix: 'Move to a current release.',
    }));
  }

  findings.push(...await auditAdvisories(name, info.version, 'PyPI'));

  return { findings, meta: { name, resolved: info.version, ageDays, downloads, created } };
}

/** Creation-date resolver for the temporal impersonation refutation. */
export async function pypiCreated(name) {
  const meta = await getJSON(`${PYPI}/${name}/json`);
  return meta ? firstRelease(meta) : null;
}
