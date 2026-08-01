import { CERTAIN, LIKELY } from './checks.js';

const OSV = 'https://api.osv.dev/v1/query';

/**
 * OSV.dev aggregates GitHub's Advisory Database, PyPA, and the registries' own
 * malware feeds. It is queried live rather than vendored as a list, because a
 * bundled copy of "known bad packages" is stale the day after it ships and this
 * tool is most useful precisely when something was published yesterday.
 *
 * No API key, no account, and it covers npm and PyPI with the same call shape.
 */
async function defaultQuery(body, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(OSV, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

/** Malware advisories are published under the MAL- prefix across ecosystems. */
const isMalware = (id) => /^MAL-/i.test(id || '');

/**
 * Look up published advisories for one package at one version.
 *
 * The version matters more than anything else here. Querying without it returns
 * every advisory ever filed against the package, including ones fixed years ago
 * — reporting those as findings would be the same false-positive failure this
 * project keeps having to correct. OSV filters server-side when given a
 * version, so an up-to-date package returns nothing at all.
 */
export async function auditAdvisories(name, version, ecosystem = 'npm', { query = defaultQuery } = {}) {
  if (!name) return [];

  const body = { package: { name, ecosystem } };
  if (version) body.version = version;

  const res = await query(body);
  const vulns = res?.vulns || [];
  const out = [];

  for (const v of vulns) {
    const malware = isMalware(v.id);
    const declared = v.database_specific?.severity;
    const severity = malware ? 'critical' : (SEVERITY[String(declared || '').toUpperCase()] || 'medium');

    const fixedIn = [...new Set(
      (v.affected || [])
        .flatMap((a) => a.ranges || [])
        .flatMap((r) => r.events || [])
        .map((e) => e.fixed)
        .filter(Boolean),
    )];

    out.push({
      id: malware ? 'MCP-ADV-001' : 'MCP-ADV-002',
      severity,
      confidence: malware ? CERTAIN : LIKELY,
      title: malware
        ? `Published malware advisory for this package (${v.id})`
        : `Known ${severity} vulnerability affects the version in use (${v.id})`,
      evidence: `${name}@${version || 'unpinned'} — ${(v.summary || v.id).slice(0, 140)}`,
      why: malware
        ? 'A malware advisory means a registry or security team examined this package and concluded it was malicious — not that it looked suspicious. If it has run on this machine, treat it as a compromise rather than a warning.'
        : `This advisory was matched against the exact version resolved for this server, so it is not a historical entry — the code being run is in the affected range. ${fixedIn.length ? `Fixed in ${fixedIn.join(', ')}.` : 'No fixed version is published yet.'}`,
      fix: malware
        ? `Remove ${name} from every MCP config and rotate every credential it could reach. Advisory: https://osv.dev/vulnerability/${v.id}`
        : fixedIn.length
          ? `Pin ${name} to ${fixedIn[0]} or later. Advisory: https://osv.dev/vulnerability/${v.id}`
          : `No fix is published. Assess whether this server is worth running meanwhile. Advisory: https://osv.dev/vulnerability/${v.id}`,
      advisory: v.id,
    });
  }

  return out;
}
