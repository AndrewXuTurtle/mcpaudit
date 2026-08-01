import { discoverServers } from './discover.js';
import { auditServer, packageFromServer, POSSIBLE } from './checks.js';
import { auditPackage, refuteBackwardsImpersonation } from './registry.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const rank = (s) => SEVERITY_ORDER.indexOf(s);

/** Two checks reaching the same conclusion should not read as two problems. */
function dedupe(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = `${f.id}|${f.evidence}`;
    if (!seen.has(key)) seen.set(key, f);
  }
  return [...seen.values()].sort((a, b) => rank(a.severity) - rank(b.severity));
}

/**
 * Audit every MCP server configured on this machine.
 *
 * `deep` additionally downloads each package tarball from the registry and reads
 * it. Nothing is ever installed or executed.
 * `paranoid` surfaces low-confidence findings that are suppressed by default.
 */
export async function runAudit({ path, deep = false, paranoid = false, onProgress } = {}) {
  const { servers, scanned, errors } = await discoverServers(path);

  const results = [];
  for (const server of servers) {
    onProgress?.(server.name);
    let findings = auditServer(server);

    const spec = packageFromServer(server);
    let pkgMeta = null;
    if (spec) {
      const { findings: pkgFindings, meta } = await auditPackage(spec, { deep });
      findings = findings.concat(pkgFindings);
      pkgMeta = meta;

      // An older package cannot be imitating a newer one.
      findings = await refuteBackwardsImpersonation(findings, meta?.created);
    }

    if (!paranoid) findings = findings.filter((f) => f.confidence !== POSSIBLE);
    results.push({ server, package: spec, packageMeta: pkgMeta, findings: dedupe(findings) });
  }

  const all = results.flatMap((r) => r.findings);
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, all.filter((f) => f.severity === s).length]));

  return {
    results,
    scanned,
    errors,
    summary: {
      servers: servers.length,
      configs: scanned.length,
      findings: all.length,
      counts,
      worst: all.length ? SEVERITY_ORDER.find((s) => counts[s] > 0) : null,
      deep,
      paranoid,
    },
  };
}

export { discoverServers, auditServer, auditPackage };
