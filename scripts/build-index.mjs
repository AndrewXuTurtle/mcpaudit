/**
 * Builds the MCP Package Trust Index.
 *
 * Ranks the most-installed MCP packages, records the provenance signals that
 * matter before you install one, and sweeps for impersonation packages. Runs on
 * a schedule in GitHub Actions, so the published index stays current without
 * anyone tending it.
 *
 * Read-only. Registry metadata only — nothing is installed or executed.
 */
import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { auditPackage } from '../src/registry.js';
import { auditPypiPackage } from '../src/pypi.js';

const OUT = 'docs/trust';
const TOP_N = 40;

/**
 * Publishers npm will not let anyone else publish under.
 *
 * The sweep is deliberately restricted to SCOPES. Scope ownership is enforced by
 * npm, so a homoglyph scope can only ever be deliberate — there is no innocent
 * reason to publish under `@modelcontextprotoco1/`. Unscoped name collisions are
 * not decidable the same way: `cp-remote` sits one deletion from `mcp-remote`
 * and is an entirely unrelated package from 2014. Sweeping unscoped names would
 * mean this job publishing accusations against uninvolved maintainers every
 * night, unattended. Scope-only keeps every published claim defensible.
 */
const OFFICIAL_SCOPES = [
  '@modelcontextprotocol/', '@anthropic-ai/', '@notionhq/', '@upstash/', '@supabase/',
  '@sentry/', '@cloudflare/', '@playwright/', '@azure/', '@github/', '@stripe/', '@eslint/',
];

const SUBS = [['l', '1'], ['l', 'I'], ['o', '0'], ['i', '1'], ['e', '3'], ['m', 'rn'], ['rn', 'm'], ['s', '5']];

function scopeVariants(scope) {
  const out = new Set();
  for (const [a, b] of SUBS) {
    let i = scope.indexOf(a);
    while (i !== -1) { out.add(scope.slice(0, i) + b + scope.slice(i + a.length)); i = scope.indexOf(a, i + 1); }
  }
  for (let i = 1; i < scope.length - 1; i++) {
    out.add(scope.slice(0, i) + scope.slice(i + 1));
    if (i < scope.length - 2) out.add(scope.slice(0, i) + scope[i + 1] + scope[i] + scope.slice(i + 2));
  }
  out.delete(scope);
  return [...out];
}

async function getJSON(url) {
  try {
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}

/** Run tasks with bounded concurrency so the registry is not hammered. */
async function pool(items, limit, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: limit }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  }));
  return out;
}

async function topNpmPackages() {
  const seen = new Map();
  for (const q of ['mcp server', 'model context protocol server', 'mcp-server']) {
    const j = await getJSON(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=250`);
    for (const o of j?.objects || []) seen.set(o.package.name, o.package);
  }
  const names = [...seen.keys()].filter((n) => /mcp|modelcontext/i.test(n));
  const withDownloads = await pool(names, 12, async (n) => {
    const j = await getJSON(`https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(n).replace(/^%40/, '@')}`);
    return j?.downloads ? { name: n, downloads: j.downloads } : null;
  });
  return withDownloads.filter(Boolean).sort((a, b) => b.downloads - a.downloads).slice(0, TOP_N);
}

/**
 * Look for packages impersonating an official scope.
 *
 * Targets the real package names people actually install, rather than a guessed
 * suffix list, so coverage tracks what is popular this week.
 */
async function sweepImpersonations(topPackages) {
  const targets = new Set();
  for (const scope of OFFICIAL_SCOPES) {
    for (const p of topPackages) {
      if (p.name.startsWith(scope)) targets.add(p.name);
    }
  }
  // Ensure the well-known first-party servers are covered even if a given
  // week's download ranking does not surface them.
  for (const n of [
    '@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-github',
    '@modelcontextprotocol/server-memory', '@modelcontextprotocol/sdk',
  ]) targets.add(n);

  const candidates = [];
  for (const original of targets) {
    const slash = original.indexOf('/');
    const bare = original.slice(1, slash);
    const suffix = original.slice(slash + 1);
    for (const v of scopeVariants(bare)) {
      candidates.push({ name: `@${v}/${suffix}`, impersonates: original });
    }
  }

  const raw = await pool(candidates, 10, async (c) => {
    const j = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(c.name).replace(/^%40/, '@')}`);
    if (!j?.['dist-tags']) return null;
    const latest = j['dist-tags'].latest;
    return {
      ...c,
      version: latest,
      created: (j.time?.created || '').slice(0, 10),
      createdRaw: j.time?.created || null,
      maintainers: (j.maintainers || []).map((m) => m.name).join(', '),
      author: j.versions?.[latest]?.author?.name || '',
    };
  });

  // Belt and braces: even under a lookalike scope, a package that predates the
  // one it resembles cannot be imitating it.
  const hits = [];
  for (const h of raw.filter(Boolean)) {
    const orig = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(h.impersonates).replace(/^%40/, '@')}`);
    const origCreated = orig?.time?.created;
    if (origCreated && h.createdRaw && new Date(h.createdRaw) < new Date(origCreated)) {
      console.log(`  refuted (predates target): ${h.name}`);
      continue;
    }
    delete h.createdRaw;
    hits.push(h);
  }
  return { probed: candidates.length, hits };
}

/** Names that make a package part of the MCP / AI-agent surface. */
const MCP_NAME = /mcp|model-?context|claude|anthropic|cursor|windsurf/i;

/**
 * Every published malware advisory for an MCP-shaped package name.
 *
 * These are GitHub Advisory Database entries — a registry security team
 * examined each package and concluded it was malicious. Naming them is not an
 * accusation on my part; the advisories are already public. Collecting them in
 * one place is the useful part, because nobody installing an MCP server thinks
 * to search 28,000 advisories first.
 */
async function fetchMcpMalware(token) {
  const headers = { accept: 'application/vnd.github+json' };
  if (token) headers.authorization = `Bearer ${token}`;

  // This endpoint paginates by CURSOR, not page number. Passing `page=N` is
  // silently ignored and returns the first page every time — which looked like
  // a successful scan of 64,000 advisories while actually re-reading the same
  // hundred, and produced 14 results where the true count is an order of
  // magnitude higher. Follow the `Link: rel="next"` cursor instead. That makes
  // it sequential, which is the cost of getting the right answer.
  const MAX_REQUESTS = 400;
  const found = [];
  let scanned = 0;
  let capped = false;
  let failed = null;

  for (const ecosystem of ['npm', 'pip']) {
    let url = `https://api.github.com/advisories?ecosystem=${ecosystem}&type=malware&per_page=100&sort=published&direction=desc`;
    let requests = 0;

    while (url && requests < MAX_REQUESTS) {
      let res;
      try {
        res = await fetch(url, { headers });
      } catch (e) {
        failed = `${ecosystem}: request failed (${e.message})`;
        break;
      }
      // Unauthenticated callers get 60 requests an hour, so a rate-limited run
      // returns nothing. Reporting that as "scanned 0, found 0" would be
      // indistinguishable from a clean result — the failure has to be loud.
      if (!res.ok) {
        failed = `${ecosystem}: HTTP ${res.status}${res.status === 403 ? ' (rate limited — is GITHUB_TOKEN set?)' : ''}`;
        break;
      }
      requests++;

      const batch = await res.json();
      if (!Array.isArray(batch) || batch.length === 0) break;
      scanned += batch.length;

      for (const a of batch) {
        // A withdrawn advisory has been retracted by GitHub. Republishing it
        // would keep an accusation alive after its author took it back.
        if (a.withdrawn_at) continue;
        const names = [...new Set((a.vulnerabilities || []).map((v) => v?.package?.name).filter(Boolean))];
        const hit = names.filter((n) => MCP_NAME.test(n));
        if (!hit.length) continue;
        found.push({
          ghsa: a.ghsa_id,
          ecosystem,
          packages: hit,
          published: (a.published_at || '').slice(0, 10),
          summary: a.summary || '',
        });
      }

      const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') || '');
      url = next ? next[1] : null;
    }
    if (url && requests >= MAX_REQUESTS) capped = true;
  }

  // Deduplicate: the same package can appear under several advisories.
  const byPackage = new Map();
  for (const f of found) {
    for (const p of f.packages) {
      if (!byPackage.has(p) || f.published > byPackage.get(p).published) {
        byPackage.set(p, { package: p, ecosystem: f.ecosystem, ghsa: f.ghsa, published: f.published });
      }
    }
  }

  const list = [...byPackage.values()].sort((a, b) => (b.published || '').localeCompare(a.published || ''));
  if (capped) console.log(`  NOTE: advisory scan hit the ${MAX_REQUESTS}-request cap; the list may be incomplete`);
  if (failed) console.log(`  WARNING: advisory scan incomplete — ${failed}`);
  return { scanned, capped, failed, list };
}

/** Minimal semver comparison — enough for GHSA ranges, without a dependency. */
function cmpSemver(a, b) {
  const pa = String(a).split('-')[0].split('.').map(Number);
  const pb = String(b).split('-')[0].split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Evaluate a GHSA `vulnerable_version_range` such as ">= 1.0.0, < 1.2.3" or "= 0.4.0". */
function inRange(version, range) {
  if (!version || !range) return null;
  for (const part of range.split(',').map((s) => s.trim()).filter(Boolean)) {
    const m = /^(=|<=|>=|<|>)\s*(.+)$/.exec(part);
    if (!m) return null;
    const c = cmpSemver(version, m[2].trim());
    const ok = m[1] === '=' ? c === 0
      : m[1] === '<' ? c < 0
        : m[1] === '<=' ? c <= 0
          : m[1] === '>' ? c > 0
            : c >= 0;
    if (!ok) return false;
  }
  return true;
}

/**
 * Establish what actually became of each flagged package.
 *
 * A flat list of names conflates three very different situations, and the
 * difference matters enormously to the maintainers named on it. An advisory
 * names a *version range*; if the maintainer has since published outside that
 * range, the package on the registry today is not the package the advisory is
 * about. Listing it as though it were is a smear.
 *
 * Measured across the flagged set: most still-installable packages fall in that
 * remediated group — the AntV visualization servers among them, where malicious
 * releases were published and then pulled.
 */
async function classifyFlagged(list, token) {
  const headers = { accept: 'application/vnd.github+json' };
  if (token) headers.authorization = `Bearer ${token}`;

  return pool(list, 8, async (r) => {
    const npm = r.ecosystem === 'npm';
    const regUrl = npm
      ? `https://registry.npmjs.org/${encodeURIComponent(r.package).replace(/^%40/, '@')}`
      : `https://pypi.org/pypi/${r.package}/json`;

    let current = null;
    let registryState = 'unknown';
    try {
      const resp = await fetch(regUrl, { headers: { accept: 'application/json' } });
      if (resp.status === 404) registryState = 'removed';
      else if (resp.ok) {
        const j = await resp.json();
        if (npm) {
          current = j['dist-tags']?.latest || null;
          const desc = j.versions?.[current]?.description || '';
          registryState = (current === '0.0.1-security' || /security holding package/i.test(desc))
            ? 'security-held' : 'live';
        } else {
          current = j.info?.version || null;
          registryState = 'live';
        }
      }
    } catch { /* leave unknown */ }

    let range = null;
    let verdict = registryState === 'live' ? 'unknown' : registryState;
    if (registryState === 'live') {
      try {
        const a = await fetch(`https://api.github.com/advisories/${r.ghsa}`, { headers });
        if (a.ok) {
          const adv = await a.json();
          range = (adv.vulnerabilities || []).find((v) => v.package?.name === r.package)?.vulnerable_version_range || null;
          const still = inRange(current, range);
          if (still === true) verdict = 'still-affected';
          else if (still === false) verdict = 'remediated';
        }
      } catch { /* leave unknown */ }
    }
    return { ...r, current, registryState, range, verdict };
  });
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function render({ generated, npm, pypi, sweep, malware }) {
  const risky = npm.filter((p) => p.findings.length).length;
  const row = (p) => {
    const worst = p.findings[0]?.severity;
    const badge = worst ? `<span class="s ${worst}">${worst}</span>` : '<span class="s ok">clean</span>';
    const notes = p.findings.map((f) => esc(f.title)).join('<br>') || '—';
    return `<tr><td><code>${esc(p.name)}</code></td><td class="n">${(p.downloads || 0).toLocaleString()}</td><td class="n">${p.ageDays ?? '—'}</td><td>${badge}</td><td class="w">${notes}</td></tr>`;
  };

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Package Trust Index</title>
<meta name="description" content="Provenance and supply-chain signals for the most-installed Model Context Protocol packages. Regenerated automatically.">
<style>
:root{--bg:#fbfbfa;--fg:#16150f;--muted:#6b6a63;--line:#e3e2dc;--card:#fff;--accent:#a3341f;--ok:#2f6b3f;--code:#f4f3ef}
@media(prefers-color-scheme:dark){:root{--bg:#12120f;--fg:#eceae2;--muted:#96948a;--line:#2a2a25;--card:#191917;--accent:#e8785c;--ok:#7fbf8f;--code:#1e1e1a}}
:root[data-theme=dark]{--bg:#12120f;--fg:#eceae2;--muted:#96948a;--line:#2a2a25;--card:#191917;--accent:#e8785c;--ok:#7fbf8f;--code:#1e1e1a}
:root[data-theme=light]{--bg:#fbfbfa;--fg:#16150f;--muted:#6b6a63;--line:#e3e2dc;--card:#fff;--accent:#a3341f;--ok:#2f6b3f;--code:#f4f3ef}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}h1{font-size:clamp(1.9rem,5vw,2.6rem);letter-spacing:-.03em;margin:56px 0 10px}
p{margin:0 0 14px}a{color:var(--accent)}code{font-family:ui-monospace,Menlo,monospace;font-size:.9em}
.sub{color:var(--muted)}.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.88rem;margin:18px 0;min-width:720px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
td.n{text-align:right;font-variant-numeric:tabular-nums}td.w{color:var(--muted);font-size:.84rem}
.s{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.critical{background:var(--accent);color:#fff}.high{background:#c2410c;color:#fff}.medium{background:#a16207;color:#fff}
.low{background:var(--line);color:var(--fg)}.ok{background:transparent;color:var(--ok);border:1px solid var(--ok)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;margin:24px 0}
.alert{border-color:var(--accent);border-width:2px}
footer{margin:64px 0 48px;padding-top:22px;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
pre{background:var(--code);border:1px solid var(--line);border-radius:9px;padding:14px;overflow-x:auto;font-size:.86rem}
</style></head><body><div class="wrap">

<h1>MCP Package Trust Index</h1>
<p class="sub">Provenance and supply-chain signals for the ${npm.length} most-installed Model Context Protocol packages, plus the Python ecosystem. Regenerated automatically — last run ${esc(generated)}.</p>
<p>Built by <a href="https://github.com/AndrewXuTurtle/mcpaudit">mcpaudit</a>. Registry metadata only; nothing is installed or executed. <a href="./data.json">Raw JSON</a>.</p>

<div class="card${sweep.hits.length ? ' alert' : ''}">
<h2 style="margin-top:0">Impersonation sweep</h2>
<p>Probed <strong>${sweep.probed}</strong> homoglyph variants of publisher scopes that npm reserves for official packages.</p>
${sweep.hits.length
      ? `<p><strong>${sweep.hits.length} package(s) found impersonating an official scope:</strong></p><div class="scroll"><table><tr><th>Package</th><th>Impersonates</th><th>First published</th><th>Maintainer</th><th>Declared author</th></tr>${sweep.hits.map((h) => `<tr><td><code>${esc(h.name)}</code></td><td><code>${esc(h.impersonates)}</code></td><td>${esc(h.created)}</td><td>${esc(h.maintainers)}</td><td>${esc(h.author)}</td></tr>`).join('')}</table></div><p>A package under a lookalike scope may be byte-identical to the real one today and hostile tomorrow. Do not install these.</p>`
      : '<p>No impersonation packages detected in this run.</p>'}
</div>

<div class="card${malware.list.length ? ' alert' : ''}">
<h2 style="margin-top:0">MCP packages with published malware advisories</h2>
<p><strong>${malware.list.length}</strong> package name(s) on the MCP / AI-agent surface have an open, non-withdrawn malware advisory in the GitHub Advisory Database.</p>
<p>Grouped by what actually became of each package, because a flat list of names conflates three very different situations. <strong>Read this as "check before you install", not as a verdict.</strong> These advisories are largely automated, and automation produces false positives. I inspected one entry on this list &mdash; <code>lokal-mcp</code>, flagged critical &mdash; and found an 18&nbsp;KB single-file server with no install hooks, no <code>child_process</code>, no obfuscation, and one outbound host that is its own documented API. It looks entirely legitimate. Its advisory is still open. Treat every row here as a prompt to look, and follow the advisory link before drawing a conclusion about anyone's package.</p>
<p class="sub">Scanned ${(malware.scanned || 0).toLocaleString()} malware advisories across npm and PyPI in the GitHub Advisory Database.${malware.capped ? ' <strong>Result truncated by a request cap &mdash; treat as a lower bound.</strong>' : ''}${malware.failed ? ` <strong>This run could not complete the scan (${esc(malware.failed)})${malware.stale ? ', so the list below is from the last successful run and may be out of date' : ''}.</strong>` : ''}</p>
${(() => {
  const g = (v) => malware.list.filter((m) => m.verdict === v);
  const table = (rows, showRange) => `<div class="scroll"><table>
<tr><th>Package</th><th>Published now</th>${showRange ? '<th>Advisory covers</th>' : ''}<th>Advisory</th></tr>
${rows.map((m) => `<tr><td><code>${esc(m.package)}</code> <span class="sub">(${esc(m.ecosystem)})</span></td><td>${esc(m.current || '—')}</td>${showRange ? `<td>${esc(m.range || '—')}</td>` : ''}<td><a href="https://github.com/advisories/${esc(m.ghsa)}">${esc(m.ghsa)}</a></td></tr>`).join('\n')}
</table></div>`;
  const gone = [...g('removed'), ...g('security-held')];
  const affected = g('still-affected');
  const fixed = g('remediated');
  const unknown = g('unknown');
  return `
<h3>Registry has acted &mdash; ${gone.length}</h3>
<p class="sub">Removed from the registry, or replaced by npm with a security-holding placeholder. The registry took action; this is not an inference.</p>
${table(gone, false)}

<h3>Affected version is still published &mdash; ${affected.length}</h3>
<p class="sub">The version the registry serves today falls inside the advisory's range. These warrant the most caution &mdash; and are also where an incorrect advisory does the most damage to an innocent maintainer, so read the advisory before concluding anything.</p>
${table(affected, true)}

<h3>Already remediated &mdash; ${fixed.length}</h3>
<p class="sub">Listed for completeness only. The maintainer has published a version outside the advisory's range, so the package on the registry today is <em>not</em> the one the advisory describes. Several are well-known projects that were compromised and cleaned up. Do not read this section as a warning about these packages.</p>
${table(fixed, true)}
${unknown.length ? `<h3>Undetermined &mdash; ${unknown.length}</h3><p class="sub">The advisory range could not be parsed or the registry did not answer. No conclusion drawn.</p>${table(unknown, true)}` : ''}`;
})()}
<p>If one of these appears in your MCP config, read its advisory first. Where the advisory holds up &mdash; and especially where npm has replaced the package with a security placeholder &mdash; treat it as a compromise rather than a warning: remove it, then rotate every credential it could reach.</p>
</div>

<h2>npm packages</h2>
<p class="sub">${risky} of ${npm.length} carry at least one finding. An unpinned official package is low risk; an unpinned unknown one is not.</p>
<div class="scroll"><table>
<tr><th>Package</th><th>Downloads/mo</th><th>Age (days)</th><th>Worst</th><th>Findings</th></tr>
${npm.map(row).join('\n')}
</table></div>

<h2>PyPI packages</h2>
<div class="scroll"><table>
<tr><th>Package</th><th>Downloads/mo</th><th>Age (days)</th><th>Worst</th><th>Findings</th></tr>
${pypi.map(row).join('\n')}
</table></div>

<h2>Check your own machine</h2>
<pre>npx github:AndrewXuTurtle/mcpaudit</pre>
<p>Scans every MCP config on your system — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code.</p>

<footer>
<p>Generated by <a href="https://github.com/AndrewXuTurtle/mcpaudit">mcpaudit</a> · MIT ·
<a href="https://github.com/AndrewXuTurtle/mcpaudit/issues">Report a false positive</a> ·
<a href="https://wise.com/pay/me/andrewx55">Support this work</a></p>
<p>Findings are automated signals, not accusations. A finding means "verify this", not "this is malicious".</p>
</footer>
</div></body></html>`;
}

async function main() {
  const generated = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  console.log('ranking npm packages…');
  const top = await topNpmPackages();

  console.log(`auditing ${top.length} npm packages…`);
  const npm = await pool(top, 6, async (p) => {
    const { findings, meta } = await auditPackage(p.name, { deep: false });
    return { name: p.name, downloads: p.downloads, ageDays: meta?.ageDays ?? null, findings };
  });

  const PY = ['mcp', 'fastmcp', 'mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite'];
  console.log('auditing PyPI packages…');
  const pypi = await pool(PY, 4, async (n) => {
    const { findings, meta } = await auditPypiPackage(`pypi:${n}`);
    return { name: n, downloads: meta?.downloads ?? null, ageDays: meta?.ageDays ?? null, findings };
  });

  console.log('sweeping for impersonations…');
  const sweep = await sweepImpersonations(top);

  console.log('collecting published malware advisories…');
  let malware = await fetchMcpMalware(process.env.GITHUB_TOKEN);

  // A rate limit or outage must not silently replace a published list of known
  // malicious packages with an empty one. Keep the last good result and say it
  // is stale instead.
  if (malware.failed && !malware.list.length) {
    try {
      const previous = JSON.parse(await readFile(`${OUT}/data.json`, 'utf8'));
      if (previous?.malware?.list?.length) {
        console.log(`  keeping previous list of ${previous.malware.list.length} (marked stale)`);
        malware = { ...previous.malware, stale: true, failed: malware.failed };
      }
    } catch { /* no previous run to fall back on */ }
  }
  console.log(`  ${malware.list.length} flagged package names from ${malware.scanned.toLocaleString()} advisories`);

  if (malware.list.length) {
    console.log('establishing what became of each flagged package…');
    malware.list = await classifyFlagged(malware.list, process.env.GITHUB_TOKEN);
    const tally = {};
    for (const r of malware.list) tally[r.verdict] = (tally[r.verdict] || 0) + 1;
    console.log(`  ${Object.entries(tally).map(([k, v]) => `${k}=${v}`).join('  ')}`);
  }

  await mkdir(OUT, { recursive: true });
  const data = { generated, npm, pypi, sweep, malware };
  await writeFile(`${OUT}/data.json`, JSON.stringify(data, null, 2));
  await writeFile(`${OUT}/index.html`, render(data));

  console.log(`\nnpm: ${npm.length} · pypi: ${pypi.length} · sweep: ${sweep.probed} probed, ${sweep.hits.length} hit(s) · malware: ${malware.list.length}`);
  for (const h of sweep.hits) console.log(`  IMPERSONATION: ${h.name} (mimics ${h.impersonates})`);

  // Surfaced for the workflow so it can raise an alert issue.
  await writeFile(`${OUT}/../../.impersonations`, String(sweep.hits.length));
}

main().catch((e) => { console.error(e); process.exit(1); });
