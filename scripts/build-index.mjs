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
import { writeFile, mkdir } from 'node:fs/promises';
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

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function render({ generated, npm, pypi, sweep }) {
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

  await mkdir(OUT, { recursive: true });
  const data = { generated, npm, pypi, sweep };
  await writeFile(`${OUT}/data.json`, JSON.stringify(data, null, 2));
  await writeFile(`${OUT}/index.html`, render(data));

  console.log(`\nnpm: ${npm.length} · pypi: ${pypi.length} · sweep: ${sweep.probed} probed, ${sweep.hits.length} hit(s)`);
  for (const h of sweep.hits) console.log(`  IMPERSONATION: ${h.name} (mimics ${h.impersonates})`);

  // Surfaced for the workflow so it can raise an alert issue.
  await writeFile(`${OUT}/../../.impersonations`, String(sweep.hits.length));
}

main().catch((e) => { console.error(e); process.exit(1); });
