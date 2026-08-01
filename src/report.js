import { SEVERITY_ORDER } from './index.js';

// FORCE_COLOR keeps output readable when stdout is a pipe — CI logs (GitHub
// Actions renders ANSI) and the demo renderer both need colour without a TTY.
const useColor =
  process.env.NO_COLOR
    ? false
    : (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') || Boolean(process.stdout.isTTY);
const c = (code, s) => (useColor ? `[${code}m${s}[0m` : s);
const bold = (s) => c('1', s);
const dim = (s) => c('2', s);

const SEVERITY_STYLE = {
  critical: { color: '1;41;97', label: 'CRITICAL' },
  high: { color: '1;31', label: 'HIGH' },
  medium: { color: '1;33', label: 'MEDIUM' },
  low: { color: '36', label: 'LOW' },
  info: { color: '2', label: 'INFO' },
};

const tag = (sev) => {
  const s = SEVERITY_STYLE[sev] ?? SEVERITY_STYLE.info;
  return c(s.color, ` ${s.label} `);
};

/** Wrap prose so long explanations stay readable in a terminal. */
function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join('\n');
}

export function renderTerminal(result) {
  const width = Math.min(process.stdout.columns || 88, 96);
  const out = [];
  const { summary, results, scanned, errors } = result;

  out.push('');
  out.push(bold('  mcpaudit') + dim(`  ·  ${summary.servers} server${summary.servers === 1 ? '' : 's'} across ${summary.configs} config${summary.configs === 1 ? '' : 's'}`));
  for (const s of scanned) out.push(dim(`    ${s.client}  ${s.path}`));
  for (const e of errors) out.push(c('33', `    could not parse ${e.path}: ${e.message}`));
  out.push('');

  if (!summary.servers) {
    out.push('  No MCP servers configured on this machine.');
    out.push(dim('  Pass a config path explicitly if yours lives somewhere unusual: mcpaudit ./path/to/config.json'));
    out.push('');
    return out.join('\n');
  }

  for (const r of results) {
    const { server, findings, package: pkg, packageMeta } = r;
    const worst = findings.length ? findings[0].severity : null;
    const status = worst ? tag(worst) : c('32', ' CLEAN ');

    let line = `  ${status} ${bold(server.name)}`;
    if (pkg) line += dim(`  ${pkg}`);
    out.push(line);

    const via = server.transport === 'stdio' ? `${server.command ?? '?'} ${server.args.join(' ')}`.trim() : server.url;
    out.push(dim(`         ${server.transport} · ${String(via).slice(0, width - 14)}`));
    if (packageMeta?.downloads != null) {
      out.push(dim(`         ${packageMeta.downloads.toLocaleString()} downloads/mo · ${packageMeta.ageDays} days old`));
    }
    if (server.alsoIn?.length) {
      out.push(dim(`         also configured in ${server.alsoIn.length} other client${server.alsoIn.length === 1 ? '' : 's'}`));
    }

    for (const f of findings) {
      out.push('');
      out.push(`         ${tag(f.severity)} ${bold(f.title)}  ${dim(f.id)}`);
      out.push(dim(`         evidence: ${String(f.evidence).slice(0, width * 2)}`));
      out.push(wrap(f.why, width - 12, '         '));
      out.push(c('32', wrap(`→ ${f.fix}`, width - 12, '         ')));
    }
    out.push('');
  }

  const parts = SEVERITY_ORDER.filter((s) => summary.counts[s] > 0).map((s) => `${summary.counts[s]} ${s}`);
  out.push('  ' + '─'.repeat(width - 4));
  out.push(summary.findings ? `  ${bold(parts.join(', '))}` : c('32', '  No issues found.'));

  if (!summary.deep) out.push(dim('  Run with --deep to download and inspect each package source (nothing is executed).'));
  if (!summary.paranoid) out.push(dim('  Run with --paranoid to include lower-confidence findings.'));
  out.push('');
  return out.join('\n');
}

export function renderMarkdown(result) {
  const { summary, results, scanned } = result;
  const out = ['# MCP security audit', ''];
  out.push(`Scanned **${summary.servers}** server${summary.servers === 1 ? '' : 's'} across **${summary.configs}** config file${summary.configs === 1 ? '' : 's'}.`);
  out.push('');

  if (summary.findings) {
    const parts = SEVERITY_ORDER.filter((s) => summary.counts[s] > 0).map((s) => `${summary.counts[s]} ${s}`);
    out.push(`**${summary.findings} finding${summary.findings === 1 ? '' : 's'}:** ${parts.join(', ')}`);
  } else {
    out.push('**No issues found.**');
  }
  out.push('');
  out.push('| Config | Path |');
  out.push('| --- | --- |');
  for (const s of scanned) out.push(`| ${s.client} | \`${s.path}\` |`);
  out.push('');

  for (const r of results) {
    out.push(`## ${r.server.name}`);
    out.push('');
    out.push(`- Transport: \`${r.server.transport}\``);
    if (r.package) out.push(`- Package: \`${r.package}\``);
    if (r.packageMeta?.downloads != null) out.push(`- Popularity: ${r.packageMeta.downloads.toLocaleString()} downloads/month, ${r.packageMeta.ageDays} days old`);
    out.push('');
    if (!r.findings.length) {
      out.push('No issues found.');
      out.push('');
      continue;
    }
    for (const f of r.findings) {
      out.push(`### ${f.severity.toUpperCase()} — ${f.title}`);
      out.push('');
      out.push(`\`${f.id}\` · confidence: ${f.confidence}`);
      out.push('');
      out.push(`**Evidence:** \`${String(f.evidence).replace(/`/g, "'")}\``);
      out.push('');
      out.push(f.why);
      out.push('');
      out.push(`**Fix:** ${f.fix}`);
      out.push('');
    }
  }
  out.push('---');
  out.push('');
  out.push('Generated by [mcpaudit](https://github.com/AndrewXuTurtle/mcpaudit).');
  return out.join('\n');
}
