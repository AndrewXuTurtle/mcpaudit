/**
 * Renders real mcpaudit output to an SVG terminal frame for the README.
 *
 * The output is captured from an actual run against a fixture, not mocked up,
 * so the demo cannot drift away from what the tool really prints. ANSI is
 * translated to styled tspans rather than screenshotted, which keeps the image
 * text-selectable, diffable in review, and a few KB instead of a few hundred.
 */
import { execFileSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';

const FIXTURE = 'test/fixtures/demo.json';
const OUT = 'docs/demo.svg';

const CHAR_W = 8.4;
const LINE_H = 19;
const PAD_X = 20;
const PAD_Y = 46;

/** Terminal palette. Deliberately close to a dark terminal so it reads as one. */
const FG = '#d8d5cc';
const COLORS = { 31: '#e8785c', 32: '#7fbf8f', 33: '#d9a441', 36: '#6fb2c9', 97: '#ffffff' };
const BG_COLORS = { 41: '#a3341f' };

const escXml = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

/**
 * Split an ANSI string into styled runs. Handles the SGR subset the reporter
 * emits: reset, bold, dim, foreground colours, and the inverted CRITICAL badge.
 */
function parseAnsi(line) {
  const runs = [];
  let style = { bold: false, dim: false, fg: null, bg: null };
  let text = '';

  const flush = () => {
    if (text) runs.push({ text, ...style });
    text = '';
  };

  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  let m;
  while ((m = re.exec(line)) !== null) {
    text += line.slice(last, m.index);
    flush();
    last = re.lastIndex;

    for (const codeStr of m[1].split(';')) {
      const code = Number(codeStr || '0');
      if (code === 0) style = { bold: false, dim: false, fg: null, bg: null };
      else if (code === 1) style.bold = true;
      else if (code === 2) style.dim = true;
      else if (COLORS[code]) style.fg = COLORS[code];
      else if (BG_COLORS[code]) style.bg = BG_COLORS[code];
    }
  }
  text += line.slice(last);
  flush();
  return runs;
}

function render(lines) {
  const cols = Math.max(...lines.map((l) => l.plain.length), 64);
  const width = Math.ceil(cols * CHAR_W) + PAD_X * 2;
  const height = lines.length * LINE_H + PAD_Y + 20;

  const body = lines.map((line, row) => {
    const y = PAD_Y + row * LINE_H;
    let col = 0;
    const parts = [];

    for (const run of line.runs) {
      const x = PAD_X + col * CHAR_W;
      const w = run.text.length * CHAR_W;

      if (run.bg) {
        parts.push(`<rect x="${x.toFixed(1)}" y="${(y - 13).toFixed(1)}" width="${w.toFixed(1)}" height="${LINE_H - 2}" fill="${run.bg}" rx="2"/>`);
      }
      const fill = run.fg || (run.bg ? '#fff' : FG);
      const opacity = run.dim ? ' opacity="0.55"' : '';
      const weight = run.bold ? ' font-weight="600"' : '';
      parts.push(`<text x="${x.toFixed(1)}" y="${y}" fill="${fill}"${weight}${opacity}>${escXml(run.text)}</text>`);
      col += run.text.length;
    }
    return parts.join('');
  }).join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13">
  <rect width="${width}" height="${height}" rx="10" fill="#16150f"/>
  <rect width="${width}" height="30" rx="10" fill="#211f1a"/>
  <rect y="20" width="${width}" height="10" fill="#211f1a"/>
  <circle cx="19" cy="15" r="5" fill="#e8785c"/>
  <circle cx="37" cy="15" r="5" fill="#d9a441"/>
  <circle cx="55" cy="15" r="5" fill="#7fbf8f"/>
  <text x="${width / 2}" y="19.5" fill="#8a887f" font-size="11" text-anchor="middle">mcpaudit</text>
${body}
</svg>`;
}

const raw = execFileSync('node', ['bin/cli.js', FIXTURE, '--fail-on', 'none'], {
  encoding: 'utf8',
  env: { ...process.env, FORCE_COLOR: '1', COLUMNS: '96' },
});

const lines = raw.replace(/\n+$/, '').split('\n').map((l) => ({
  runs: parseAnsi(l),
  // eslint-disable-next-line no-control-regex
  plain: l.replace(/\x1b\[[0-9;]*m/g, ''),
}));

await writeFile(OUT, render(lines));
console.log(`${OUT}: ${lines.length} lines, ${Math.max(...lines.map((l) => l.plain.length))} cols`);
