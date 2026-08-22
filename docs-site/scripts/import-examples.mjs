#!/usr/bin/env node
// Generates docs/guide/secrets/providers/ from examples/secrets/<name>/README.md.
//
// The per-provider recipes are written where they are used, next to the .sbx.toml
// fragments they describe, and a reader who never clones the repository would never
// meet them: they are not in the sidebar and Pagefind never indexes them. This script
// is the bridge. The output is committed so the site builds from a plain checkout, and
// `--check` re-runs the transform to fail CI when the two have drifted.
import { readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, '..', '..', 'examples', 'secrets');
const OUT = join(here, '..', 'docs', 'guide', 'secrets', 'providers');
const check = process.argv.includes('--check');

const BANNER = (name) =>
  `\n---\n\n*This page is generated from \`examples/secrets/${name}/README.md\`. Edit it there:\n` +
  `the file beside the configuration it describes is the copy people import.*\n`;

/**
 * The guide does not write em dashes (src/docs_coverage.rs enforces it); the READMEs
 * these pages come from do. Rewriting them at the source would churn 42 files that
 * read fine where they live, so the punctuation is converted on the way in: a colon
 * where the dash introduces an explanation, a comma where the sentence already has a
 * colon or the dash sits inside parentheses. The line wrapping is left alone, so the
 * generated page stays diffable against its source.
 */
function noEmDash(body) {
  const fences = [];
  const masked = body.replace(/```[\s\S]*?```/g, (m) => `\u0000${fences.push(m) - 1}\u0000`);

  // One pass, carrying two facts about the sentence being read: whether the dash sits inside an
  // unclosed parenthesis, and whether this sentence has already been given a colon. The second is
  // what a closing dash needs to know: the opening half took the colon, so the closing half is a
  // comma rather than a second introduction.
  let out = '';
  let last = 0;
  let depth = 0;
  let colonUsed = false;
  let colonInParen = false;
  const dash = /(\s+)—(\s+)/g;
  for (let i = 0; i < masked.length; i += 1) {
    const ch = masked[i];
    if (ch === '(') {
      depth += 1;
      if (depth === 1) colonInParen = false;
    } else if (ch === ')') depth = Math.max(0, depth - 1);
    // A colon that closes a bold label (`- **Variable:** …`) punctuates the label, not the
    // sentence, so it leaves the sentence's one colon still available.
    else if (ch === ':' && masked.slice(i + 1, i + 3) !== '**') {
      if (depth > 0) colonInParen = true;
      else colonUsed = true;
    }
    else if (ch === '.' || ch === '!' || ch === '?') {
      depth = 0;
      colonUsed = false;
    } else if (ch === '—') {
      dash.lastIndex = Math.max(0, i - 40);
      let m;
      while ((m = dash.exec(masked)) !== null && m.index + m[1].length < i);
      if (!m || m.index + m[1].length !== i) continue;
      const [, ws1, ws2] = m;
      // A sentence gets one colon. After that the closing half of a parenthetical is a comma
      // when what follows leans on the clause before it (`so`, `and`, `which`), and a semicolon
      // when what follows stands on its own.
      const after = masked.slice(i + 1, i + 1 + m[2].length + 12).trimStart().toLowerCase();
      const leans = /^(so|and|but|or|yet|nor|which|because|since|while|though)\b/.test(after);
      // `- **Variable:** `X` — the env var …` is apposition after a label, not a new clause:
      // the label already took a colon, so a second one reads heavy and a semicolon reads wrong.
      const lineStart = masked.lastIndexOf('\n', i) + 1;
      const label = /^\s*[-*]\s+\*\*[^*]+:\*\*[^—.]*$/.test(masked.slice(lineStart, i));
      const punct = label
        ? ','
        : depth > 0
          ? colonInParen
            ? ','
            : ':'
          : colonUsed
            ? leans
              ? ','
              : ';'
            : ':';
      if (punct === ':') {
        if (depth > 0) colonInParen = true;
        else colonUsed = true;
      }
      const ws = ws1.includes('\n') ? ws1 : ws2.includes('\n') ? ws2 : ' ';
      out += masked.slice(last, m.index) + punct + ws;
      last = m.index + m[0].length;
      i = last - 1;
    }
  }
  out += masked.slice(last);
  return out.replace(/\u0000(\d+)\u0000/g, (_, n) => fences[Number(n)]);
}

/** Strip code spans and fences, to test the prose that is left. */
function prose(body) {
  return body.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '');
}

/** Repository-relative markdown links become site links; MDX has no autolinks. */
function rewrite(body, name) {
  const out = body
    // MDX v3 parses `<` as JSX, so CommonMark's <https://…> is a syntax error there.
    .replace(/<(https?:\/\/[^>\s]+)>/g, '[$1]($1)')
    // "the shared page" is `examples/secrets/README.md`, which the site does not have:
    // on a published page the reader is in the Secrets section, so name it.
    .replace(/\[the\s+shared\s+page\]\(\.\.\/README\.md\)/g, '[Secrets](../)')
    .replace(/\(see\s+the\s+shared\s+page\)/g, '(see [Secrets](../))')
    .replace(/\bthe\s+shared\s+page\b/g, '[Secrets](../)')
    .replace(/\]\(\.\.\/README\.md\)/g, '](../)')
    .replace(/\]\(\.\.\/([a-z0-9-]+)\/README\.md\)/g, ']($1)')
    // a sibling recipe, referenced as its directory in the repository
    .replace(/\]\(\.\.\/([a-z0-9-]+)\/\)/g, ']($1)')
    .replace(/\]\(\.\.\/\.\.\/([a-z0-9/-]+)\)/g, '](https://github.com/gigi206/ops-cli/tree/ops-v2/$1)');
  // A stray angle bracket in prose is a build error three minutes later, in a file
  // nobody edited; say so here, naming the source the author actually opens.
  const stray = prose(out).match(/<[^\s>]+>/);
  if (stray) {
    console.error(
      `examples/secrets/${name}/README.md: ${stray[0]} is JSX to MDX. ` +
        'Wrap it in backticks, or write it as a [text](url) link.'
    );
    process.exit(1);
  }
  return out;
}

/** The H1 carries `name` — provider, so the label is the backticked half. */
function split(md, name) {
  const m = md.match(/^#\s+(.*)$/m);
  const title = m ? m[1].trim() : name;
  const label = (title.match(/^`([^`]+)`/) || [null, name])[1];
  const body = md.replace(/^#\s+.*$/m, '').trim();
  const first = body
    .split('\n\n')
    .find((p) => p && !p.startsWith('```') && !p.startsWith('#'));
  const description = (first || `Injecting a credential for ${label}.`)
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*]/g, '')
    .replace(/\s+/g, ' ')
    .split('. ')[0]
    .slice(0, 240)
    .trim()
    .replace(/[.,;]$/, '') + '.';
  return { title, label, body, description };
}

const names = readdirSync(SRC, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(join(SRC, d.name, 'README.md')))
  .map((d) => d.name)
  .sort();

const pages = new Map();
names.forEach((name, i) => {
  // Normalised once, before anything is read out of it, so the title and the
  // description carry the guide's punctuation too.
  const source = noEmDash(readFileSync(join(SRC, name, 'README.md'), 'utf8'));
  const { title, label, body, description } = split(source, name);
  pages.set(`${name}.md`, [
    '---',
    `title: ${JSON.stringify(title)}`,
    `sidebar_label: ${JSON.stringify(label)}`,
    `description: ${JSON.stringify(description)}`,
    `sidebar_position: ${i + 1}`,
    '---',
    '',
    `# ${title}`,
    '',
    rewrite(body, name),
    BANNER(name),
  ].join('\n'));
});

const rows = names
  .map((name) => {
    const md = readFileSync(join(SRC, name, 'README.md'), 'utf8');
    const host = (md.match(/\[secret\."([^"]+)"\]/) || [])[1] || '';
    const from = (md.match(/from\s*=\s*"([^"]+)"/) || [])[1] || '';
    const header = (md.match(/header\s*=\s*"([^"]+)"/) || [])[1] || '';
    const type = (md.match(/type\s*=\s*"([^"]+)"/) || [])[1] || '';
    const label = (md.match(/^#\s+`([^`]+)`/m) || [null, name])[1];
    const cell = (v) => (v ? `\`${v}\`` : '—');
    return `| [\`${label}\`](${name}) | ${cell(host)} | ${cell(from)} | ${cell(header)} / ${cell(type)} |`;
  })
  .join('\n');

pages.set('index.md', `---
title: Provider recipes
sidebar_label: Provider recipes
description: A ready-made [secret] block for around forty API providers, each keyed by the host it authenticates to.
sidebar_position: 0
---

# Provider recipes

One page per provider: the \`[secret]\` block to paste, the environment variable the
\`from\` names, what is specific to that service, and a request that proves the header
arrived. The mechanics they share are on [Secrets](../) and in
[\`[secret]\`](../../configuration/secret); each page below adds only what its own
service needs.

New to this? [Give an agent a credential it can use but never
read](../../how-to/inject-a-credential) walks the whole path once, then these pages are
lookups.

| Provider | Host | Source | Header / type |
|---|---|---|---|
${rows}

Each page is generated from \`examples/secrets/<name>/README.md\`, which is the file
that sits beside the configuration it describes. Adding a provider there adds it here.
`);

if (check) {
  const seen = existsSync(OUT) ? readdirSync(OUT).sort() : [];
  const want = [...pages.keys()].sort();
  const bad = [];
  if (seen.join() !== want.join()) bad.push(`file set differs:\n  have: ${seen.join(' ')}\n  want: ${want.join(' ')}`);
  for (const [f, content] of pages) {
    const p = join(OUT, f);
    if (!existsSync(p)) continue;
    if (readFileSync(p, 'utf8') !== content) bad.push(`${f} is out of date`);
  }
  if (bad.length) {
    console.error(`docs/guide/secrets/providers is stale:\n- ${bad.join('\n- ')}\n\nRun: node scripts/import-examples.mjs`);
    process.exit(1);
  }
  console.log(`providers up to date (${names.length} pages)`);
  process.exit(0);
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
for (const [f, content] of pages) writeFileSync(join(OUT, f), content);
console.log(`wrote ${pages.size} pages to docs/guide/secrets/providers/`);
