/**
 * The contract between `number-headings` and Docusaurus's own headings plugin.
 *
 * `number-headings` leans on two behaviours of that plugin which are internal,
 * not part of any public API: it honors a pre-set `hProperties.id` (re-slugging
 * it through its own slugger), and it slugs every heading in document order,
 * whatever the level. Both are what lets the numbers appear in the heading text
 * while the anchors stay derived from the unnumbered title. Neither is
 * guaranteed across a Docusaurus upgrade, and a break would be silent: the
 * build stays green, `tsc` stays green, no link goes missing, the anchors just
 * quietly change and every bookmark rots.
 *
 * Hence the central assertion below: for every heading, the anchor must be the
 * one the site would have had with no numbering at all.
 *
 * The tree is built by hand rather than parsed, so the test pulls in nothing
 * beyond what the plugin itself already imports.
 *
 * Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import numberHeadings from './number-headings.ts';
import headingsPlugin from '@docusaurus/mdx-loader/lib/remark/headings/index.js';

const docusaurusHeadings = headingsPlugin.default ?? headingsPlugin;

const text = (value) => ({ type: 'text', value });
const html = (value) => ({ type: 'html', value });
const h = (depth, ...children) => ({
  type: 'heading',
  depth,
  children: children.map((child) =>
    typeof child === 'string' ? text(child) : child,
  ),
});

/**
 * Cases the guide does not contain today, and that a future edit might: a
 * duplicate title across levels the plugin does not number, a level skipped on
 * the way down, and the two ways an author can pin an anchor by hand.
 */
const document = () => ({
  type: 'root',
  children: [
    h(1, 'Page title'),
    h(2, 'Alpha'),
    h(3, 'Alpha'),
    h(5, 'Alpha'),
    h(2, 'Alpha'),
    h(3, 'Orphan h3 with no h2 above it'),
    h(2, 'Ports'),
    h(4, 'Deep jump from h2 straight to h4'),
    h(2, 'Ports'),
    h(5, 'Late h5 named Ports'),
    h(2, 'Explicit anchor {#stable-id}'),
    h(2, 'Commented anchor ', html('<!-- #pinned-id -->')),
    h(2, 'Groups'),
    h(3, 'Groups'),
    h(4, 'Groups'),
  ],
});

function headingText(node) {
  if (node.type === 'text' || node.type === 'inlineCode') {
    return node.value;
  }
  return (node.children ?? []).map(headingText).join('');
}

/** The real pipeline: this plugin first, then the default one, as configured. */
async function process({ numbered }) {
  const tree = document();
  if (numbered) {
    numberHeadings()(tree);
  }
  await docusaurusHeadings({ anchorsMaintainCase: false })(tree);
  return tree.children.map((node) => ({
    depth: node.depth,
    id: node.data?.id,
    text: headingText(node),
  }));
}

test('every anchor is the one the page would have without numbering', async () => {
  const bare = await process({ numbered: false });
  const numbered = await process({ numbered: true });

  assert.deepEqual(
    numbered.map((heading) => heading.id),
    bare.map((heading) => heading.id),
  );
});

test('sections are numbered per level, h1 left alone', async () => {
  const rendered = (await process({ numbered: true })).map(
    (heading) => `h${heading.depth} ${heading.text}`,
  );

  assert.deepEqual(rendered, [
    'h1 Page title',
    'h2 1. Alpha',
    'h3 1.1 Alpha',
    // Below the numbered levels: no number, and no slug spent either.
    'h5 Alpha',
    'h2 2. Alpha',
    'h3 2.1 Orphan h3 with no h2 above it',
    'h2 3. Ports',
    // A skipped level shows as a zero rather than silently renumbering: the
    // document structure is what needs fixing, and this makes it visible.
    'h4 3.0.1 Deep jump from h2 straight to h4',
    'h2 4. Ports',
    'h5 Late h5 named Ports',
    'h2 5. Explicit anchor',
    'h2 6. Commented anchor',
    'h2 7. Groups',
    'h3 7.1 Groups',
    'h4 7.1.1 Groups',
  ]);
});

test('an authored anchor is kept, and its syntax stays out of the title', async () => {
  const headings = await process({ numbered: true });
  const pinned = headings.filter((heading) =>
    heading.text.endsWith('anchor'),
  );

  assert.deepEqual(
    pinned.map((heading) => heading.id),
    ['stable-id', 'pinned-id'],
  );
  for (const heading of pinned) {
    assert.doesNotMatch(heading.text, /\{#|<!--/);
  }
});
