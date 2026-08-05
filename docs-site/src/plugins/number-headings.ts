import { createSlugger, parseMarkdownHeadingId } from '@docusaurus/utils';
import type { Plugin } from 'unified';
import type { Root } from 'mdast';
import type { Root as HastRoot } from 'hast';

/**
 * Numbered section headings, per page: h2 → 1., 2., 3., h3 → 1.1, 1.2, h4 →
 * 1.1.1... The h1 (the page title) is left alone.
 *
 * Registered under `beforeDefaultRemarkPlugins` so the number lands in the
 * heading *text* before the default plugins run: the "On this page" TOC then
 * carries the numbers too, at no extra cost.
 *
 * Anchor preservation: Docusaurus's own headings plugin runs after this one
 * and honors a pre-set `hProperties.id`. The id is computed here from the
 * original, unnumbered text, so every existing in-page anchor (hundreds of
 * cross-references across the guide) keeps working unchanged. The dedicated
 * slugger is kept in sync with the one the headings plugin creates, so
 * duplicate-title suffixes match as well: every heading it slugs, this one
 * slugs too, in the same order, including the levels left unnumbered. A
 * heading whose id the author pinned is handed over untouched, see
 * `hasAuthoredId`.
 */

type MdNode = {
  type: string;
  value?: string;
  depth?: number;
  children?: MdNode[];
  // Loose on purpose: the mdast node types narrow `data` differently (e.g.
  // TableRowData carries no index signature), and this plugin only ever
  // touches the heading id slot.
  data?: any;
};

const NUMBERED_DEPTHS = [2, 3, 4] as const;

function textContent(node: MdNode): string {
  if (node.type === 'text' || node.type === 'inlineCode') {
    return node.value ?? '';
  }
  if (node.children) {
    // Same filter as Docusaurus's headings plugin: html/jsx nodes do not
    // participate in the anchor slug.
    return node.children
      .filter((child) => child.type !== 'html' && child.type !== 'jsx')
      .map(textContent)
      .join('');
  }
  return '';
}

function isHeading(node: MdNode): node is MdNode & { depth: number } {
  return node.type === 'heading' && typeof node.depth === 'number';
}

/**
 * Whether the author pinned the anchor themselves, in any of the three ways
 * Docusaurus honors: the `{#id}` suffix, an HTML comment, or an MDX comment.
 *
 * Such a heading must be left entirely alone here. The headings plugin only
 * reads the author's id when no id is already set, and it spends no slug on
 * those headings either, so pre-setting one would both discard the pinned
 * anchor and desynchronize the two sluggers.
 *
 * The MDX form is approximated: it is matched on the expression source, where
 * the headings plugin matches on the parsed estree (an empty body holding
 * exactly one comment). The two part ways on a heading carrying several
 * expressions at once, which no heading in the guide does.
 */
function hasAuthoredId(node: MdNode, text: string): boolean {
  if (parseMarkdownHeadingId(text, 'classic').id) {
    return true;
  }
  const last = node.children?.[(node.children?.length ?? 0) - 1];
  if (!last) {
    return false;
  }
  // Both comment forms carry their id as the first word, behind a leading `#`.
  if (last.type === 'html') {
    const comment = /^<!--([\s\S]*)-->$/.exec(last.value ?? '');
    return comment !== null && comment[1].trim().startsWith('#');
  }
  if (last.type === 'mdxTextExpression') {
    return (last.value ?? '')
      .trim()
      .replace(/^\/\*/, '')
      .trim()
      .startsWith('#');
  }
  return false;
}

const numberHeadings: Plugin<[], Root> = () => (root) => {
  const slugs = createSlugger();
  const counters: Record<number, number> = { 2: 0, 3: 0, 4: 0 };

  const visit = (node: MdNode): void => {
    if (isHeading(node)) {
      const { depth } = node;
      const originalText = textContent(node);
      const authored = hasAuthoredId(node, originalText);

      // A new h1 opens a fresh numbering scope.
      if (depth === 1) {
        for (const level of NUMBERED_DEPTHS) counters[level] = 0;
      }

      if (depth < 2 || depth > 4) {
        // Keep the slugger's dedup state aligned with the headings plugin,
        // which slugs every heading in document order, h1 and h5/h6 included.
        // Skipping one here would shift a later duplicate's `-N` suffix. The
        // heading itself keeps its naturally derived anchor.
        if (!authored) slugs.slug(originalText, { maintainCase: false });
        return;
      }

      counters[depth] += 1;
      for (const level of NUMBERED_DEPTHS) {
        if (level > depth) counters[level] = 0;
      }

      const number = NUMBERED_DEPTHS.filter((level) => level <= depth)
        .map((level) => counters[level])
        .join('.');

      if (!authored) {
        node.data ??= {};
        node.data.hProperties ??= {};
        node.data.hProperties.id = slugs.slug(originalText, {
          maintainCase: false,
        });
      }

      // "1. ", "1.1 ", "1.1.1 ": the top level carries a dot, the nested
      // levels only the separator — the classic manual convention. The number
      // stays plain text here so the "On this page" TOC (derived from the raw
      // heading text) carries it; `styleHeadingNumbers` reshapes it for
      // display at the rehype stage.
      node.children ??= [];
      node.children.unshift({
        type: 'text',
        value: `${number}${depth === 2 ? '.' : ''} `,
      });
      return;
    }

    if (node.children) {
      for (const child of node.children) visit(child);
    }
  };

  visit(root);
};

export default numberHeadings;

type HastNode = {
  type: string;
  tagName?: string;
  value?: string;
  properties?: { className?: string | string[] };
  children?: HastNode[];
};

/**
 * Wraps the automatic section number of each heading in a span
 * (`.section-number`), so CSS can hold it a step off the title. The number is
 * plain text in the remark tree (the TOC and anchors are built from there);
 * only the rendered heading is reshaped.
 *
 * Registered under `beforeDefaultRehypePlugins`. Every h2–h4 heading carries
 * the "N. " prefix by construction, and the first child is always its text
 * node, so a match here can only be a number this site generated.
 *
 * The separating space moves into the span along with the number, rather than
 * being left at the head of the title: a copied heading keeps its "1. Title"
 * shape, and the CSS margin then widens that one space instead of adding a
 * second one.
 */
export const styleHeadingNumbers: Plugin<[], HastRoot> = () => (root) => {
  const visit = (node: HastNode): void => {
    if (node.type === 'element' && /^h[234]$/.test(node.tagName ?? '')) {
      const first = node.children?.[0];
      if (first?.type === 'text' && first.value !== undefined) {
        const match = /^(\d+(?:\.\d+)*\.?) /.exec(first.value);
        if (match) {
          first.value = first.value.slice(match[0].length);
          node.children?.unshift({
            type: 'element',
            tagName: 'span',
            properties: { className: ['section-number'] },
            children: [{ type: 'text', value: match[0] }],
          });
        }
      }
      return;
    }

    if (node.children) {
      for (const child of node.children) visit(child);
    }
  };

  visit(root);
};
