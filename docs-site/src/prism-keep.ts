import type { PrismTheme } from 'prism-react-renderer';

/**
 * Syntax colours for "The Keep". The code surface stays the same stone in both
 * colour modes, so a single theme serves light and dark alike: table headers and
 * keywords in coral, keys in bone, every literal value in olive.
 */
const prismKeep: PrismTheme = {
  plain: {
    color: '#E6DDD1',
    backgroundColor: '#221E19',
  },
  styles: [
    {
      types: ['comment', 'prolog', 'cdata', 'doctype'],
      style: { color: '#7F7565', fontStyle: 'italic' },
    },
    {
      // Bracket and separator carry the body colour, so `[table]` reads as one
      // token rather than an accent word between two grey marks.
      types: ['punctuation', 'operator', 'entity'],
      style: { color: '#E4DACB' },
    },
    {
      types: ['property', 'key', 'attr-name', 'variable', 'symbol'],
      style: { color: '#CFC3B2' },
    },
    {
      types: ['string', 'char', 'attr-value', 'url', 'inserted', 'regex'],
      style: { color: '#E8C34A' },
    },
    {
      types: ['number', 'boolean', 'constant', 'date'],
      style: { color: '#E8C34A' },
    },
    {
      // `class-name` belongs here: Prism marks a TOML table as `table class-name`,
      // and the later group would otherwise win and lighten it.
      types: ['keyword', 'atrule', 'selector', 'tag', 'table', 'section', 'important', 'class-name'],
      style: { color: '#E8895F' },
    },
    {
      types: ['function', 'builtin', 'title'],
      style: { color: '#F09368' },
    },
    {
      types: ['deleted'],
      style: { color: '#E8895F' },
    },
  ],
};

export default prismKeep;
