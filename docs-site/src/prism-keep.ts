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
      types: ['punctuation', 'operator', 'entity'],
      style: { color: '#A89D8E' },
    },
    {
      types: ['property', 'key', 'attr-name', 'variable', 'symbol'],
      style: { color: '#C9BFAF' },
    },
    {
      types: ['string', 'char', 'attr-value', 'url', 'inserted', 'regex'],
      style: { color: '#B7C98A' },
    },
    {
      types: ['number', 'boolean', 'constant', 'date'],
      style: { color: '#B7C98A' },
    },
    {
      types: ['keyword', 'atrule', 'selector', 'tag', 'table', 'section', 'important'],
      style: { color: '#E8895F' },
    },
    {
      types: ['function', 'class-name', 'builtin', 'title'],
      style: { color: '#F09368' },
    },
    {
      types: ['deleted'],
      style: { color: '#E8895F' },
    },
  ],
};

export default prismKeep;
