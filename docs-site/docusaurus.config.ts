import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'sbx',
  tagline:
    'a sandbox launcher that runs tools and encapsulated AI agents in a bubblewrap sandbox',
  favicon: 'assets/logo-mark.svg',

  url: 'https://gigi206.github.io',
  baseUrl: '/ops-cli/',

  organizationName: 'gigi206',
  projectName: 'ops-cli',

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
    mermaid: true,
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          // The migrated user guide lives under docs/guide/ (relative to the
          // project root), mirroring the old mkdocs docs_dir. `index.md` per
          // directory replaces the old README.md index pages.
          path: 'docs/guide',
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/gigi206/ops-cli/tree/ops-v2/docs-site/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'sbx',
      logo: {
        alt: 'sbx',
        src: 'assets/logo.svg',
      },
      items: [
        { type: 'docSidebar', sidebarId: 'guideSidebar', position: 'left', label: 'Docs' },
        {
          href: 'https://github.com/gigi206/ops-cli',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      copyright: `Copyright © ${new Date().getFullYear()} gigi206.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['toml', 'bash', 'rust'],
    },
    mermaid: {
      theme: { light: 'neutral', dark: 'forest' },
    },
  } satisfies Preset.ThemeConfig,

  plugins: [
    // Client-side full-text search, no external service. Equivalent to Pagefind
    // (Starlight's engine) and to mkdocs-material's built-in search. Indexes
    // every page on disk at build time, so content aggregated from remote repos
    // (plugins, apps) must be assembled before `docusaurus build` runs.
    [
      '@easyops-cn/docusaurus-search-local',
      {
        indexBlog: false,
        docsRouteBasePath: '/',
        highlightSearchTermsOnTargetPage: true,
      },
    ],
  ],
};

export default config;
