import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import prismKeep from './src/prism-keep';

const config: Config = {
  title: 'sbx',
  tagline:
    'a sandbox launcher that runs tools and encapsulated AI agents in a bubblewrap sandbox',
  favicon: 'assets/favicon.svg',

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
          // The guide sits under /docs/ so the root can be the landing page
          // (src/pages/index.tsx). Every in-guide link is relative, so none of
          // them care where the tree is mounted.
          routeBasePath: 'docs',
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

  // Renders ```mermaid fences. Without it `markdown.mermaid` resolves the block
  // to a theme component that does not exist, and the diagram vanishes from the
  // page instead of failing the build.
  themes: ['@docusaurus/theme-mermaid'],

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
        srcDark: 'assets/logo-dark.svg',
        width: 26,
        height: 26,
      },
      items: [
        { type: 'docSidebar', sidebarId: 'guideSidebar', position: 'left', label: 'Docs' },
        // The theme's own search slot, filled by src/theme/SearchBar. Declared
        // before the repository link so the bar reads: search, repository, mode.
        { type: 'search', position: 'right' },
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
      // One theme for both colour modes: the code surface is the same stone in
      // light and dark, so a second palette would only fight the first.
      theme: prismKeep,
      darkTheme: prismKeep,
      additionalLanguages: ['toml', 'bash', 'rust'],
    },
    mermaid: {
      theme: { light: 'neutral', dark: 'dark' },
      options: {
        fontFamily: "'JetBrains Mono Variable', ui-monospace, monospace",
        // Labels wrap at 200px by default, which turns a two-word caption into
        // a three-line column and stretches every diagram vertically.
        flowchart: { wrappingWidth: 280, nodeSpacing: 40, rankSpacing: 45 },
      },
    },
  } satisfies Preset.ThemeConfig,

  plugins: [
    // No server-side search plugin: Docusaurus 3.10's classic SearchBar is dead without
    // Algolia. Pagefind (post-build step, see package.json "postbuild") replaces it, and
    // src/theme/SearchBar fills the theme's search slot with it. Pagefind is
    // framework-agnostic and indexes the static HTML, so content aggregated from remote
    // repos (plugins, apps) is covered as long as it is assembled before the build runs.

    // The mermaid theme guards its ELK-layout import behind a build-time flag, but the
    // bundler still resolves the specifier and fails on the missing optional package.
    // The guides only use the built-in layouts, so the module resolves to nothing rather
    // than pulling a heavy graph-layout engine into the client bundle.
    () => ({
      name: 'mermaid-elk-layout-opt-out',
      configureWebpack: () => ({
        resolve: { alias: { '@mermaid-js/layout-elk': false } },
      }),
    }),
  ],
};

export default config;
