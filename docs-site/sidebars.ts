import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

// The navigation is listed explicitly rather than derived from the directory tree: the
// guide's pages carry no frontmatter, and a section's order is a choice. Most sections
// are ordered editorially, by reading order; `Command reference` alone is alphabetical,
// since a reader arrives there already knowing the verb's name.
// A new page therefore has to be listed here, or it ships reachable only by URL
// and by search.
const sidebars: SidebarsConfig = {
  guideSidebar: [
    'index',
    {
      type: 'category',
      label: 'Getting started',
      items: [
        'getting-started/installation',
        'getting-started/quickstart',
        'getting-started/doctor',
        'getting-started/troubleshooting',
      ],
    },
    {
      type: 'category',
      label: 'Concepts',
      items: [
        'concepts/overview',
        'concepts/security-model',
        'concepts/trust',
        'concepts/enforcement',
        'concepts/observability',
        'concepts/sessions',
        'concepts/provisioning',
        'concepts/upgrade',
        'concepts/gc',
        'concepts/directory-layout',
      ],
    },
    // Configuration and Command reference carry roughly half the guide between them, so
    // each is grouped rather than listed flat — on different principles, because they
    // are read differently. Configuration groups by subject: a reader knows what they
    // want the cage to do, not which field does it. The command reference is
    // alphabetical: a reader already has the verb's name and wants its page. The
    // thematic view of the verbs lives in `cli/index` instead, where it costs nothing.
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'configuration/index',
        {
          type: 'category',
          label: "The cage's contents",
          items: [
            'configuration/env',
            'configuration/binds',
            'configuration/packages',
            'configuration/tools',
            'configuration/recommended-tools',
            'configuration/nixpkgs',
          ],
        },
        {
          type: 'category',
          label: 'Enforcement and refusals',
          items: [
            'configuration/limits',
            'configuration/seccomp',
            'configuration/devices',
            'configuration/fs',
            'configuration/proc',
            'configuration/notify',
          ],
        },
        {
          type: 'category',
          label: 'Desktop access',
          items: [
            'configuration/gui',
            'configuration/gpu',
            'configuration/audio',
            'configuration/dbus',
          ],
        },
        {
          type: 'category',
          label: 'Network and credentials',
          items: [
            'configuration/network',
            'configuration/secret',
            'configuration/ssh-agent',
            'configuration/task',
          ],
        },
        {
          type: 'category',
          label: 'Composition',
          items: [
            'configuration/apps',
            'configuration/bundles',
            'configuration/overrides',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Command reference',
      items: [
        'cli/index',
        'cli/app',
        'cli/bundle',
        'cli/completion',
        'cli/config',
        'cli/doctor',
        'cli/fs',
        'cli/gc',
        'cli/mise',
        'cli/net',
        'cli/path',
        'cli/plugins',
        'cli/proc',
        'cli/projects',
        'cli/run',
        'cli/search',
        'cli/secret',
        'cli/session',
        'cli/ssh-agent',
        'cli/storage',
        'cli/store',
        'cli/task',
        'cli/test',
        'cli/trust',
        'cli/untrust',
        'cli/upgrade',
      ],
    },
    {
      type: 'category',
      label: 'Apps and profiles',
      items: ['apps/index', 'apps/home', 'apps/profiles', 'apps/catalog'],
    },
    {
      type: 'category',
      label: 'Networking',
      items: [
        'networking/index',
        'networking/architecture',
        'networking/modes',
        'networking/rules',
        'networking/groups',
        'networking/forward',
        'networking/ask',
        'networking/observability',
      ],
    },
    {
      type: 'category',
      label: 'Declared operations',
      items: [
        'tasks/index',
        'tasks/parameters',
        'tasks/credentials',
        'tasks/execution',
        'tasks/output',
        'tasks/network',
      ],
    },
    {
      type: 'category',
      label: 'Secrets',
      items: [
        'secrets/index',
        'secrets/resolvers',
        'secrets/injection',
        'secrets/redaction',
        'secrets/plugins',
        'secrets/stores',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/environment-variables',
        'reference/exit-codes',
        'reference/glossary',
      ],
    },
  ],
};

export default sidebars;
