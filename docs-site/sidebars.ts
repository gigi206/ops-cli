import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

// The site has two halves, each with its own sidebar and its own navbar entry:
//
//   guideSidebar     what you read: start, recipes, concepts, workflows, operations.
//                    Ordered editorially, by reading order; a linear reader meets the
//                    product before its knobs.
//   referenceSidebar what you look up: configuration fields, CLI verbs, env vars,
//                    exit codes, glossary. Nobody reads these linearly, so they are
//                    grouped for scanning instead: Configuration by subject (a reader
//                    knows what they want the cage to do, not which field does it),
//                    Command reference alphabetically (a reader already has the
//                    verb's name). The thematic view of the verbs lives in
//                    `cli/index`, where it costs nothing.
//
// The navigation is listed explicitly rather than derived from the directory tree:
// the guide's pages carry no frontmatter, and a section's order is a choice.
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
      label: 'How-to',
      items: [
        'how-to/index',
        'how-to/run-agent-safely',
        'how-to/reproducible-toolchain',
        'how-to/restrict-network',
      ],
    },
    {
      type: 'category',
      label: 'Concepts',
      items: [
        'concepts/overview',
        'concepts/architecture',
        'concepts/security-model',
        'concepts/decisions',
        'concepts/trust',
        'concepts/enforcement',
        'concepts/observability',
        'concepts/provisioning',
        'concepts/directory-layout',
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
        'secrets/oauth',
        'secrets/plugins',
        'secrets/stores',
      ],
    },
    // Operations rather than model: sessions, gc and upgrade are commands a user runs
    // over a project's lifetime, not ideas the rest of the guide builds on, so they
    // leave Concepts for their own section, under docs/housekeeping/.
    {
      type: 'category',
      label: 'Housekeeping',
      items: ['housekeeping/sessions', 'housekeeping/gc', 'housekeeping/upgrade'],
    },
  ],
  referenceSidebar: [
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
            'configuration/timezone',
            'configuration/binds',
            'configuration/packages',
            'configuration/service',
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
            'configuration/open',
          ],
        },
        {
          type: 'category',
          label: 'Network and credentials',
          items: [
            'configuration/network',
            'configuration/secret',
            'configuration/ssh-agent',
            'configuration/broker',
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
        'cli/logs',
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
        'cli/version',
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
