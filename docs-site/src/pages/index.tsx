import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';
import ThemedImage from '@theme/ThemedImage';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

const START = [
  {
    to: '/docs/getting-started/installation',
    label: 'Install',
    detail: 'the static binary, or a dev build',
  },
  {
    to: '/docs/getting-started/quickstart',
    label: 'Quick start',
    detail: 'your first sandboxed command',
  },
  {
    to: '/docs/concepts/security-model',
    label: 'Security model',
    detail: 'what the cage actually protects',
  },
];

// What the tool does, one card each, each pointing at the section that owns it.
// Every claim here is something the guide documents as shipped.
const CAPABILITIES = [
  {
    name: 'Filtered egress',
    detail:
      'Deny by default, then allow by host, port, path, method or regex. The cage has an empty network namespace; a host-side proxy is the only way out.',
    to: '/docs/networking/',
  },
  {
    name: 'Secrets stay outside',
    detail:
      'A credential is resolved on the host and injected into the request on the wire. The agent authenticates without the plaintext ever entering the cage.',
    to: '/docs/secrets/',
  },
  {
    name: 'Daemonless Nix',
    detail:
      "A project's full dependency set is installed into its own store, single-user, with no daemon and no change to the host OS.",
    to: '/docs/concepts/provisioning',
  },
  {
    name: 'Named app profiles',
    detail:
      '48 importable profiles and 26 bundles. Each app gets an isolated home, its own tools and its own egress policy.',
    to: '/docs/apps/',
  },
  {
    name: 'Brokered tasks',
    detail:
      'Expose a fixed command to the caged agent, run in a sibling cage with a credential the caller never holds.',
    to: '/docs/configuration/task',
  },
  {
    name: 'Observability',
    detail:
      'Record what the agent executed and what it wrote, and optionally veto a process before it runs.',
    to: '/docs/concepts/observability',
  },
];

// The three always-on layers, in the guide's own words. Anything opt-in or
// deferred stays off this page: a landing page that overstates the enforcement
// is worse than no landing page.
const ENFORCEMENT = [
  {
    name: 'bubblewrap',
    detail: 'Namespaces, no_new_privs, all capabilities dropped.',
  },
  {
    name: 'seccomp',
    detail: 'A two-filter syscall denylist, applied unconditionally.',
  },
  {
    name: 'cgroup v2',
    detail: 'Resource limits to bound denial-of-service, best-effort.',
  },
];

// The two layers share one schema: the global file sets the baseline, the
// project file inherits it and adds to it.
const GLOBAL_CONFIG = `[network]
# baseline for every project
mode = "deny"
allow = ["*.nixos.org"]

[packages]
jq = "nix:jq"`;

const PROJECT_CONFIG = `[network]
# no mode: inherits "deny", adds a host
allow = ["api.anthropic.com"]

[app.agent]
cmd = "opencode"`;

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout description={siteConfig.tagline}>
      <main className="home">
        <section className="home__hero">
          <div className="home__inner">
            <div className="home__hero-head">
              <ThemedImage
                className="home__mark"
                alt=""
                sources={{
                  light: useBaseUrl('/assets/logo.svg'),
                  dark: useBaseUrl('/assets/logo-dark.svg'),
                }}
              />
              <div>
                <p className="home__eyebrow">Sandbox launcher · static Rust binary</p>
                <h1 className="home__title">Give the agent a wall, not a promise.</h1>
              </div>
            </div>
            <p className="home__lede">
              Run tools and encapsulated AI agents inside a bubblewrap cage. They install the
              project's full dependency set through single-user, daemonless Nix, without
              mutating the host OS.
            </p>
            <div className="home__actions">
              <Link className="home__cta" to="/docs/">
                Read the docs
              </Link>
              <code className="home__command">$ sbx app run opencode</code>
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <h2 className="home__section-label">Start here</h2>
            <div className="home__grid home__grid--three">
              {START.map(({ to, label, detail }) => (
                <Link className="home__card home__card--link" to={to} key={to}>
                  <p className="home__card-name">{label}</p>
                  <p className="home__card-detail">{detail}</p>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="home__section">
          <div className="home__inner">
            <h2 className="home__section-label">What it does</h2>
            <div className="home__grid">
              {CAPABILITIES.map(({ name, detail, to }) => (
                <Link className="home__card home__card--link" to={to} key={name}>
                  <p className="home__card-name">{name}</p>
                  <p className="home__card-detail">{detail}</p>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <h2 className="home__section-label">Two files, one schema</h2>
            <p className="home__aside home__aside--lead">
              The global file sets your baseline; a project's <code>.sbx.toml</code> inherits
              it and adds to it. Both are read through the same{' '}
              <Link to="/docs/concepts/trust">trust gate</Link>, so cloning a hostile
              repository grants it nothing.
            </p>
            <div className="home__configs">
              <CodeBlock language="toml" title="~/.config/sbx/sbx.toml">
                {GLOBAL_CONFIG}
              </CodeBlock>
              <CodeBlock language="toml" title=".sbx.toml">
                {PROJECT_CONFIG}
              </CodeBlock>
            </div>
          </div>
        </section>

        <section className="home__section">
          <div className="home__inner">
            <h2 className="home__section-label">Always-on enforcement</h2>
            <div className="home__grid home__grid--three">
              {ENFORCEMENT.map(({ name, detail }) => (
                <div className="home__card" key={name}>
                  <p className="home__card-name">{name}</p>
                  <p className="home__card-detail">{detail}</p>
                </div>
              ))}
            </div>
            <p className="home__aside">
              The bind layout is the primary control: the cage runs as your uid, so a secret
              is protected by being{' '}
              <Link to="/docs/concepts/security-model">absent</Link>, not by a permission
              check. The layers above are{' '}
              <Link to="/docs/concepts/enforcement">defense in depth</Link> on top of it.
            </p>
          </div>
        </section>
      </main>
    </Layout>
  );
}
