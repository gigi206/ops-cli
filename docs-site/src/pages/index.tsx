import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

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

const START = [
  { to: '/docs/getting-started/installation', label: 'Install', detail: 'the static binary, or a dev build' },
  { to: '/docs/getting-started/quickstart', label: 'Quick start', detail: 'your first sandboxed command' },
  { to: '/docs/concepts/security-model', label: 'Security model', detail: 'what the cage actually protects' },
];

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout description={siteConfig.tagline}>
      <main className="home">
        <section className="home__hero">
          <p className="home__eyebrow">Sandbox launcher · static Rust binary</p>
          <h1 className="home__title">Give the agent a wall, not a promise.</h1>
          <p className="home__lede">
            Run tools and encapsulated AI agents inside a bubblewrap cage. They install the
            project's full dependency set through single-user, daemonless Nix — without
            mutating the host OS.
          </p>
          <div className="home__actions">
            <Link className="home__cta" to="/docs/">
              Read the docs
            </Link>
            <code className="home__command">$ sbx run -- claude</code>
          </div>
        </section>

        <section className="home__section">
          <h2 className="home__section-label">Always-on enforcement</h2>
          <div className="home__grid">
            {ENFORCEMENT.map(({ name, detail }) => (
              <div className="home__card" key={name}>
                <p className="home__card-name">{name}</p>
                <p className="home__card-detail">{detail}</p>
              </div>
            ))}
          </div>
          <p className="home__aside">
            The bind layout is the primary control — the cage runs as your uid, so a secret
            is protected by being <Link to="/docs/concepts/security-model">absent</Link>, not
            by a permission check. The layers above are{' '}
            <Link to="/docs/concepts/enforcement">defense in depth</Link> on top of it.
          </p>
        </section>

        <section className="home__section">
          <h2 className="home__section-label">Start here</h2>
          <div className="home__grid">
            {START.map(({ to, label, detail }) => (
              <Link className="home__card home__card--link" to={to} key={to}>
                <p className="home__card-name">{label}</p>
                <p className="home__card-detail">{detail}</p>
              </Link>
            ))}
          </div>
        </section>
      </main>
    </Layout>
  );
}
