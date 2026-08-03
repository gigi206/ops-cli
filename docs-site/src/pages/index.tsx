import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import ThemedImage from '@theme/ThemedImage';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

// The transcript is real output, trimmed and with host-specific paths made
// generic the way the guide does it. The repository's own rule is that quoted
// output matches the binary; inventing a plausible line would break it on the
// most-read page of the site.
const TRANSCRIPT: { kind: 'cmd' | 'ok' | 'detail' | 'plain' | 'blank'; text?: string; tail?: string }[] = [
  { kind: 'cmd', text: 'sbx doctor' },
  { kind: 'plain', text: 'sbx doctor — runtime preflight' },
  { kind: 'blank' },
  { kind: 'ok', text: 'bubblewrap', tail: '/usr/bin/bwrap' },
  { kind: 'ok', text: 'sandbox', tail: 'bubblewrap launched a hardened process' },
  { kind: 'detail', text: 'user namespaces: capability-bearing' },
  { kind: 'detail', text: 'no_new_privs set, every capability dropped' },
  { kind: 'detail', text: 'host $HOME absent' },
  { kind: 'ok', text: 'resource limits', tail: 'cage capped via a systemd scope' },
  { kind: 'ok', text: 'nix', tail: '/nix/var/nix/profiles/default/bin/nix' },
  { kind: 'ok', text: 'store', tail: '/home/you/.local/share/sbx/store' },
  { kind: 'ok', text: 'channel', tail: 'nixos-unstable @ 0954f7e (locked)' },
  { kind: 'blank' },
  { kind: 'plain', text: 'sbx: prerequisites OK.' },
  { kind: 'blank' },
  { kind: 'cmd', text: 'sbx trust' },
  { kind: 'plain', text: 'sbx: trusted .sbx.toml' },
  { kind: 'blank' },
  { kind: 'cmd', text: 'sbx app import examples/app/opencode.toml' },
  { kind: 'plain', text: "imported app profile 'opencode' -> ~/.config/sbx/apps/opencode.toml" },
  { kind: 'detail', text: 'launch it with: sbx app run opencode' },
  { kind: 'blank' },
  { kind: 'cmd', text: 'sbx app run opencode' },
];

const INSIDE = [
  'the project directory',
  'a per-project Nix store',
  'an isolated $HOME, per app',
  'explicitly granted binds',
  'host-injected credentials, per app',
];

const ABSENT = [
  'the rest of the host filesystem',
  '~/.ssh, ~/.aws, ~/.config',
  'your real $HOME and dotfiles',
  'capabilities, setuid escalation',
  'egress, under a filtering mode',
];

// Three always-on layers (Landlock is a deferred option in this codebase, not a
// layer that runs today), plus the egress firewall, which is opt-in by posture.
const LAYERS: { n: string; tag?: string; name: string; detail: string; to?: string }[] = [
  {
    n: '01',
    name: 'bubblewrap',
    detail: 'All namespaces, no_new_privs, capabilities dropped.',
    to: '/docs/concepts/enforcement',
  },
  {
    n: '02',
    name: 'seccomp',
    detail: 'A two-filter syscall denylist, applied unconditionally.',
    to: '/docs/configuration/seccomp',
  },
  {
    n: '03',
    name: 'cgroup v2',
    detail: 'Memory, pids and CPU limits, best-effort.',
    to: '/docs/configuration/limits',
  },
  {
    n: '04',
    tag: 'opt-in',
    name: 'egress proxy',
    detail:
      'Deny by default, then allow by host, port, path, method or regex. A host-side MITM proxy is the only way out of an empty netns.',
    to: '/docs/networking/',
  },
];

const VERBS = [
  { cmd: 'sbx doctor', detail: 'Verify the host can build the cage.', to: '/docs/cli/doctor' },
  { cmd: 'sbx config show', detail: 'Resolved config, with its trust state.', to: '/docs/cli/config' },
  { cmd: 'sbx run -- <cmd>', detail: 'Run a command, or an interactive shell.', to: '/docs/cli/run' },
  { cmd: 'sbx search', detail: "Find packages for the project's store.", to: '/docs/cli/search' },
  { cmd: 'sbx app run <name>', detail: 'Launch a named agent profile.', to: '/docs/cli/app' },
  { cmd: 'sbx upgrade', detail: 'Move nix, mise or the flake forward.', to: '/docs/cli/upgrade' },
  { cmd: 'sbx trust', detail: "Bind trust to the file's content hash.", to: '/docs/cli/trust' },
  { cmd: 'sbx session', detail: 'List, attach to or stop a session.', to: '/docs/cli/session' },
];

const PROFILE_SAMPLE = `[network]
mode  = "deny"
allow = ["api.anthropic.com", "crates.io"]

[app.agent]
cmd     = "opencode"
network = { mode = "deny", allow = ["api.anthropic.com"] }

[secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
kind   = "http-header"
header = "x-api-key"
type   = "raw"`;

// The portable form: the same fields, at the top level, the filename being the
// app name. Documented in configuration/apps.md.
const PROFILE_FILE = `cmd     = "opencode"
network = { mode = "deny", allow = ["api.anthropic.com"] }

[secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
kind   = "http-header"
header = "x-api-key"
type   = "raw"`;

function Transcript(): ReactNode {
  return (
    <div className="terminal" aria-hidden="true">
      <div className="terminal__bar">
        <span className="terminal__dot" />
        <span className="terminal__dot" />
        <span className="terminal__dot" />
        <span className="terminal__path">~/work/api-gateway</span>
      </div>
      <pre className="terminal__body">
        {TRANSCRIPT.map((line, i) => {
          if (line.kind === 'blank') return <span key={i}>{'\n'}</span>;
          if (line.kind === 'cmd') {
            return (
              <span key={i}>
                <span className="terminal__prompt">$ </span>
                <span className="terminal__cmd">{line.text}</span>
                {'\n'}
              </span>
            );
          }
          if (line.kind === 'ok') {
            return (
              <span key={i}>
                {'  '}
                <span className="terminal__ok">[ ok ]</span>
                {' '}
                <span className="terminal__key">{line.text?.padEnd(17)}</span>
                <span className="terminal__val">{line.tail}</span>
                {'\n'}
              </span>
            );
          }
          if (line.kind === 'detail') {
            return (
              <span key={i} className="terminal__detail">
                {'         · '}
                {line.text}
                {'\n'}
              </span>
            );
          }
          return (
            <span key={i} className="terminal__plain">
              {line.text}
              {'\n'}
            </span>
          );
        })}
      </pre>
    </div>
  );
}

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout description={siteConfig.tagline}>
      <main className="home">
        <section className="home__hero">
          <div className="home__inner home__hero-grid">
            <div className="home__hero-copy">
              <p className="home__eyebrow">single static Rust binary · Linux</p>
              <div className="home__hero-head">
                <ThemedImage
                  className="home__mark"
                  alt=""
                  sources={{
                    light: useBaseUrl('/assets/logo.svg'),
                    dark: useBaseUrl('/assets/logo-dark.svg'),
                  }}
                />
                <h1 className="home__title">
                  The bind layout <em>is</em> the security control.
                </h1>
              </div>
              <p className="home__lede">
                sbx is a sandbox launcher. It runs tools and encapsulated AI agents inside a
                bubblewrap cage, where they install a project's full dependency set through
                single-user, daemonless Nix, without mutating the host OS.
              </p>
              <div className="home__actions">
                <Link className="home__cta" to="/docs/getting-started/quickstart">
                  Get started
                </Link>
                <code className="home__command">
                  $ sbx app import opencode.toml{'\n'}$ sbx app run opencode
                </code>
              </div>
              <ul className="home__badges">
                <li>no OCI runtime</li>
                <li>no daemon</li>
                <li>no root</li>
              </ul>
            </div>
            <Transcript />
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <p className="home__kicker home__kicker--accent">01 · the cage</p>
            <h2 className="home__section-title">A secret is protected by being absent.</h2>
            <p className="home__aside home__aside--lead">
              sbx runs as your uid, and same-uid means read-only is not a boundary. The host
              filesystem and your credentials simply are not in the cage unless a{' '}
              <Link to="/docs/concepts/trust">trusted config</Link> grants them.
            </p>
            <div className="home__cage">
              <div className="home__cage-col">
                <p className="home__cage-head">Inside the cage</p>
                <ul className="home__list home__list--in">
                  {INSIDE.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div className="home__cage-col">
                <p className="home__cage-head">Absent by default</p>
                <ul className="home__list home__list--out">
                  {ABSENT.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        <section className="home__section">
          <div className="home__inner">
            <p className="home__kicker home__kicker--accent">02 · enforcement</p>
            <h2 className="home__section-title">Four layers, three of them always on.</h2>
            <p className="home__aside home__aside--lead">
              Every launch goes through them, and none is a toggle. They require
              capability-bearing unprivileged user namespaces: without them{' '}
              <Link to="/docs/cli/doctor">
                <code>sbx doctor</code>
              </Link>{' '}
              hard-fails, because there is no emulation fallback. The network posture is the
              one you choose: the host network by default, or a filtered egress the cage
              cannot step around.
            </p>
            <div className="home__grid home__grid--three">
              {LAYERS.map(({ n, tag, name, detail, to }) => {
                const body = (
                  <>
                    <p className="home__layer-n">
                      layer {n}
                      {tag && <span className="home__layer-tag">{tag}</span>}
                    </p>
                    <p className="home__card-name">{name}</p>
                    <p className="home__card-detail">{detail}</p>
                  </>
                );
                return (
                  <Link className="home__card home__card--layer" to={to!} key={n}>
                    {body}
                  </Link>
                );
              })}
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <p className="home__kicker home__kicker--accent">03 · app profiles</p>
            <h2 className="home__section-title">One profile per agent.</h2>
            <div className="home__profile">
              <div>
                <p className="home__aside home__aside--lead">
                  An <code>[app.&lt;name&gt;]</code> table, or a standalone profile file,
                  defines a reusable launcher with its own isolated <code>$HOME</code>,
                  package set, network allowlist and host-side credential injection.
                </p>
                <ul className="home__arrows">
                  <li>
                    Trust is bound to the file's content hash, the direnv model.
                  </li>
                  <li>
                    An untrusted <code>.sbx.toml</code> cannot touch security fields.
                  </li>
                  <li>
                    Import ready-made starters with <code>sbx app import</code>.
                  </li>
                </ul>
              </div>
              <div className="home__profile-code">
                <Tabs groupId="profile-form">
                  <TabItem value="project" label=".sbx.toml" default>
                    <CodeBlock language="toml">{PROFILE_SAMPLE}</CodeBlock>
                  </TabItem>
                  <TabItem value="profile" label="agent.profile.toml">
                    <CodeBlock language="toml">{PROFILE_FILE}</CodeBlock>
                  </TabItem>
                </Tabs>
              </div>
            </div>
          </div>
        </section>

        <section className="home__section home__section--deep">
          <div className="home__inner">
            <p className="home__kicker home__kicker--accent">04 · surface</p>
            <h2 className="home__section-title">The verbs you reach for.</h2>
            <p className="home__aside home__aside--lead">
              Eight of them carry most of the work. The{' '}
              <Link to="/docs/cli/">full reference</Link> covers the rest: networking,
              secrets, tasks, plugins, storage and housekeeping.
            </p>
            <div className="home__verbs">
              {VERBS.map(({ cmd, detail, to }) => (
                <Link className="home__verb" to={to} key={cmd}>
                  <code className="home__verb-cmd">{cmd}</code>
                  <span className="home__verb-detail">{detail}</span>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner home__is">
            <div className="home__is-card home__is-card--yes">
              <p className="home__kicker home__kicker--accent">sbx is</p>
              <h2 className="home__section-title home__section-title--sm">
                A sandbox launcher, built for untrusted autonomous agents.
              </h2>
              <p className="home__aside">
                Isolation under namespace boundaries, as the host user. The default posture
                is a locked-down agent, not an interactive shell.
              </p>
            </div>
            <div className="home__is-card">
              <p className="home__kicker">sbx is not</p>
              <h2 className="home__section-title home__section-title--sm">
                A container manager. An environment manager.
              </h2>
              <p className="home__aside">
                No OCI runtime, no image build, no shared host kernel tricks, and more than a
                tool that only sets environment variables.
              </p>
            </div>
          </div>
        </section>

        <section className="home__section home__closer">
          <div className="home__inner">
            <ThemedImage
              className="home__closer-mark"
              alt=""
              sources={{
                light: useBaseUrl('/assets/logo.svg'),
                dark: useBaseUrl('/assets/logo-dark.svg'),
              }}
            />
            <h2 className="home__closer-title">Give the agent a wall, not a promise.</h2>
            <p className="home__aside">
              Start with the preflight check, then cage your first command.
            </p>
            <div className="home__actions">
              <Link className="home__cta" to="/docs/">
                Read the docs
              </Link>
              <Link className="home__ghost" to="https://github.com/gigi206/ops-cli">
                GitHub ↗
              </Link>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
