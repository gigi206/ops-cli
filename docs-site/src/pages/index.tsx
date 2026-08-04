import React, { useEffect, useRef, useState, type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import ThemedImage from '@theme/ThemedImage';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

// Real `sbx` output, trimmed, with host-specific paths made generic. Quoted
// output must match the binary.
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

// What the hero's copy button hands over, and what it prints above it.
const COMMAND = ['sbx app import opencode.toml', 'sbx app run opencode'];

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
const LAYERS: { n: string; tag?: string; name: string; detail: string; to: string; delay: number }[] = [
  {
    n: '01',
    name: 'bubblewrap',
    detail: 'All namespaces, no_new_privs, capabilities dropped.',
    to: '/docs/concepts/enforcement',
    delay: 60,
  },
  {
    n: '02',
    name: 'seccomp',
    detail: 'A two-filter syscall denylist, applied unconditionally.',
    to: '/docs/configuration/seccomp',
    delay: 130,
  },
  {
    n: '03',
    name: 'cgroup v2',
    detail: 'Memory, pids and CPU limits, best-effort.',
    to: '/docs/configuration/limits',
    delay: 200,
  },
  {
    n: '04',
    tag: 'opt-in',
    name: 'egress proxy',
    detail:
      'Deny by default, then allow by host, port, path, method or regex. A host-side MITM proxy is the only way out of an empty netns.',
    to: '/docs/networking/',
    delay: 270,
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

/**
 * Parallax over the hero, and blocks that rise as they come into view.
 *
 * Purely additive: the server-rendered page is complete and visible, and this
 * only hides what is still below the fold, after confirming it can reveal it
 * again. A blocked script or reduced motion leaves the page whole, not blank.
 */
function useCinematic(): void {
  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let observer: IntersectionObserver | undefined;

    if (!reduced && 'IntersectionObserver' in window) {
      // A block's parts: its children when it staggers them, itself otherwise.
      // The observer watches one node per block and releases them together.
      const parts = new Map<Element, HTMLElement[]>();

      observer = new IntersectionObserver(
        (entries, self) => {
          for (const entry of entries) {
            if (!entry.isIntersecting) continue;
            parts.get(entry.target)?.forEach((part) => part.classList.remove('rv--out'));
            self.unobserve(entry.target);
          }
        },
        { rootMargin: '0px 0px -8% 0px' },
      );

      const fold = window.innerHeight * 0.9;
      document.querySelectorAll<HTMLElement>('[data-reveal]').forEach((block) => {
        const step = Number(block.dataset.stagger ?? '0');
        const delay = Number(block.dataset.delay ?? '0');
        const nodes = step > 0 ? (Array.from(block.children) as HTMLElement[]) : [block];

        nodes.forEach((node, i) => {
          node.classList.add('rv');
          // A custom property, not `transition-delay`: that would delay every
          // transitioned property, including the hover ones.
          const wait = delay + i * step;
          if (wait > 0) node.style.setProperty('--rv-delay', `${wait}ms`);
        });

        if (block.getBoundingClientRect().top < fold) return;
        nodes.forEach((node) => node.classList.add('rv--out'));
        parts.set(block, nodes);
        observer!.observe(block);
      });
    }

    const hero = document.querySelector<HTMLElement>('.home__hero');
    const bar = document.querySelector<HTMLElement>('.navbar');
    const media = document.getElementById('home-hero-media');
    const copy = document.getElementById('home-hero-copy');
    const cue = document.getElementById('home-hero-cue');

    // The bar is frosted while the hero is behind it, solid once past. The class
    // marks "scrolled past" rather than "over the hero" so the first paint, before
    // any script, is already correct. A state, not motion: it always runs.
    const barState = (): void => {
      if (!hero) return;
      const past = hero.getBoundingClientRect().bottom <= (bar?.offsetHeight ?? 0);
      document.body.classList.toggle('is-past-hero', past);
    };

    let frame = 0;
    const paint = (): void => {
      frame = 0;
      barState();

      // Below is parallax, which is motion and nothing else.
      if (reduced) return;
      const y = window.scrollY;

      if (media) {
        const scale = 1 + Math.min(y, 900) * 0.00018;
        media.style.transform = `translate3d(0, ${(y * 0.28).toFixed(1)}px, 0) scale(${scale.toFixed(4)})`;
      }
      if (copy) {
        copy.style.transform = `translate3d(0, ${(y * 0.14).toFixed(1)}px, 0)`;
        copy.style.opacity = String(1 - Math.min(y / 520, 1) * 0.92);
      }
      if (cue) cue.style.opacity = String(Math.max(0, 1 - y / 260));
    };

    const onScroll = (): void => {
      if (!frame) frame = requestAnimationFrame(paint);
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    paint();

    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (frame) cancelAnimationFrame(frame);
      observer?.disconnect();
      // Otherwise the next landing mount starts out believing the hero is past.
      document.body.classList.remove('is-past-hero');
    };
  }, []);
}

// Hero footage: "Castle, Mist, Forest" by HelpUkraine, 960x540 rendition.
//   source:  https://pixabay.com/videos/castle-mist-forest-nature-mountain-122406/
//   licence: https://pixabay.com/service/license-summary/ (Pixabay Content License)
// Self-hosted rather than loaded from the origin CDN, which keeps the page free
// of third-party requests. The poster is the first frame, as WebP.
const HERO_VIDEO = '/assets/hero-keep.mp4';
const HERO_POSTER = '/assets/hero-keep.webp';

/**
 * Attaches the hero video source, unless the browser reports that a 4.7 MB
 * decorative background is unwelcome: reduced motion, Save-Data, or one of the
 * two slowest connection tiers. The poster carries the hero in those cases.
 *
 * Setting the source here rather than in the markup is what makes the decision
 * possible at all: an `src` in the served HTML starts the download before any
 * preference can be read.
 *
 * Every read of `navigator.connection` is optional because Safari and Firefox do
 * not implement it, and absence must mean the full page. `effectiveType` is only
 * consulted for its bottom two tiers: it is an estimate from observed round
 * trips, and at first paint it commonly reports "3g" on a fast link, so a
 * stricter bound withholds the footage from ordinary visits.
 */
function useHeroVideo(src: string): React.RefObject<HTMLVideoElement | null> {
  const video = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const el = video.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const link = (
      navigator as Navigator & {
        connection?: { saveData?: boolean; effectiveType?: string };
      }
    ).connection;
    if (link?.saveData) return;
    if (link?.effectiveType === '2g' || link?.effectiveType === 'slow-2g') return;

    el.src = src;
  }, [src]);

  return video;
}

function Command(): ReactNode {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const id = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(id);
  }, [copied]);

  return (
    <div className="home__command">
      <code className="home__command-text">
        {COMMAND.map((line, i) => (
          <span key={line}>
            <span className="home__command-sigil">$</span> {line}
            {i < COMMAND.length - 1 ? '\n' : ''}
          </span>
        ))}
      </code>
      <button
        type="button"
        className="home__command-copy"
        aria-label="Copy both commands"
        onClick={() => {
          navigator.clipboard?.writeText(COMMAND.join('\n')).then(
            () => setCopied(true),
            () => undefined,
          );
        }}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  );
}

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
  const heroVideo = useHeroVideo(useBaseUrl(HERO_VIDEO));
  useCinematic();

  return (
    <Layout description={siteConfig.tagline}>
      <main className="home">
        <section className="home__hero">
          {/* The keep in the morning fog. Muted, looping, decorative: it carries
              no information the page needs, so it is aria-hidden, it drifts
              under the copy as the page scrolls, and CSS drops it entirely under
              prefers-reduced-motion. The hatch beneath it is what the hero shows
              before the footage decodes. */}
          <div className="home__hero-media" id="home-hero-media">
            <video
              className="home__hero-video"
              ref={heroVideo}
              poster={useBaseUrl(HERO_POSTER)}
              autoPlay
              muted
              loop
              playsInline
              aria-hidden="true"
              tabIndex={-1}
            />
          </div>
          <div className="home__hero-veil" />

          <div className="home__inner home__hero-copy" id="home-hero-copy">
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
              <Command />
            </div>
            <ul className="home__badges">
              <li>no OCI runtime</li>
              <li>no daemon</li>
              <li>no root</li>
            </ul>
          </div>

          <div className="home__scrollcue" id="home-hero-cue" aria-hidden="true">
            <span>scroll</span>
            <span className="home__scrollcue-line" />
          </div>
        </section>

        <section className="home__section">
          <div className="home__inner">
            <div className="home__preflight" data-reveal>
              <div>
                <p className="home__kicker home__kicker--accent">00 · preflight</p>
                <h2 className="home__section-title">
                  Check the ground before you build the wall.
                </h2>
                <p className="home__aside home__aside--lead">
                  sbx requires capability-bearing unprivileged user namespaces. Without them{' '}
                  <Link to="/docs/cli/doctor">
                    <code>sbx doctor</code>
                  </Link>{' '}
                  hard-fails, because there is no emulation fallback: emulation is not a
                  boundary.
                </p>
              </div>
              <Transcript />
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <div data-reveal>
              <p className="home__kicker home__kicker--accent">01 · the cage</p>
              <h2 className="home__section-title">A secret is protected by being absent.</h2>
              <p className="home__aside home__aside--lead">
                sbx runs as your uid, and same-uid means read-only is not a boundary. The host
                filesystem and your credentials simply are not in the cage unless a{' '}
                <Link to="/docs/concepts/trust">trusted config</Link> grants them.
              </p>
            </div>
            <div className="home__cage">
              <div className="home__cage-col" data-reveal data-delay="80">
                <p className="home__cage-head">Inside the cage</p>
                <ul className="home__list home__list--in" data-reveal data-stagger="55">
                  {INSIDE.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div className="home__cage-col" data-reveal data-delay="160">
                <p className="home__cage-head">Absent by default</p>
                <ul className="home__list home__list--out" data-reveal data-stagger="55">
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
            <div className="home__section-head" data-reveal>
              <div>
                <p className="home__kicker home__kicker--accent">02 · enforcement</p>
                <h2 className="home__section-title home__section-title--flush">
                  Four layers, three of them always on.
                </h2>
              </div>
              <p className="home__note">
                requires capability-bearing unprivileged userns · no emulation fallback
              </p>
            </div>
            <p className="home__aside home__aside--lead">
              Every launch goes through them, and none is a toggle. The network posture is the
              one you choose: the host network by default, or a filtered egress the cage cannot
              step around.
            </p>
            <div className="home__grid home__grid--three">
              {LAYERS.map(({ n, tag, name, detail, to, delay }) => (
                <Link
                  className="home__card home__card--layer"
                  to={to}
                  key={n}
                  data-reveal
                  data-delay={delay}
                >
                  <p className="home__layer-n">
                    layer {n}
                    {tag && <span className="home__layer-tag">{tag}</span>}
                  </p>
                  <p className="home__card-name">{name}</p>
                  <p className="home__card-detail">{detail}</p>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint">
          <div className="home__inner">
            <div className="home__profile">
              <div data-reveal>
                <p className="home__kicker home__kicker--accent">03 · app profiles</p>
                <h2 className="home__section-title">One profile per agent.</h2>
                <p className="home__aside home__aside--lead">
                  An <code>[app.&lt;name&gt;]</code> table, or a standalone profile file,
                  defines a reusable launcher with its own isolated <code>$HOME</code>,
                  package set, network allowlist and host-side credential injection.
                </p>
                <ul className="home__arrows" data-reveal data-stagger="70">
                  <li>Trust is bound to the file's content hash, the direnv model.</li>
                  <li>
                    An untrusted <code>.sbx.toml</code> cannot touch security fields.
                  </li>
                  <li>
                    Import ready-made starters with <code>sbx app import</code>.
                  </li>
                </ul>
              </div>
              <div className="home__profile-code" data-reveal data-delay="120">
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
            <div data-reveal>
              <p className="home__kicker home__kicker--accent">04 · surface</p>
              <h2 className="home__section-title">The verbs you reach for.</h2>
              <p className="home__aside home__aside--lead">
                Eight of them carry most of the work. The{' '}
                <Link to="/docs/cli/">full reference</Link> covers the rest: networking,
                secrets, tasks, plugins, storage and housekeeping.
              </p>
            </div>
            <div className="home__verbs" data-reveal data-stagger="45">
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
            <div className="home__is-card home__is-card--yes" data-reveal>
              <p className="home__kicker home__kicker--accent">sbx is</p>
              <h2 className="home__section-title home__section-title--sm">
                A sandbox launcher, built for untrusted autonomous agents.
              </h2>
              <p className="home__aside">
                Isolation under namespace boundaries, as the host user. The default posture
                is a locked-down agent, not an interactive shell.
              </p>
            </div>
            <div className="home__is-card" data-reveal data-delay="110">
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
          <div className="home__inner" data-reveal>
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
