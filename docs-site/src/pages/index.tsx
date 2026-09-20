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

// The numbered blocks, in page order: one rail dot each, and the id its dot
// links to. The rail is a plain list of in-page anchors, so it navigates with
// no script at all; what the script adds is only which dot is lit.
const RAIL: { id: string; label: string }[] = [
  { id: 'preflight', label: 'Preflight' },
  { id: 'trace', label: 'The trace' },
  { id: 'bind-layout', label: 'The bind layout' },
  { id: 'trust-gate', label: 'The trust gate' },
  { id: 'enforcement', label: 'Enforcement stack' },
  { id: 'provisioning', label: 'Provisioning' },
  { id: 'egress', label: 'Egress · Model B' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'tasks', label: 'Declared operations' },
  { id: 'apps', label: 'Apps and profiles' },
  { id: 'observability', label: 'Observability' },
  { id: 'desktop', label: 'The desktop hole' },
];

// ---------------------------------------------------------------------------
// The trace: one command, followed through the cage.
//
// Four outcomes over one path, because the system is legible through its
// refusals rather than its happy path. Every string a pane quotes is the
// binary's, on the rule the transcript above already follows:
//
//   - a refusal is quoted as `write_refusal` puts it on the wire — the status
//     line, the machine-readable `X-Sbx-Egress-Reason`, and `refusal_body`'s
//     prefixed sentence — carrying `Refusal::body`'s own `DeniedDefault` text,
//     down to the asymmetry between the backquoted `host:port` and the
//     suggestion beside it, which elides the default port (`rule_destination`);
//   - the trust warning is `config::gate::refuse_untrusted`, whose reason comes
//     from `untrusted_reason`;
//   - the feed lines carry `control::LogVerdict`'s own tokens (`allow`, `deny`)
//     and the proxy's reason (`no-rule`), in the column order `sbx logs` prints.
//
// The stages are sbx's real sequence, which spans a launch and the request that
// follows it: the trust gate decides before anything runs, and the proxy decides
// per request. A scenario names the stage that settled it, which is why the
// untrusted one is settled at `trust` while the other three are settled on the
// wire.
const TRACE_STAGES: { id: string; label: string }[] = [
  { id: 'trust', label: 'trust' },
  { id: 'provision', label: 'provision' },
  { id: 'bind', label: 'bind' },
  { id: 'spawn', label: 'spawn' },
  { id: 'request', label: 'request' },
  { id: 'inspect', label: 'inspect' },
  { id: 'verdict', label: 'verdict' },
  { id: 'observe', label: 'observe' },
];

type TraceVerdict = 'allow' | 'deny' | 'idle';

type TraceScenario = {
  id: string;
  tab: string;
  /** The stage that settled this outcome; the rail marks it. */
  decides: string;
  /** What the scenario demonstrates, in one sentence, above the panes. */
  lede: string;
  /** The left pane: what was asked, and what came back. */
  session: {
    /** Whose pane it is — an agent's session, or the launch itself. */
    label: string;
    ask: string;
    intent?: string;
    lines: { kind: 'cmd' | 'out' | 'resp' | 'refusal' | 'warn' | 'note'; text: string }[];
  };
  /** The middle pane: what decided, in the order it decided. */
  gates: { n: string; name: string; detail: string; verdict: TraceVerdict; to: string }[];
  /** The right pane: the cage, the proxy that answers for it, and upstream. */
  wire: { proxy: string; verdict: TraceVerdict; upstream: string; reached: boolean };
  /** The bottom strip: what the host-side feeds recorded. */
  feed: { at: string; feed: string; token: string; subject: string }[];
  /** What the person running sbx is told, when that differs from what the cage sees. */
  host?: string;
};

// The gates every scenario passes before the wire. Only their verdicts and the
// egress rule differ, so the three constant ones are written once.
const GATE_TRUST = { n: '01', name: 'trust', to: '/docs/concepts/trust' };
const GATE_BIND = { n: '02', name: 'bind layout', to: '/docs/concepts/security-model' };
const GATE_SECCOMP = { n: '03', name: 'seccomp', to: '/docs/configuration/seccomp' };
const GATE_EGRESS = { n: '04', name: 'egress rule', to: '/docs/networking/rules' };

const TRACES: TraceScenario[] = [
  {
    id: 'allowed',
    tab: 'allowed',
    decides: 'verdict',
    lede:
      'A rule names the host, so the request leaves through the one socket the cage has, and the proxy validates the upstream certificate against the system trust store.',
    session: {
      label: 'agent session',
      ask: 'List the models the API offers.',
      intent: 'I will call the Anthropic API.',
      lines: [
        { kind: 'cmd', text: 'curl -sI https://api.anthropic.com/v1/models' },
        { kind: 'resp', text: 'HTTP/2 200' },
      ],
    },
    gates: [
      { ...GATE_TRUST, detail: '.sbx.toml approved — its SHA-256 still matches', verdict: 'allow' },
      { ...GATE_BIND, detail: 'the project tree, the store, the egress socket', verdict: 'allow' },
      { ...GATE_SECCOMP, detail: 'two cBPF filters, default-allow', verdict: 'allow' },
      { ...GATE_EGRESS, detail: 'allow api.anthropic.com', verdict: 'allow' },
    ],
    wire: {
      proxy: 'CONNECT api.anthropic.com:443 · inspected',
      verdict: 'allow',
      upstream: 'api.anthropic.com',
      reached: true,
    },
    feed: [{ at: '12:04:29', feed: 'net', token: 'allow', subject: 'api.anthropic.com:443' }],
  },
  {
    id: 'secret',
    tab: 'secret brokered',
    decides: 'inspect',
    lede:
      'The credential is resolved host-side at launch and injected inside the proxy. The cage is handed a capability toward one host, never the secret — so there is nothing in it to exfiltrate.',
    session: {
      label: 'agent session',
      ask: 'Open an issue on the repository.',
      intent: 'I will need a GitHub token.',
      lines: [
        { kind: 'cmd', text: 'env | grep -i token' },
        { kind: 'note', text: 'nothing: the token was never bound in' },
        { kind: 'cmd', text: "curl -s -o /dev/null -w '%{http_code}' https://api.github.com/user" },
        { kind: 'out', text: '200' },
        { kind: 'note', text: 'Authorization was added host-side, inside the proxy' },
      ],
    },
    gates: [
      { ...GATE_TRUST, detail: '.sbx.toml approved — [secret] applies', verdict: 'allow' },
      { ...GATE_BIND, detail: 'declared secrets: absent from the cage in plaintext', verdict: 'allow' },
      { ...GATE_SECCOMP, detail: 'two cBPF filters, default-allow', verdict: 'allow' },
      { ...GATE_EGRESS, detail: 'allow api.github.com', verdict: 'allow' },
    ],
    wire: {
      proxy: 'broker injects `Authorization` · bearer',
      verdict: 'allow',
      upstream: 'api.github.com',
      reached: true,
    },
    feed: [{ at: '12:06:02', feed: 'net', token: 'allow', subject: 'api.github.com:443' }],
    host: 'The plaintext lives in sbx’s own memory for the length of the request, and in no file the cage can name.',
  },
  {
    id: 'denied',
    tab: 'egress denied',
    decides: 'verdict',
    lede:
      'No rule names the host. The proxy answers the cage with a 403 whose body carries the command that would allow it — and raises a host-side notification, because an agent is under no obligation to surface a refusal.',
    session: {
      label: 'agent session',
      ask: 'Post the results to our metrics endpoint.',
      intent: 'I will call api.example.com.',
      lines: [
        { kind: 'cmd', text: 'curl -s https://api.example.com' },
        { kind: 'resp', text: 'HTTP/1.1 403 Forbidden' },
        { kind: 'resp', text: 'X-Sbx-Egress-Reason: denied-default' },
        {
          kind: 'refusal',
          text:
            'sbx egress refused this request: `api.example.com:443` is not allowed by the network policy. Allow it: sbx net allow api.example.com',
        },
      ],
    },
    gates: [
      { ...GATE_TRUST, detail: '.sbx.toml approved — its SHA-256 still matches', verdict: 'allow' },
      { ...GATE_BIND, detail: 'the project tree, the store, the egress socket', verdict: 'allow' },
      { ...GATE_SECCOMP, detail: 'two cBPF filters, default-allow', verdict: 'allow' },
      { ...GATE_EGRESS, detail: 'no rule names api.example.com', verdict: 'deny' },
    ],
    wire: {
      proxy: 'CONNECT api.example.com:443 · denied-default',
      verdict: 'deny',
      upstream: 'api.example.com',
      reached: false,
    },
    feed: [
      { at: '12:04:31', feed: 'proc', token: 'observe', subject: 'curl -s https://api.example.com' },
      { at: '12:04:31', feed: 'net', token: 'deny', subject: 'api.example.com:443  (no-rule)' },
    ],
    host: 'sbx notifies you separately: a boundary nobody hears about is one that looks like it never bit.',
  },
  {
    id: 'untrusted',
    tab: 'untrusted .sbx.toml',
    decides: 'trust',
    lede:
      'The project declared a network posture. Approval is bound to the file’s content hash, so an unapproved file keeps its free fields and loses every security one: the launch goes ahead, without what the file asked for.',
    session: {
      label: 'your shell',
      ask: 'The project ships a .sbx.toml declaring `network`.',
      lines: [
        { kind: 'cmd', text: 'sbx run -- curl -s https://api.example.com' },
        {
          kind: 'warn',
          text: '.sbx.toml: ignoring `network` policy (untrusted — run `sbx trust`)',
        },
        { kind: 'resp', text: 'HTTP/1.1 403 Forbidden' },
        {
          kind: 'refusal',
          text:
            'sbx egress refused this request: `api.example.com:443` is not allowed by the network policy. Allow it: sbx net allow api.example.com',
        },
        { kind: 'note', text: 'the policy the project declared never applied' },
      ],
    },
    gates: [
      {
        ...GATE_TRUST,
        detail: 'untrusted: every security field dropped, with a warning',
        verdict: 'deny',
      },
      { ...GATE_BIND, detail: 'the default layout — no trusted [binds] applied', verdict: 'idle' },
      { ...GATE_SECCOMP, detail: 'always on: trust changes nothing here', verdict: 'allow' },
      {
        ...GATE_EGRESS,
        detail: 'the built-in self-equip set, not the declared policy',
        verdict: 'deny',
      },
    ],
    wire: {
      proxy: 'CONNECT api.example.com:443 · denied-default',
      verdict: 'deny',
      upstream: 'api.example.com',
      reached: false,
    },
    feed: [
      { at: '09:12:07', feed: 'net', token: 'deny', subject: 'api.example.com:443  (no-rule)' },
    ],
    host: 'sbx trust binds approval to the file’s SHA-256. Edit the file and trust is re-armed, on the direnv model.',
  },
];

// The bind zones of concepts/security-model, as the cage sees them. The egress
// socket is on the "in" side because it is exactly one bind: a Unix socket in the
// cage's tmpfs, which an in-cage socat fronts on loopback.
const INSIDE = [
  'the project tree',
  '/nix, the per-project store',
  'an isolated $HOME, per app',
  'a minimal, hostless /dev',
  'trusted [binds] paths',
  'the egress socket',
];

const ABSENT = [
  'the rest of the host filesystem',
  '~/.ssh, ~/.aws, ~/.config',
  'your real $HOME',
  'every capability (cap-drop ALL)',
  'host device nodes',
  'declared secrets, in plaintext',
];

// The split of concepts/trust, in the two panels the gate actually has. `[fs]`
// is neither free nor gated: it is the one *closing* table, so it keeps its own
// group inside the ungated panel rather than being filed as a free field.
const FIELD_PANELS: {
  head: string;
  gated?: boolean;
  groups: { label: string; note: string; fields: string[] }[];
}[] = [
  {
    head: 'Applied from any project',
    groups: [
      {
        label: 'Free',
        note: 'Setting one can only harm the cage that set it.',
        fields: ['env', 'timezone'],
      },
      {
        label: 'Closing, outside the gate',
        note: 'Every entry subtracts; there is no syntax that grants.',
        fields: ['[fs]'],
      },
    ],
  },
  {
    head: 'Security fields: trusted only',
    gated: true,
    groups: [
      {
        label: 'Dropped from an untrusted project, with a warning',
        note: 'Two of them are global-only: no project may declare them.',
        fields: [
          'binds',
          'network',
          'secret',
          'packages',
          'nixpkgs',
          'forward',
          'gui',
          'gpu',
          'audio',
          'dbus',
          '[proc]',
          '[limits]',
          '[seccomp]',
          '[devices]',
          '[ssh_agent]',
          '[notify]',
          '[task.<name>]',
          '[app.<name>]',
          '[network.groups]',
          '[bundle.<name>]',
        ],
      },
    ],
  },
];

// The stack of concepts/enforcement: three always-on layers, plus the opt-in exec
// veto its own diagram numbers fourth. The egress proxy is not a layer here: it is
// a posture, and it has a block of its own below. Landlock is not one either: its
// union semantics cannot carve a closed path out of a readable project without
// making everything the agent later creates at the project root unreadable too.
// `[fs]` is not a fifth: it is mount work, so it belongs to layer 01, and listing
// it beside the seccomp filter would promise a boundary it does not provide.
const LAYERS: {
  n: string;
  tag?: string;
  name: string;
  note?: string;
  chips: string[];
  to: string;
}[] = [
  {
    n: '01',
    name: 'bubblewrap',
    chips: [
      'all namespaces',
      'no_new_privs',
      '--cap-drop ALL',
      '--die-with-parent',
      '--clearenv',
      '--new-session',
    ],
    to: '/docs/concepts/enforcement',
  },
  {
    n: '02',
    name: 'seccomp',
    note: 'two cBPF filters, default-allow',
    chips: [
      'ptrace · process_vm_readv · process_vm_writev',
      'mount · unshare · setns · pivot_root · chroot',
      'init_module',
      'bpf · perf_event_open',
      'io_uring',
      'keyctl · add_key · request_key',
      'userfaultfd',
      'clone(CLONE_NEWUSER | CLONE_NEWNS)',
      'ioctl(TIOCSTI) · ioctl(TIOCLINUX)',
      'clone3 → ENOSYS',
    ],
    to: '/docs/configuration/seccomp',
  },
  {
    n: '03',
    name: 'cgroup v2',
    note: 'best-effort, never the boundary',
    chips: ['MemoryHigh=80%', 'MemoryMax=90%', 'TasksMax=16384', 'no CPUQuota, by design'],
    to: '/docs/configuration/limits',
  },
  {
    n: '04',
    tag: 'opt-in',
    name: 'exec veto',
    note: 'trusted-only',
    chips: ['[proc] mode = "enforce"', '[proc] mode = "ask"'],
    to: '/docs/configuration/proc',
  },
];

const VERBS = [
  { cmd: 'sbx doctor', detail: 'Verify the host can build the cage.', to: '/docs/cli/doctor' },
  { cmd: 'sbx trust', detail: "Bind trust to the file's content hash.", to: '/docs/cli/trust' },
  { cmd: 'sbx config show', detail: 'Resolved config, with its trust state.', to: '/docs/cli/config' },
  { cmd: 'sbx run -- <cmd>', detail: 'Run a command, or an interactive shell.', to: '/docs/cli/run' },
  { cmd: 'sbx app run <name>', detail: 'Launch a named agent profile.', to: '/docs/cli/app' },
  { cmd: 'sbx task run <op>', detail: 'Invoke a declared operation.', to: '/docs/cli/task' },
  { cmd: 'sbx search', detail: "Find packages for the project's store.", to: '/docs/cli/search' },
  { cmd: 'sbx upgrade', detail: 'Roll a channel, an engine or a pinned family.', to: '/docs/cli/upgrade' },
];

// The other half of block 10: what a session leaves behind, and what reclaims it.
const HOUSEKEEPING: { cmd: string; detail: string; to: string }[] = [
  { cmd: 'sbx session ls · attach · stop', detail: 'the live cages', to: '/docs/cli/session' },
  { cmd: 'sbx run --detach --observe', detail: 'run it in the background, watched', to: '/docs/cli/run' },
  { cmd: 'sbx logs <id> -f', detail: 'seven feeds in one column of time', to: '/docs/cli/logs' },
  { cmd: 'sbx gc', detail: 'reclaim per-project store space', to: '/docs/cli/gc' },
  { cmd: 'sbx storage', detail: 'a compressed, self-growing volume', to: '/docs/cli/storage' },
  { cmd: 'sbx store', detail: 'what sbx occupies on disk', to: '/docs/cli/store' },
  { cmd: 'sbx projects', detail: 'the per-project runtime trees', to: '/docs/cli/projects' },
  { cmd: 'sbx path', detail: 'where config, data and state live', to: '/docs/cli/path' },
];

// What a profile carries that a bare `sbx run` does not.
const APP_PROPS: { term: string; detail: string }[] = [
  {
    term: 'An isolated $HOME',
    detail:
      "A dedicated, persistent identity per app: its config, login state and history never bleed into your project shell or another app. home_scope decides whether that home is per-project too.",
  },
  {
    term: 'Its own posture',
    detail:
      'Package set, network allowlist, limits, declared operations and host-side credential injection, all scoped to the profile.',
  },
  {
    term: 'Portable',
    detail:
      'A standalone file under ~/.config/sbx/apps/<name>.toml, trusted by location because you put it there, moved between machines with sbx app import.',
  },
  {
    term: 'Bundles',
    detail:
      'Reusable tool sets an app names with use, declared once where you own them, so profiles stay short.',
  },
];

const LENSES: { lens: string; question: string; reader: string; to: string }[] = [
  { lens: 'exec', question: 'What did it run?', reader: 'sbx proc logs · ls', to: '/docs/cli/proc' },
  { lens: 'filesystem', question: 'What did it write?', reader: 'sbx fs logs', to: '/docs/cli/fs' },
  { lens: 'egress', question: 'Where did it go?', reader: 'sbx net logs · live', to: '/docs/cli/net' },
  {
    lens: 'ssh-agent',
    question: 'What did it ask your keys to sign?',
    reader: 'sbx ssh-agent logs',
    to: '/docs/cli/ssh-agent',
  },
];

const FEEDS = ['proc', 'net', 'fs', 'ssh', 'signer', 'broker', 'task'];

// `sbx logs`, trimmed to the feeds this session actually records: the four lines
// that say which feeds are absent from that config are dropped, the rest is the
// reference page's own sample, verbatim. Quoted output must match the binary.
const FEED_HEAD = [
  'feeds \u2014 session 4019373 [demo-app] ~/dev/demo-app',
  '  recording: proc, net, fs',
];

const FEED_LINES: { at: string; feed: string; token: string; subject: string }[] = [
  { at: '12:04:31', feed: 'proc', token: 'observe', subject: 'curl -s https://api.example.com' },
  { at: '12:04:31', feed: 'net', token: 'deny', subject: 'api.example.com:443  (no-rule)' },
  { at: '12:04:32', feed: 'fs', token: 'write', subject: './retry.sh' },
  { at: '12:04:33', feed: 'proc', token: 'observe', subject: 'sh ./retry.sh' },
];

// The desktop holes, each opened one field at a time and every one of them
// trusted-only: each widens what the cage can see or reach.
const DESKTOP: { term: string; detail: string }[] = [
  {
    term: 'gui',
    detail:
      'The display posture: none, offscreen, or the host Wayland socket bound read-only. X11 is never offered, because an X client can snoop on and drive every other window on the display.',
  },
  {
    term: 'gpu',
    detail:
      'Hardware-accelerated rendering through mesa, covering Intel, AMD and nouveau. The NVIDIA proprietary stack cannot be provisioned hermetically and is not this hole.',
  },
  {
    term: 'audio',
    detail:
      'Microphone and playback, which a hermetic cage otherwise has no socket and no client library for.',
  },
  {
    term: 'dbus',
    detail:
      'A private in-cage portal: file chooser, appearance, notifications. Never the host session bus, which carries the login keyring and every saved password.',
  },
  {
    term: '[open]',
    detail:
      'Which in-cage program handles a URI, by scheme, so a sign-in page opens behind the same egress allowlist and its callback returns to the caged application.',
  },
];

const PROFILE_SAMPLE = `[network]
mode  = "deny"
allow = ["api.anthropic.com", "crates.io"]

[app.agent]
cmd     = "opencode"
network = { mode = "deny", allow = ["api.anthropic.com"] }

[secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
header = "x-api-key"
type   = "raw"`;

// The portable form: the same fields, at the top level, the filename being the
// app name. Documented in configuration/apps.md.
const PROFILE_FILE = `cmd     = "opencode"
network = { mode = "deny", allow = ["api.anthropic.com"] }

[secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
header = "x-api-key"
type   = "raw"`;

// One example per host-side shape, as the design lists them. The count, and the
// four backends not shown here, are in the prose and on the packages page.
const BACKENDS = ['nix:ripgrep', 'mise:node@22', 'flake:github:owner/repo#tool'];

const PACKAGES_SAMPLE = `[packages]
jq       = "nix:jq"
ripgrep  = "mise:aqua:BurntSushi/ripgrep"
myagent  = "flake:github:owner/repo#default"`;

const MODES: { mode: string; tag?: string; reach: string; proxy: string; use: string }[] = [
  {
    mode: 'none',
    reach: 'nothing: an empty network namespace',
    proxy: 'no',
    use: 'fully offline work',
  },
  {
    mode: 'shared',
    reach: 'the whole host network, unfiltered',
    proxy: 'no',
    use: 'trusted interactive work',
  },
  {
    mode: 'deny',
    tag: 'default',
    reach: 'the hosts you allow, plus the built-in self-equip set',
    proxy: 'yes',
    use: 'a provider and the nix cache, nothing else',
  },
  {
    mode: 'allow',
    reach: 'every public host except the ones you deny',
    proxy: 'yes',
    use: 'broad access, a few carve-outs',
  },
  {
    mode: 'ask',
    reach: 'anything unlisted parks for your live decision',
    proxy: 'yes',
    use: 'discovering what an agent needs',
  },
];

// The three transport planes of networking/rules. Two of them are opt-in because
// each gives up something the default keeps: TLS, or inspection altogether.
const PLANES: { tag: string; spell: string; name: string; detail: string }[] = [
  {
    tag: 'the default',
    spell: 'host · https://',
    name: 'Inspected over TLS',
    detail:
      'TLS is terminated under a per-session, cage-only CA, and the rule decides on host, port, path, method and regex, with redaction and anti-fronting. Port 443.',
  },
  {
    tag: 'opt-in',
    spell: 'http://',
    name: 'Cleartext',
    detail:
      'The same HTTP policy on a plaintext connection, port 80, for a host that offers no TLS. Strictly opt-in, and no credential is ever injected onto it.',
  },
  {
    tag: 'opt-in',
    spell: 'tcp://',
    name: 'Raw splice',
    detail:
      'Bytes copied verbatim for ssh or a database wire: host:port and the SSRF guard, nothing else. Each declared port gets an in-cage listener, and one below 1024 gets a generated ProxyCommand instead.',
  },
];

const GRAMMAR = [
  'api.example.com',
  '*.domain',
  '1.2.3.4 · [2001:db8::1]',
  'host/path · host/path/*',
  're:^https://…',
  ':80,8000-8100 · :*',
  '{GET,HEAD} · {*}',
  'tcp://host:5432',
  '@group',
];

// Guards that sit under the rule set: no allow widens them, and a regex never
// satisfies the one that asks to be named.
const GUARDS: { term: string; detail: string }[] = [
  {
    term: 'SSRF',
    detail:
      'A private, loopback or metadata address is refused unless the deciding rule names that exact host. A regex never does.',
  },
  {
    term: 'Anti-fronting',
    detail: 'A CONNECT authority, an SNI and a decrypted Host that disagree are blocked.',
  },
  { term: 'Outbound secret', detail: 'A request carrying a configured value is refused with a 403.' },
  {
    term: 'Framing',
    detail: 'A malformed or smuggling request is refused before any rule is consulted.',
  },
  {
    term: 'DNS',
    detail: 'Resolved host-side, so the cage never sees a name to exfiltrate through.',
  },
];

const NET_SURFACES = [
  {
    cmd: 'sbx net rules',
    detail: 'The effective policy, each rule tagged config or built-in. --expand unfolds a group.',
    to: '/docs/cli/net',
  },
  {
    cmd: 'sbx test net',
    detail: 'A what-if through the matcher the proxy uses, and the rule that decides it.',
    to: '/docs/cli/test',
  },
  {
    cmd: 'sbx net stats',
    detail: 'Per-host counters that outlive the session: allowed, denied, blocked.',
    to: '/docs/cli/net',
  },
  {
    cmd: 'sbx net logs',
    detail: "Every decision, live, in the session's memory and never on disk.",
    to: '/docs/cli/net',
  },
  {
    cmd: 'sbx net live',
    detail: 'A top for the open tunnels: host, transport, age, bytes each way.',
    to: '/docs/cli/net',
  },
];

// resolver (SOURCE) x broker (SINK), and what the cage is left holding.
const SECRET_STEPS: { n: string; head: string; detail: string; now?: boolean }[] = [
  {
    n: '01',
    head: 'resolver: the source',
    detail: 'env://, file://, sops://, or a plugin scheme. Read host-side, at launch.',
  },
  {
    n: '02',
    head: 'broker: the sink',
    detail: "Header injection inside the egress proxy. The plaintext lives in sbx's memory only.",
    now: true,
  },
  {
    n: '03',
    head: 'the cage',
    detail: 'curl and git get a capability toward one host, never the credential.',
  },
];

const SECRET_SAMPLE = `[secret."api.github.com"]
from   = "sops://secrets.enc.yaml#gh.token"
header = "Authorization"
type   = "bearer"`;

// Straight out of configuration/task: the field reference's own example. The
// bound is elided rather than rewritten, so the pane does not scroll; the whole
// pattern is on the page that owns it.
const TASK_SAMPLE = `description = "Read-only SQL against staging"
cmd     = ["psql", "-h", "db.staging.internal", "-c", "{sql}"]
params  = { sql = "^SELECT \u2026$" }
network = ["tcp://db.staging.internal:5432"]

[task.db-query.secret]
PGPASSWORD = "sops://secrets.enc.yaml#db.password"`;

// What the caller types, and what it cost them, closing the same pane.
const TASK_RUN = 'sbx task run db-query --param sql="SELECT id FROM users"';
const TASK_RUN_OUT = 'ran in a sibling cage \u00b7 PGPASSWORD never entered yours';

const TASK_BOUNDS = [
  'An argv list, never a shell string, so nothing the caller sends reaches a shell.',
  'Its own ephemeral cage: /nix read-only, the project read-only, a tmpfs $HOME, its own pid namespace, no stdin, no tty.',
  'Every caller-supplied value carries a bound, and the bound must match the whole value.',
  'A fixed quota of 500 invocations per session, refused past that rather than degraded.',
  "What crosses into the agent's cage is a generated client with three verbs, not sbx.",
];

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
    const progress = document.getElementById('home-progress');
    const dots = Array.from(document.querySelectorAll<HTMLElement>('.home__rail-dot'));
    const blocks = dots.map((dot) => document.getElementById(dot.dataset.block ?? ''));

    // The bar is frosted while the hero is behind it, solid once past. The class
    // marks "scrolled past" rather than "over the hero" so the first paint, before
    // any script, is already correct. A state, not motion: it always runs.
    const barState = (): void => {
      if (!hero) return;
      const past = hero.getBoundingClientRect().bottom <= (bar?.offsetHeight ?? 0);
      document.body.classList.toggle('is-past-hero', past);
    };

    // How far down a page this long the reader has come. A state, like the bar
    // above it, so it runs under reduced motion too: it reports a position, it
    // does not animate one. Server-rendered at zero width, so a page with no
    // script shows nothing rather than a bar stuck at the start.
    const progressState = (): void => {
      if (!progress) return;
      const travel = document.documentElement.scrollHeight - window.innerHeight;
      const done = travel > 0 ? Math.min(window.scrollY / travel, 1) : 0;
      progress.style.width = `${(done * 100).toFixed(2)}%`;
    };

    // Which block the reader is in, by the same rule the rail's dots imply: the
    // last one that has crossed the middle of the window without having left
    // it. Lighting a dot is a state, so it runs under reduced motion; only the
    // easing on the dot itself is motion, and CSS drops that.
    const railState = (): void => {
      if (!dots.length) return;
      const vh = window.innerHeight;
      let active = -1;
      blocks.forEach((block, i) => {
        if (!block) return;
        const box = block.getBoundingClientRect();
        if (box.top < vh * 0.5 && box.bottom > vh * 0.35) active = i;
      });
      dots.forEach((dot, i) => {
        dot.classList.toggle('home__rail-dot--on', i === active);
        // The lit dot is where the reader is, which is what `current` means.
        if (i === active) dot.setAttribute('aria-current', 'true');
        else dot.removeAttribute('aria-current');
      });
    };

    let frame = 0;
    const paint = (): void => {
      frame = 0;
      barState();
      progressState();
      railState();

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

/**
 * A block's number and its one-line label.
 *
 * The numeral is decorative: it repeats the reading order the sections already
 * carry, so it is hidden from assistive technology rather than read out as a
 * bare "01" before every heading.
 */
function Ordinal({ n, label }: { n: string; label: string }): ReactNode {
  return (
    <>
      <p className="home__ordinal" aria-hidden="true">
        {n}
      </p>
      <p className="home__kicker home__kicker--accent">{label}</p>
    </>
  );
}

/**
 * The guide pages a block was written from, each one a link.
 *
 * A block's prose links only what it names in a sentence; this line is where
 * the rest of its sources stay reachable, so a reader who wants the whole
 * chapter does not have to hunt for the one word that happened to be a link.
 */
function Source({ pages }: { pages: { path: string; to: string }[] }): ReactNode {
  return (
    <p className="home__source">
      {pages.map(({ path, to }, i) => (
        <React.Fragment key={to}>
          {i > 0 && <span className="home__source-sep"> · </span>}
          <Link to={to}>{path}</Link>
        </React.Fragment>
      ))}
    </p>
  );
}

/**
 * A code sample dressed as a pane, the way the design draws one: a label bar
 * naming the file or the table the sample belongs to, then the code.
 *
 * The transcript below has a bar of its own, with the three dots, because it is
 * a session rather than a file.
 */
function Pane({ label, children }: { label: string; children: ReactNode }): ReactNode {
  return (
    <div className="home__pane">
      <p className="home__pane-bar">{label}</p>
      {children}
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

/**
 * The trace: four outcomes over one path.
 *
 * A tablist, on the WAI-ARIA pattern: arrows move between the scenarios and the
 * panel below is what changes. Only one panel is mounted at a time, so what the
 * reader has is what the page is showing — there is no hidden copy of the other
 * three for a find-in-page to land in.
 *
 * Every visual state is a class the markup carries, never a measurement, so the
 * block renders identically on the server and needs no effect to settle. The
 * transition between scenarios is a CSS animation on the panel, which
 * `prefers-reduced-motion` drops entirely in the stylesheet.
 */
function Trace(): ReactNode {
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const trace = TRACES[active];

  // Arrows, Home and End move the selection, as the tablist pattern requires;
  // the browser's own Tab still leaves the list for the panel.
  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>): void => {
    const last = TRACES.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? (active + 1) % TRACES.length
        : event.key === 'ArrowLeft'
          ? (active + last) % TRACES.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : -1;
    if (next < 0) return;
    event.preventDefault();
    setActive(next);
    tabs.current[next]?.focus();
  };

  return (
    <div className="trace">
      <div className="trace__tabs" role="tablist" aria-label="What the cage did" onKeyDown={onKeyDown}>
        {TRACES.map(({ id, tab }, i) => (
          <button
            type="button"
            key={id}
            role="tab"
            id={`trace-tab-${id}`}
            aria-selected={i === active}
            /* Only the selected panel is mounted, so only the selected tab may
               claim to control one: an `aria-controls` pointing at an absent id
               is a dangling reference the other three would each carry. */
            aria-controls={i === active ? `trace-panel-${id}` : undefined}
            tabIndex={i === active ? 0 : -1}
            ref={(node) => {
              tabs.current[i] = node;
            }}
            className={
              i === active ? 'trace__tab trace__tab--on' : 'trace__tab'
            }
            onClick={() => setActive(i)}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* The stages, with the one that settled this scenario marked. It is a
          list rather than a row of divs because that is what it is: eight
          ordered steps, one of them called out. */}
      <ol className="trace__rail" aria-label="Stages, and where this outcome was settled">
        {TRACE_STAGES.map(({ id, label }) => {
          const decides = id === trace.decides;
          return (
            <li
              className={decides ? 'trace__stage trace__stage--decides' : 'trace__stage'}
              key={id}
            >
              {label}
              {decides && <span className="trace__stage-note"> (settled here)</span>}
            </li>
          );
        })}
      </ol>

      <div
        className="trace__panel"
        role="tabpanel"
        id={`trace-panel-${trace.id}`}
        aria-labelledby={`trace-tab-${trace.id}`}
        /* Keyed on the scenario so React remounts the panel: the entry
           animation should replay on every change, which it would not if the
           nodes were reused. */
        key={trace.id}
        tabIndex={0}
      >
        <p className="trace__lede">{trace.lede}</p>

        <div className="trace__cols">
          {/* Left: what was asked, and what came back. */}
          <div className="trace__col trace__col--session">
            <p className="trace__col-bar">{trace.session.label}</p>
            <div className="trace__session">
              <p className="trace__ask">{trace.session.ask}</p>
              {trace.session.intent && (
                <p className="trace__intent">{trace.session.intent}</p>
              )}
              <pre className="trace__lines">
                {trace.session.lines.map(({ kind, text }, i) => (
                  <span className={`trace__line trace__line--${kind}`} key={i}>
                    {kind === 'cmd' && <span className="trace__sigil">$ </span>}
                    {kind === 'resp' && <span className="trace__wire-sigil">← </span>}
                    {text}
                    {'\n'}
                  </span>
                ))}
              </pre>
            </div>
          </div>

          {/* Middle: what decided, in the order it decided. */}
          <div className="trace__col trace__col--gates">
            <p className="trace__col-bar">sbx · what decides</p>
            <ol className="trace__gates">
              {trace.gates.map(({ n, name, detail, verdict, to }) => (
                <li className={`trace__gate trace__gate--${verdict}`} key={n}>
                  <Link className="trace__gate-head" to={to}>
                    <span className="trace__gate-n">{n}</span>
                    {name}
                  </Link>
                  <p className="trace__gate-detail">{detail}</p>
                </li>
              ))}
            </ol>
          </div>

          {/* Right: the cage, the proxy that answers for it, and upstream. */}
          <div className="trace__col trace__col--wire">
            <p className="trace__col-bar">the cage, and the one way out</p>
            <div className="trace__wire">
              <div className="trace__cage">
                <p className="trace__cage-head">bubblewrap · uid = yours</p>
                <p className="trace__cage-detail">
                  empty netns · no route, no resolver · one bound Unix socket
                </p>
              </div>
              <p className="trace__hop" aria-hidden="true">
                ↓
              </p>
              <div className={`trace__proxy trace__proxy--${trace.wire.verdict}`}>
                <p className="trace__proxy-head">sbx CONNECT proxy · host-side</p>
                <p className="trace__proxy-detail">{trace.wire.proxy}</p>
              </div>
              <p className="trace__hop" aria-hidden="true">
                {trace.wire.reached ? '↓' : '✕'}
              </p>
              <div
                className={
                  trace.wire.reached
                    ? 'trace__upstream'
                    : 'trace__upstream trace__upstream--unreached'
                }
              >
                <p className="trace__upstream-head">{trace.wire.upstream}</p>
                <p className="trace__upstream-detail">
                  {trace.wire.reached
                    ? 'certificate validated against the system trust store'
                    : 'never contacted: the refusal is local to the proxy'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom: what the host-side feeds recorded, and what you were told. */}
        <div className="trace__record">
          <pre className="trace__feed">
            {trace.feed.map(({ at, feed, token, subject }) => (
              <span key={`${at}${feed}${subject}`}>
                <span className="home__feed-at">{at}</span>
                {'  '}
                <span className="home__feed-name">{feed.padEnd(5)}</span>
                <span className="home__feed-token">{token.padEnd(8)}</span>
                {subject}
                {'\n'}
              </span>
            ))}
          </pre>
          {trace.host && <p className="trace__host">{trace.host}</p>}
        </div>
      </div>
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
        <div className="home__progress" aria-hidden="true">
          <div className="home__progress-fill" id="home-progress" />
        </div>

        {/* One dot per numbered block, in the page's gutter. Plain anchors, so
            it navigates with no script; the script only lights the dot the
            reader is standing on. Hidden where the gutter is too narrow to hold
            it without landing on the copy. */}
        <nav className="home__rail" aria-label="Sections of this page">
          {RAIL.map(({ id, label }) => (
            <a className="home__rail-dot" data-block={id} href={`#${id}`} key={id}>
              <span className="home__rail-core" />
              <span className="home__rail-label">{label}</span>
            </a>
          ))}
        </nav>

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

            <div className="home__scrollcue" id="home-hero-cue" aria-hidden="true">
              <span>scroll: the ten subsystems</span>
              <span className="home__scrollcue-line" />
            </div>
          </div>
        </section>

        <section className="home__section" id="preflight">
          <div className="home__inner">
            <div className="home__preflight" data-reveal>
              <div>
                <Ordinal n="00" label="preflight" />
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

        {/* The canonical pass over the whole path. It carries no ordinal: the
            numbered blocks below are the subsystems, and this is the map they
            are read against — each of its gates links into the block that owns
            it. */}
        <section className="home__section home__section--tint" id="trace">
          <div className="home__inner">
            <div className="home__section-head" data-reveal>
              <div>
                <p className="home__kicker home__kicker--accent">the trace</p>
                <h2 className="home__section-title home__section-title--flush">
                  One command, four ways it can end.
                </h2>
              </div>
              <p className="home__aside home__aside--side">
                The same path every time: a trust gate that decides before anything runs, a
                bind layout, an always-on filter, and a proxy that answers per request. What
                changes is where it is settled — and what the agent is handed back.
              </p>
            </div>

            <div data-reveal>
              <Trace />
            </div>

            <Source
              pages={[
                { path: 'concepts/security-model', to: '/docs/concepts/security-model' },
                { path: 'concepts/trust', to: '/docs/concepts/trust' },
                { path: 'networking/rules', to: '/docs/networking/rules' },
                { path: 'secrets/injection', to: '/docs/secrets/injection' },
              ]}
            />
          </div>
        </section>

        <section className="home__section" id="bind-layout">
          <div className="home__inner">
            <div className="home__split">
              <div className="home__split-aside" data-reveal>
                <Ordinal n="01" label="the primary control" />
                <h2 className="home__section-title">A secret is protected by being absent.</h2>
                <p className="home__aside home__aside--lead">
                  sbx runs as your uid, and same-uid means read-only is not a boundary. The
                  bind layout is what protects a secret: the host filesystem and your
                  credentials simply are not in the cage unless a{' '}
                  <Link to="/docs/concepts/trust">trusted config</Link> puts them there.
                </p>
                <p className="home__aside home__aside--lead">
                  The project itself is the exception: it is all there, key and{' '}
                  <code>.env</code> included, so{' '}
                  <Link to="/docs/configuration/fs">
                    <code>[fs] deny</code>
                  </Link>{' '}
                  closes the paths that have to stay where they are. The name still lists; the
                  contents do not open.
                </p>
                <Source
                  pages={[
                    { path: 'concepts/security-model', to: '/docs/concepts/security-model' },
                    { path: 'configuration/binds', to: '/docs/configuration/binds' },
                    { path: 'configuration/fs', to: '/docs/configuration/fs' },
                  ]}
                />
              </div>
              <div className="home__cage">
                <div className="home__cage-col" data-reveal data-delay="80">
                  <p className="home__cage-head">Bound into the cage</p>
                  <ul className="home__list home__list--in" data-reveal data-stagger="55">
                    {INSIDE.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
                <div className="home__cage-col" data-reveal data-delay="160">
                  <p className="home__cage-head">Absent by construction</p>
                  <ul className="home__list home__list--out" data-reveal data-stagger="55">
                    {ABSENT.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint" id="trust-gate">
          <div className="home__inner">
            <div className="home__section-head" data-reveal>
              <div>
                <Ordinal n="02" label="the direnv model" />
                <h2 className="home__section-title home__section-title--flush">
                  An untrusted project cannot touch the security fields.
                </h2>
              </div>
              <p className="home__aside home__aside--side">
                Approval is bound to the file's content hash and re-armed whenever the file
                changes, so a security field applies only while you have vouched for the exact
                bytes that declare it. <a href="#trace">The trace</a> follows what an
                unapproved file costs at launch; what this block carries is the field list the
                gate decides over.
              </p>
            </div>

            <div className="home__groups">
              {FIELD_PANELS.map(({ head, gated, groups }, i) => (
                <div
                  className={gated ? 'home__group home__group--gated' : 'home__group'}
                  key={head}
                  data-reveal
                  data-delay={i * 110}
                >
                  <p className="home__group-head">{head}</p>
                  {groups.map(({ label, note, fields }) => (
                    <div className="home__group-part" key={label}>
                      <p className="home__group-label">{label}</p>
                      <div className="home__chips" data-reveal data-stagger="45">
                        {fields.map((field) => (
                          <span
                            className={gated ? 'home__chip home__chip--gated' : 'home__chip'}
                            key={field}
                          >
                            {field}
                          </span>
                        ))}
                      </div>
                      <p className="home__group-note">{note}</p>
                    </div>
                  ))}
                </div>
              ))}
            </div>
            <Source
              pages={[
                { path: 'concepts/trust', to: '/docs/concepts/trust' },
                { path: 'cli/trust', to: '/docs/cli/trust' },
                { path: 'configuration/overrides', to: '/docs/configuration/overrides' },
              ]}
            />
          </div>
        </section>

        <section className="home__section" id="enforcement">
          <div className="home__inner">
            <div data-reveal>
              <Ordinal n="03" label="defense in depth" />
              <h2 className="home__section-title">
                Three layers on every launch. A fourth when you ask for it.
              </h2>
              <p className="home__aside home__aside--lead">
                None of them is a toggle, and none replaces the bind layout: they bound what a
                mistake in it can become. The fourth vetoes what the agent spawns, and is
                trusted-only because an untrusted project may not forge the enforcement of its
                own agent. <a href="#trace">The trace</a> shows the always-on three holding
                on every one of its four outcomes, the unapproved project included.
              </p>
            </div>
            <div className="home__layers" data-reveal data-stagger="120">
              {LAYERS.map(({ n, tag, name, note, chips, to }) => (
                <Link
                  className={tag ? 'home__layer home__layer--opt' : 'home__layer'}
                  to={to}
                  key={n}
                >
                  <div className="home__layer-head">
                    <p className="home__layer-n">
                      layer {n}
                      {tag && <span className="home__layer-tag">{tag}</span>}
                    </p>
                    <p className="home__card-name">{name}</p>
                    {note && <p className="home__layer-note">{note}</p>}
                  </div>
                  <div className="home__chips">
                    {chips.map((chip) => (
                      <span className="home__chip" key={chip}>
                        {chip}
                      </span>
                    ))}
                  </div>
                </Link>
              ))}
            </div>
            <p className="home__aside">
              The exec veto is a seccomp user-notification gate: a denied{' '}
              <code>execve</code> is blocked before the syscall runs, and an unmatched one can
              park for a live decision. A guardrail on what the agent spawns, not a
              replacement for the three above.
            </p>
          </div>
        </section>

        <section className="home__section home__section--tint" id="provisioning">
          <div className="home__inner">
            <div className="home__profile">
              <div data-reveal>
                <Ordinal n="04" label="provisioning" />
                <h2 className="home__section-title">
                  The agent equips itself, into its project's own store.
                </h2>
                <p className="home__aside home__aside--lead">
                  Single-user, daemonless Nix inside the cage, on a rolling channel whose
                  exact revision is pinned as data, into a store that belongs to the project,
                  leaving the host OS untouched. Seven backends, one field, and no bare form:
                  a value with no recognized prefix is dropped with a warning naming the fix.
                </p>
                <div className="home__chips" data-reveal data-stagger="45">
                  {BACKENDS.map((backend) => (
                    <span className="home__chip" key={backend}>
                      {backend}
                    </span>
                  ))}
                </div>
                <Source
                  pages={[
                    { path: 'concepts/provisioning', to: '/docs/concepts/provisioning' },
                    { path: 'configuration/packages', to: '/docs/configuration/packages' },
                  ]}
                />
              </div>
              <div className="home__profile-code" data-reveal data-delay="120">
                <Pane label=".sbx.toml">
                  <CodeBlock language="toml">{PACKAGES_SAMPLE}</CodeBlock>
                </Pane>
              </div>
            </div>
          </div>
        </section>

        <section className="home__section" id="egress">
          <div className="home__inner">
            <div className="home__section-head" data-reveal>
              <div>
                <Ordinal n="05" label="egress · model b" />
                <h2 className="home__section-title home__section-title--flush">
                  An empty network namespace, and one socket out.
                </h2>
              </div>
              <p className="home__aside home__aside--side">
                No interface but loopback, no route, no DNS resolver. Nothing leaves by
                construction, so a misconfiguration fails closed rather than open.{' '}
                <a href="#trace">The trace</a> walks one request down that path; what
                follows is the policy surface it is decided against.
              </p>
            </div>

            <p className="home__subhead" data-reveal>
              Five postures, and what each one lets through
            </p>
            <div className="home__tablewrap" data-reveal>
              <table className="home__table">
                <thead>
                  <tr>
                    <th>mode</th>
                    <th>what reaches the cage</th>
                    <th>proxy</th>
                    <th>typical use</th>
                  </tr>
                </thead>
                <tbody>
                  {MODES.map(({ mode, tag, reach, proxy, use }) => (
                    <tr key={mode} className={tag ? 'home__table-row--now' : undefined}>
                      <td>
                        <code>{mode}</code>
                        {tag && <span className="home__layer-tag">{tag}</span>}
                      </td>
                      <td>{reach}</td>
                      <td>{proxy}</td>
                      <td>{use}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="home__subhead" data-reveal>
              Three transport planes, two of them opt-in
            </p>
            <div className="home__grid" data-reveal data-stagger="110">
              {PLANES.map(({ tag, spell, name, detail }) => (
                <div className="home__card" key={spell}>
                  <p className="home__layer-n">
                    {tag}
                    <span className="home__plane-spell">{spell}</span>
                  </p>
                  <p className="home__card-name">{name}</p>
                  <p className="home__card-detail">{detail}</p>
                </div>
              ))}
            </div>

            <p className="home__subhead" data-reveal>
              The rule grammar, and the guards no rule can widen
            </p>
            <div className="home__split">
              <div data-reveal>
                <div className="home__chips" data-reveal data-stagger="45">
                  {GRAMMAR.map((spell) => (
                    <span className="home__chip" key={spell}>
                      {spell}
                    </span>
                  ))}
                </div>
                <p className="home__aside">
                  Deny always wins. A bare host is HTTPS on 443 and matches no subdomain. A
                  bare <code>*</code> is rejected outright: opening everything stays an
                  explicit act, and a catch-all regex is labelled as one wherever a rule is
                  listed. Under an app, an unscoped allow reads by default, resolving to{' '}
                  <code>{'{GET,HEAD}'}</code> until{' '}
                  <Link to="/docs/networking/modes">
                    <code>default_methods</code>
                  </Link>{' '}
                  says otherwise.
                </p>
                <Source
                  pages={[
                    { path: 'networking/rules', to: '/docs/networking/rules' },
                    { path: 'networking/modes', to: '/docs/networking/modes' },
                    { path: 'networking/architecture', to: '/docs/networking/architecture' },
                    { path: 'networking/ask', to: '/docs/networking/ask' },
                    { path: 'configuration/network', to: '/docs/configuration/network' },
                  ]}
                />
              </div>
              <dl className="home__facts" data-reveal data-stagger="70">
                {GUARDS.map(({ term, detail }) => (
                  <div className="home__fact" key={term}>
                    <dt>{term}</dt>
                    <dd>{detail}</dd>
                  </div>
                ))}
              </dl>
            </div>

            <p className="home__subhead" data-reveal>
              Five host-side surfaces, none of them reachable from the cage
            </p>
            <div className="home__verbs" data-reveal data-stagger="45">
              {NET_SURFACES.map(({ cmd, detail, to }) => (
                <Link className="home__verb" to={to} key={cmd}>
                  <code className="home__verb-cmd">{cmd}</code>
                  <span className="home__verb-detail">{detail}</span>
                </Link>
              ))}
            </div>

            <div className="home__notes">
              <div className="home__note" data-reveal>
                <p className="home__note-head">Quiet the noise</p>
                <p className="home__note-body">
                  <Link to="/docs/networking/observability">
                    <code>mute</code>
                  </Link>{' '}
                  keeps a deliberately denied host out of the default log, the SELinux{' '}
                  <code>dontaudit</code> analogue. It never changes a verdict and never hides
                  a count; <code>--all</code> brings the lines back, tagged.
                </p>
              </div>
              <div className="home__note" data-reveal data-delay="110">
                <p className="home__note-head">Or read the bytes</p>
                <p className="home__note-body">
                  <Link to="/docs/networking/observability">
                    <code>capture</code>
                  </Link>{' '}
                  is off by default, and records request and response heads, or the leading
                  bytes of each body, HTTP/2 streams and WebSocket transcripts included.
                  Configured secrets are masked before the bytes are stored, so the ring
                  never holds a credential.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint" id="secrets">
          <div className="home__inner">
            <div className="home__section-head" data-reveal>
              <div>
                <Ordinal n="06" label="secrets" />
                <h2 className="home__section-title home__section-title--flush">
                  The agent authenticates. It never holds the credential.
                </h2>
              </div>
              <p className="home__aside home__aside--side">
                The plaintext is read host-side, injected into the matching outbound request
                on the wire, and torn down when the cage exits.
              </p>
            </div>

            <div className="home__steps" data-reveal data-stagger="90">
              {SECRET_STEPS.map(({ n, head, detail, now }) => (
                <div className={now ? 'home__step home__step--now' : 'home__step'} key={n}>
                  <p className="home__step-head">
                    <span className="home__step-n">{n} · </span>
                    {head}
                  </p>
                  <p className="home__step-detail">{detail}</p>
                </div>
              ))}
            </div>

            <div className="home__profile home__profile--code-left">
              <div className="home__profile-code" data-reveal>
                <Pane label=".sbx.toml">
                  <CodeBlock language="toml">{SECRET_SAMPLE}</CodeBlock>
                </Pane>
              </div>
              <div data-reveal data-delay="120">
                <p className="home__aside home__aside--lead">
                  Resolvers are the open-ended half, installed as plugins from{' '}
                  <Link to="/docs/plugins/stores">signed stores</Link>, as are the signers
                  that form a credential per request and the brokers that stand in front of a
                  host socket. The one that puts a header on the wire stays first-party.
                </p>
                <div className="home__notes home__notes--stack">
                  <div className="home__note">
                    <p className="home__note-head">Two tripwires, and a third that only reports</p>
                    <p className="home__note-body">
                      The proxy refuses an outbound request carrying a configured value and
                      masks one a cooperating upstream reflects back. On an open WebSocket
                      neither is possible, so sbx names the secret and says plainly that
                      nothing was blocked. Backstops, not the boundary: any encoding evades a
                      byte-exact scan.
                    </p>
                  </div>
                  <div className="home__note">
                    <p className="home__note-head">Only under a filtering posture</p>
                    <p className="home__note-body">
                      Injection happens in the MITM proxy, so <code>shared</code> and{' '}
                      <code>none</code> inject nothing. sbx warns rather than quietly sending
                      an unauthenticated request.
                    </p>
                  </div>
                </div>
                <Source
                  pages={[
                    { path: 'secrets/', to: '/docs/secrets/' },
                    { path: 'secrets/resolvers', to: '/docs/secrets/resolvers' },
                    { path: 'secrets/injection', to: '/docs/secrets/injection' },
                    { path: 'secrets/redaction', to: '/docs/secrets/redaction' },
                    { path: 'configuration/secret', to: '/docs/configuration/secret' },
                  ]}
                />
              </div>
            </div>
          </div>
        </section>

        <section className="home__section" id="tasks">
          <div className="home__inner">
            <div className="home__profile home__profile--code-left">
              <div className="home__profile-code" data-reveal>
                <Pane label="[task.db-query]">
                  <CodeBlock language="toml">{TASK_SAMPLE}</CodeBlock>
                  {/* The invocation closes the same pane: the declaration, what
                      the caller types against it, and what it cost them are one
                      object, not a sample with a caption. */}
                  <pre className="home__pane-run">
                    <span className="home__pane-sigil">$ </span>
                    {TASK_RUN}
                    {'\n'}
                    <span className="home__pane-out">{TASK_RUN_OUT}</span>
                  </pre>
                </Pane>
              </div>
              <div data-reveal data-delay="120">
                <Ordinal n="07" label="declared operations" />
                <h2 className="home__section-title">
                  A fixed command, run with a credential the caller never holds.
                </h2>
                <ul className="home__arrows" data-reveal data-stagger="70">
                  {TASK_BOUNDS.map((bound) => (
                    <li key={bound}>{bound}</li>
                  ))}
                </ul>
                <Source
                  pages={[
                    { path: 'tasks/', to: '/docs/tasks/' },
                    { path: 'configuration/task', to: '/docs/configuration/task' },
                    { path: 'cli/task', to: '/docs/cli/task' },
                  ]}
                />
              </div>
            </div>
          </div>
        </section>

        <section className="home__section home__section--tint" id="apps">
          <div className="home__inner">
            <div className="home__profile">
              <div data-reveal>
                <Ordinal n="08" label="apps and profiles" />
                <h2 className="home__section-title">
                  One named launcher per agent, with an identity of its own.
                </h2>
                <p className="home__aside home__aside--lead">
                  An <code>[app.&lt;name&gt;]</code> table, or a standalone profile file,
                  defines a reusable launcher: <code>sbx app run agent</code> and it comes up
                  the same way every time, on any machine that has the file.
                </p>
                <dl className="home__facts" data-reveal data-stagger="70">
                  {APP_PROPS.map(({ term, detail }) => (
                    <div className="home__fact" key={term}>
                      <dt>{term}</dt>
                      <dd>{detail}</dd>
                    </div>
                  ))}
                </dl>
                <Source
                  pages={[
                    { path: 'apps/', to: '/docs/apps/' },
                    { path: 'apps/home', to: '/docs/apps/home' },
                    { path: 'configuration/apps', to: '/docs/configuration/apps' },
                    { path: 'configuration/bundles', to: '/docs/configuration/bundles' },
                  ]}
                />
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

        <section className="home__section" id="observability">
          <div className="home__inner">
            <div className="home__section-head" data-reveal>
              <div>
                <Ordinal n="09" label="observability" />
                <h2 className="home__section-title home__section-title--flush">
                  Four lenses on a running cage. None of them reachable from inside it.
                </h2>
              </div>
              <p className="home__aside home__aside--side">
                Host-side, read-only, unprivileged. The agent can neither read the record of
                what it did nor amend it.
              </p>
            </div>

            <div className="home__profile">
              <div data-reveal data-stagger="90">
                {LENSES.map(({ lens, question, reader, to }) => (
                  <Link className="home__lens" to={to} key={lens}>
                    <span className="home__lens-name">{lens}</span>
                    <span className="home__lens-body">
                      <span className="home__lens-q">{question}</span>
                      <span className="home__lens-reader">{reader}</span>
                    </span>
                  </Link>
                ))}
              </div>
              <div data-reveal data-delay="120">
                <Pane label="sbx logs">
                  <pre className="home__feed">
                    {FEED_HEAD.map((line) => (
                      <span className="home__feed-head" key={line}>
                        {line}
                        {'\n'}
                      </span>
                    ))}
                    {'\n'}
                    {FEED_LINES.map(({ at, feed, token, subject }, i) => (
                      <span key={i}>
                        {'  '}
                        <span className="home__feed-at">{at}</span>
                        {'  '}
                        <span className="home__feed-name">{feed.padEnd(6)}</span>
                        <span className="home__feed-token">{token.padEnd(10)}</span>
                        {subject}
                        {'\n'}
                      </span>
                    ))}
                  </pre>
                </Pane>
                <p className="home__aside">
                  Each lens is a ring in the supervisor's or the proxy's memory, never on
                  disk, read over a per-session control socket that is never bound into the
                  cage. Each is a lens, not a fence: only the exec lens has an enforcing
                  sibling. <Link to="/docs/cli/logs"><code>sbx logs</code></Link> is the only
                  reader for the two plugin feeds.
                </p>
              </div>
            </div>
            <Source
              pages={[
                { path: 'concepts/observability', to: '/docs/concepts/observability' },
                { path: 'networking/observability', to: '/docs/networking/observability' },
                { path: 'cli/logs', to: '/docs/cli/logs' },
              ]}
            />
          </div>
        </section>

        <section className="home__section home__section--tint" id="desktop">
          <div className="home__inner">
            <div data-reveal>
              <Ordinal n="10" label="the desktop hole, and the registry" />
              <h2 className="home__section-title">
                A GUI app can run in the cage. Wayland, never X11.
              </h2>
              <p className="home__aside home__aside--lead">
                A hermetic cage has no display, no GPU, no audio and no session bus, which is
                the safe default and useless for a graphical agent. Each hole opens one field
                at a time, and every one of them is trusted-only.
              </p>
            </div>

            <div className="home__panels">
              <div className="home__panel" data-reveal>
                <p className="home__panel-head">Desktop access, one field at a time</p>
                <dl className="home__facts home__facts--inline" data-reveal data-stagger="60">
                  {DESKTOP.map(({ term, detail }) => (
                    <div className="home__fact" key={term}>
                      <dt>{term}</dt>
                      <dd>{detail}</dd>
                    </div>
                  ))}
                </dl>
                <Source
                  pages={[
                    { path: 'configuration/gui', to: '/docs/configuration/gui' },
                    { path: 'gpu', to: '/docs/configuration/gpu' },
                    { path: 'audio', to: '/docs/configuration/audio' },
                    { path: 'dbus', to: '/docs/configuration/dbus' },
                    { path: 'open', to: '/docs/configuration/open' },
                  ]}
                />
              </div>
              <div className="home__panel" data-reveal data-delay="110">
                <p className="home__panel-head">Sessions and housekeeping</p>
                <div className="home__runs" data-reveal data-stagger="45">
                  {HOUSEKEEPING.map(({ cmd, detail, to }) => (
                    <Link className="home__run" to={to} key={cmd}>
                      <code className="home__run-cmd">{cmd}</code>
                      <span className="home__run-detail">{detail}</span>
                    </Link>
                  ))}
                </div>
                <Source
                  pages={[
                    { path: 'housekeeping/sessions', to: '/docs/housekeeping/sessions' },
                    { path: 'housekeeping/gc', to: '/docs/housekeeping/gc' },
                    { path: 'concepts/directory-layout', to: '/docs/concepts/directory-layout' },
                  ]}
                />
              </div>
            </div>
          </div>
        </section>

        <section className="home__section home__section--deep">
          <div className="home__inner">
            <div data-reveal>
              <p className="home__kicker home__kicker--accent">the surface</p>
              <h2 className="home__section-title">The verbs you reach for.</h2>
              <p className="home__aside home__aside--lead">
                Twelve of them carry most of the work. The{' '}
                <Link to="/docs/cli/">full reference</Link> covers the rest: networking,
                secrets, plugins, and the rest of the housekeeping.
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
            <h2 className="home__closer-title">
              Check the ground, then cage your first command.
            </h2>
            <p className="home__aside">
              The complete guide covers the concepts, every field of <code>.sbx.toml</code>,
              and every command. If you would rather follow a recipe, the{' '}
              <Link to="/docs/how-to/">how-to pages</Link> carry you from nothing to a caged
              agent, a filtered network, or a reproducible toolchain, with the commands in
              order.
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
