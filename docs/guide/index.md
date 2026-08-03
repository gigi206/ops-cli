---
hide:
  - toc
---

<div class="mdx-hero">

<div class="mdx-hero__content">

<h1>Run untrusted tools.<br>Encapsulate AI agents.</h1>

<p class="mdx-tagline">
  <code>sbx</code> is a single static binary that launches tools, including AI agents, inside a
  bubblewrap sandbox, where they install a project's full dependency set via
  daemonless nix, <strong>without ever touching your host</strong>.
</p>

<div class="mdx-badges">

<span class="mdx-badge">bubblewrap</span><span class="mdx-badge">daemonless nix</span><span class="mdx-badge">seccomp</span><span class="mdx-badge">cgroups v2</span><span class="mdx-badge">empty netns</span><span class="mdx-badge">static binary</span>

</div>

<a href="getting-started/quickstart/" class="md-button md-button--primary">Quick start</a>
<a href="concepts/overview/" class="md-button">What sbx is</a>

</div>

<div class="mdx-hero__image">

<div class="term">
  <div class="term__bar">
    <span class="term__dot"></span><span class="term__dot"></span><span class="term__dot"></span>
    <span class="term__title">sbx: project <code>repos/untrusted</code></span>
  </div>
  <pre class="term__body"><span class="term__prompt">$</span> sbx run -- npm install
<span class="term__dim">nix store: 342 packages provisioned, cage ready</span>
<span class="term__ok">seccomp</span> <span class="term__ok">cgroups</span> <span class="term__ok">empty netns</span> <span class="term__ok">read-only root</span>
<span class="term__prompt">$</span> sbx app launch codex
<span class="term__ok">cage up</span>: agent online, secrets never injected
<span class="term__prompt">$</span> sbx net rules
<span class="term__dim">allow: pypi.org, github.com, api.openai.com</span></pre>
</div>

</div>

</div>

## Sections

<div class="mdx-cards">

<a class="mdx-card" href="getting-started/installation/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="m20 22-3.86-1.55c.7-1.53 1.2-3.11 1.51-4.72zM7.86 20.45 4 22l2.35-6.27c.31 1.61.81 3.19 1.51 4.72M12 2s5 2 5 10c0 3.1-.75 5.75-1.67 7.83A2 2 0 0 1 13.5 21h-3a2 2 0 0 1-1.83-1.17C7.76 17.75 7 15.1 7 12c0-8 5-10 5-10m0 10c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2"/></svg>
<span class="mdx-card__title">Getting started</span>
<span class="mdx-card__text">Install the static binary, your first sandboxed command, <code>sbx doctor</code>.</span>
</a>

<a class="mdx-card" href="concepts/overview/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5zm0 6c1.4 0 2.8 1.1 2.8 2.5V11c.6 0 1.2.6 1.2 1.3v3.5c0 .6-.6 1.2-1.3 1.2H9.2c-.6 0-1.2-.6-1.2-1.3v-3.5c0-.6.6-1.2 1.2-1.2V9.5C9.2 8.1 10.6 7 12 7m0 1.2c-.8 0-1.5.5-1.5 1.3V11h3V9.5c0-.8-.7-1.3-1.5-1.3"/></svg>
<span class="mdx-card__title">Concepts</span>
<span class="mdx-card__text">The security model, the trust gate, the enforcement stack, provisioning.</span>
</a>

<a class="mdx-card" href="configuration/README/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M3 17v2h6v-2zM3 5v2h10V5zm10 16v-2h8v-2h-8v-2h-2v6zM7 9v2H3v2h4v2h2V9zm14 4v-2H11v2zm-6-4h2V7h4V5h-4V3h-2z"/></svg>
<span class="mdx-card__title">Configuration</span>
<span class="mdx-card__text">All <code>.sbx.toml</code> fields: env, binds, packages, secrets.</span>
</a>

<a class="mdx-card" href="cli/README/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 3v10h4v-2H4V5h2V3zm10 8h-2v2h4V3h-4v2h2zm10-5v12c0 1.11-.89 2-2 2H4a2 2 0 0 1-2-2v-3h2v3h16V6h-2.97V4H20c1.11 0 2 .89 2 2"/></svg>
<span class="mdx-card__title">Command reference</span>
<span class="mdx-card__text">Every <code>sbx</code> command at a glance, from <code>run</code> to <code>gc</code>.</span>
</a>

<a class="mdx-card" href="apps/README/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M16 20h4v-4h-4m0-2h4v-4h-4m-6-2h4V4h-4m6 4h4V4h-4m-6 10h4v-4h-4m-6 4h4v-4H4m0 10h4v-4H4m6 4h4v-4h-4M4 8h4V4H4z"/></svg>
<span class="mdx-card__title">Apps and profiles</span>
<span class="mdx-card__text">Named agent launchers with per-app isolated <code>$HOME</code> and portable profiles.</span>
</a>

<a class="mdx-card" href="networking/README/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M17 3a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-4v2h1a1 1 0 0 1 1 1h7v2h-7a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1H2v-2h7a1 1 0 0 1 1-1h1v-2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/></svg>
<span class="mdx-card__title">Networking</span>
<span class="mdx-card__text">The egress modes, the rule grammar, ask mode, observability.</span>
</a>

<a class="mdx-card" href="secrets/README/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2m5.6-4c-.8-2.3-3-4-5.6-4-3.3 0-6 2.7-6 6s2.7 6 6 6c2.6 0 4.8-1.7 5.6-4H16v4h4v-4h3v-4z"/></svg>
<span class="mdx-card__title">Secrets</span>
<span class="mdx-card__text">Resolvers, injection, redaction, plugins: credentials never enter the cage.</span>
</a>

<a class="mdx-card" href="housekeeping/sessions/">
<svg class="mdx-card__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="m19.36 2.72 1.42 1.42-5.72 5.71c1.07 1.54 1.22 3.39.32 4.59L9.06 8.12c1.2-.9 3.05-.75 4.59.32zM5.93 17.57c-2.01-2.01-3.24-4.41-3.58-6.65l4.88-2.09 7.44 7.44-2.09 4.88c-2.24-.34-4.64-1.57-6.65-3.58"/></svg>
<span class="mdx-card__title">Housekeeping</span>
<span class="mdx-card__text">Sessions, garbage collection, upgrading toolchains.</span>
</a>

</div>

## Reading paths

- **"I want to run an agent on an untrusted project safely."**
  [Security model](concepts/security-model.md) → [Apps](apps/README.md) →
  [Network modes](networking/modes.md) → [Secrets](secrets/README.md).
- **"I want to give my project a reproducible toolchain."**
  [Provisioning](concepts/provisioning.md) → [`packages`](configuration/packages.md) /
  [`[tools]`](configuration/tools.md) → [`sbx upgrade`](housekeeping/upgrade.md).
- **"I want to lock down what a tool can reach on the network."**
  [Network modes](networking/modes.md) → [Rule grammar](networking/rules.md) →
  [Ask mode](networking/ask.md) → [Observability](networking/observability.md).
- **"I just want the CLI."** [Command index](cli/README.md).
