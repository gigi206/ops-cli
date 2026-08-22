---
sidebar_label: "Overview"
description: "Task-oriented walkthroughs: the commands in order, from nothing to a working setup."
---

# How-to recipes

These pages are task-oriented walkthroughs: each one carries you from nothing to a
working setup with the commands in order, and hands you off to the page that owns
each subject for the full story. The conceptual and reference material they lean on
is linked at every step, not repeated.

- [Run an agent on an untrusted project](run-agent-safely): launch first, declare
  tools, shape the egress posture, keep credentials out of the cage, watch it run,
  vouch last.
- [Give a project a reproducible toolchain](reproducible-toolchain): `packages`,
  pins, mise toolchains, deliberate upgrades, reclaiming space.
- [Restrict what a tool reaches on the network](restrict-network): modes, rule
  grammar, learning the rule set from a live session, proving it before a launch.
- [Give an agent a credential it can use but never read](inject-a-credential): a
  `[secret]` block from nothing to a verified injection, and what then watches it.
- [Run an agent in the background and check on it](background-agent): `--detach`, the
  four observation feeds, attaching to a live cage, and ending it.
- [Choose the tools an agent cage needs](recommended-tools): the recommended set, where
  to declare each tier, and how to pin versions.

New to `sbx` itself? [Install](../getting-started/installation) then
[Quick start](../getting-started/quickstart) come first.
