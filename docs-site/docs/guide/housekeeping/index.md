---
sidebar_label: "Overview"
description: "What a project needs over its lifetime: live sessions, the disk its stores take, and toolchains that move only when you say so."
---

# Housekeeping

What a project needs over its lifetime rather than at its first launch: the live
sessions a launch registers, the disk the per-project stores take, and the toolchains
that only move when you say so. These are operations you run, not ideas the rest of the
guide builds on, which is why they sit here rather than in [Concepts](../concepts/).

- [Sessions](sessions): the registry a launch writes, listing, attaching to and stopping
  what is running, and the background-agent posture.
- [Garbage collection](gc): what `sbx gc` reclaims, what it refuses to touch, and why a
  dry run is the default.
- [Upgrading toolchains](upgrade): why a binary update moves no version, what each
  backend does on `sbx upgrade`, and the lock model behind it.

The command references for the same three verbs are
[`sbx session`](../cli/session), [`sbx gc`](../cli/gc) and
[`sbx upgrade`](../cli/upgrade): this section is the model, those are the flags.
