---
sidebar_label: "Overview"
description: "The three lookup tables that belong to no single subsystem: environment variables, exit codes, and the glossary."
---

# Reference

Three lookup tables that belong to no single subsystem, because every subsystem
touches them.

- [Environment variables](environment-variables): the `SBX_*` knobs read on the host,
  and what the cage's own environment holds.
- [Exit codes](exit-codes): what each exit status means, and which of them a script may
  branch on.
- [Glossary](glossary): the terms this guide uses in a specific sense: cage, posture,
  broker, resolver, the trust gate.

The other two reference surfaces have their own sections:
[Configuration](../configuration/) for the `.sbx.toml` fields, and
[Command reference](../cli/) for the verbs.
