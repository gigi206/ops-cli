---
sidebar_label: "[plugin.<name>]"
description: "What this machine supplies to an installed plugin, and where to get a tool it does not have."
---

# `[plugin.<name>]`: configuring an installed plugin


A manifest says what a resolver *needs*. What this machine *supplies* is declared on your side,
in a `[plugin.<name>]` table in the global config or a trusted project's:

```toml
[plugin.vault]
env      = { VAULT_ADDR = "https://vault.example.com", VAULT_NAMESPACE = "team-a" }
programs = { vault = "nix:vault" }

[plugin.pass]
env = { PASSWORD_STORE_DIR = "/data/secrets" }
```

This is why the variables exist at all. `VAULT_ADDR` had to be exported by whatever shell
launched `sbx`; now it can live in the project that needs it, versioned with the rest of the
configuration.

- **Only a variable the manifest reads may be set.** A name that appears in neither `allow_env`
  nor `allow_env_paths` is dropped with a warning naming it, so a config can never put an
  arbitrary variable into the environment of a third-party binary that runs host-side on the
  plaintext path.
- **A path-valued variable is bound as well as passed.** `PASSWORD_STORE_DIR` above both tells
  `pass` where the store is and gives the sandbox access to it, since the manifest declares that
  name in `allow_env_paths`.
- **A value here wins over the same name in sbx's environment.** A config that names a value is
  more deliberate than whatever the invoking shell happened to export.
- **It is a security field**, gated like `[packages]`: honored from the global config or a
  trusted project, dropped with a warning from an untrusted one, and ignored in a one-shot
  `--config` blob.
- **Not for secrets.** A value here sits in plaintext in a config file. A credential belongs in
  [`[secret]`](../configuration/secret), whose sources are resolved at launch.

`sbx plugins info <name>` prints the table under the grant, marking any variable that will be
ignored, so the answer to "why is my setting not applying" is in the same place as the setting.

#### `programs`: where to get a tool this machine does not have

A manifest names the tools its resolver runs and `sbx` finds each on its own `PATH`, which is
what makes a published plugin work whatever installed them. `programs` is the answer for the
machine where one of them is simply not installed: name a nixpkgs attribute, and `sbx` builds it
into its own store and binds that.

- **`PATH` always wins.** This is a fallback, never a redirection. If you have the tool, you get
  the tool you have, and the entry is reported as unused.
- **Only a program the manifest runs may appear**, and **only `nix:`**. Anything else is dropped
  with a warning naming it. `nix:` is the one backend that can be built host-side and
  project-independently at the moment a plugin is installed: a `mise:` tool is equipped *inside* a
  cage, and the prebuilt backends are pinned per project.
- **What follows `nix:` must be an attribute**, by the same rule `[packages]` applies to the same
  value: letters, digits, `_`, `-`, `.` and `+`. Anything else is dropped with a warning naming it,
  because that text goes into the nix expression sbx builds the program from.
- **The build happens at `sbx plugins install`**, not at launch. A plugin is installed once and
  any project may route a secret through it, so its program belongs to the plugin rather than to
  a project, and a launch only reads the result. The consequence is worth knowing: adding
  `programs` **after** installing takes one command, `sbx plugins install` again. The error a
  launch raises for a missing program says so.
- It uses the **global** nixpkgs pin, never a project's, so one plugin's tool cannot differ
  between the projects that share it.
- Removing the plugin removes what was built for it.

`sbx plugins info <name>` distinguishes all four states: found on `PATH`, provisioned, configured
but not yet built, and neither.

## See also

- [The `plugin.toml` manifest](manifest): the `allow_env`, `allow_env_paths` and
  `programs` declarations this table answers.
- [Configuration overview](../configuration/): where a security field is honored from.
