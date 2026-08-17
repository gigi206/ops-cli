# `[open]`: what a link opens with, inside the cage

A hermetic cage has no browser, no file manager and no desktop. So when a tool asks to open a URI,
there is nothing to open it with, and by default sbx says so: it prints the URI on stderr and
returns success, leaving you to follow the link yourself. That is enough for a device-auth flow to
carry on, but it is not enough for a sign-in that must come back to the application.

`[open]` says where a URI goes, keyed by its scheme:

```toml
[open]
http   = ["chromium", "--no-sandbox", "--ozone-platform=wayland"]
https  = ["chromium", "--no-sandbox", "--ozone-platform=wayland"]
cursor = { cmd = ["cursor", "--open-url"], mode = "detach" }
```

Two kinds of scheme show up in practice, and they answer different halves of one flow. `http` and
`https` send web links to a browser **running in the cage**, which is where a sign-in page should
open: the credentials you type there stay behind the same egress allowlist as everything else. A
scheme named after an application is that application's **callback**: the provider finishes the
sign-in by redirecting to `cursor://callback?...`, and that link has to arrive back at the caged
application rather than at your host desktop.

`[open]` is a **security field**, honored from the global config or a trusted project, ignored from
an untrusted one. A handler runs a program every time a link is opened, including a sign-in link a
person clicked, so a project that could declare one could answer that click with a page of its own.

See also: [`dbus`](dbus) · [`gui`](gui) · [`[network]`](network) · [`[bundle.<name>`](bundles) ·
[The trust gate](../concepts/trust)

## The shape of an entry

The key is a URI scheme. The value is either the argv to run, or a table adding how it is launched:

| field  | meaning                                                                       |
|--------|-------------------------------------------------------------------------------|
| `cmd`  | the program and its fixed arguments, as an argv (a bare string is a one-element argv) |
| `mode` | `"exec"` (the default) or `"detach"`                                          |

The table form can also be written as a section, which reads better once an entry has both fields:

```toml
[open.cursor]
cmd  = ["cursor", "--open-url"]
mode = "detach"
```

The URI is appended to the argv as its last argument. There is no shell in between, and no
placeholder to position it with: whatever runs in the cage chooses the URI, so a form that let it
land in the middle of a command would be a quoting surface rather than a convenience.

Scheme matching is case-insensitive, as URI schemes are, so a provider that redirects to
`CURSOR://callback` reaches the same handler as one that redirects to `cursor://callback`.

An entry is chosen by its scheme alone, whatever shape the rest of the URI takes:
`cursor://callback`, `cursor:/callback` and `cursor:callback` all reach the same handler. The `//`
is not what identifies a link, and a private-use redirect usually has none, since there is no host
in it to name.

## `mode`, and why it is not a detail

`exec` replaces the router with the handler, so a caller that waits for the open to finish waits
until the handler exits. `detach` starts the handler in the background and returns success
immediately.

Which one you need is a property of the **caller**, not of the handler. Some command-line tools run
the equivalent of `xdg-open <url>` and then wait for it before going on to exchange the
authorization code for a token. Give such a tool a handler that `exec`s a browser and the wait never
returns: the browser stays open, the tool sits on "opening browser", the sign-in completes in the
window, and no token is ever saved. Those callers need `detach`. An application that is already
running and only needs the deep link delivered to it wants `exec`, so the delivery is finished
before the router returns.

A detached handler's output cannot stay on your terminal, since it outlives the call that started
it, so it is appended to `.sbx-open.log` in the app's isolated home. That is where to look when a
sign-in opens a window and then goes nowhere. The file is never rotated: delete it if it grows.

## What a handler runs with

A handler gets the cage's environment on both routes, including the same `$HOME`, so one that writes
into the isolated home lands in the same place however the link was opened. The working directory is
the one difference: a handler reached through the portal starts at `/`, not where your command was
launched. Use absolute paths rather than relative ones.

## Both ways of opening a link reach the same handler

A URI can be opened two ways from inside a cage, and which one a tool uses depends on the library it
was built with:

- a command-line tool runs `xdg-open <uri>`, resolved on the cage's `PATH`;
- a GTK or Electron application calls the desktop portal's `OpenURI`, which resolves a **desktop
  entry** through the mime database and runs its `Exec=`.

sbx generates one router from `[open]` and points both routes at it, so a link behaves the same
either way. Under [`dbus = true`](dbus) that means a desktop entry and a `mimeapps.list` naming it,
generated for this launch alongside the router.

## Neither route can be re-pointed from inside the cage

The router is bound read-only, in a directory that comes **first** on the cage's `PATH`. It is the
one place sbx claims the head of `PATH` rather than leaving it to your declared tools, and it holds
that single name: without it the router would sit behind directories the cage can write, and
anything running in the cage could answer `xdg-open` in its place.

The portal's route is frozen the same way. The desktop entry and the mime defaults are bound
read-only at the exact names the XDG lookup prefers, which are inside the writable home: the lookup
asks for those paths by name, so freezing the directory around them would leave the names free to be
taken. `mimeapps.list` is the load-bearing one, because it decides **which** entry answers a scheme
no matter how many others claim it.

What this prevents is worth stating precisely, because it is narrower than it may sound. A cage is
one trust domain: whatever runs inside it can already run whatever it likes, so this is not a
privilege boundary and it is not what stops a compromised tool from acting. What it stops is
**substitution**: answering a sign-in link *you* clicked with a page of its own choosing, and
collecting credentials for a service the cage would otherwise never see.

## What `[open]` does not do

- **Schemes, not MIME types.** This routes links, not files. Opening a document with a viewer is a
  desktop concern, and the cage has no desktop.
- **No per-origin rules.** A handler is chosen by scheme alone. Which hosts are reachable at all is
  [`[network]`](network)'s answer, and a second policy here would be one more thing to keep in step
  with the first.
- **No configurable fallback.** A scheme no entry matches keeps the default behaviour: the URI is
  named on stderr and the call succeeds.

## Where to declare it

A handler can be declared at the baseline, on an app, or in a bundle. An app's entry wins over a
bundle's, and a bundle's over the baseline's, on the same scheme, exactly as `packages` and `env`
resolve.

A tool's own callback scheme belongs in its [bundle](bundles), beside its packages and its hosts:
it is a property of the tool, tracked with it, and a hand-copy of it falls behind the tool just as a
hand-copied host list does. Your choice of browser for the web schemes belongs at the baseline,
where every app shares it:

```toml
# global sbx.toml: one browser for every app's web links
[open]
http  = ["chromium", "--no-sandbox", "--ozone-platform=wayland"]
https = ["chromium", "--no-sandbox", "--ozone-platform=wayland"]
```

```toml
# the tool's bundle: its callback, carried with the tool
[bundle.cursor.open]
cursor = { cmd = ["cursor", "--open-url"], mode = "detach" }
```

An entry sbx cannot honor is dropped with a warning naming the scheme, and the launch goes on: a
malformed handler leaves a link unopened, never opened somewhere unintended.
