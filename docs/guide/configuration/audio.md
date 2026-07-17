# `audio` — microphone and playback

A hermetic cage carries no audio: no PulseAudio/PipeWire socket and no PulseAudio client
library, so a graphical app (Chromium/Electron) cannot open a capture or playback stream — its
**microphone and sound are silently unavailable**. `audio = true` lets a **trusted** config
open audio.

```toml
gui = "wayland"
audio = true
```

`audio` is a **security field** — honored from the global config or a trusted project, ignored
from an untrusted one — because the PulseAudio bus is not per-client isolated: a connected
client can capture the microphone **and every system-audio `.monitor` source** (record whatever
is playing on the host). It defaults to `false` (no audio access).

See also: [`gui`](gui.md) · [`gpu`](gpu.md) · [`dbus`](dbus.md) · [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## What `audio = true` provides

Everything is supplied automatically — no paths to write. It covers **both** kinds of Linux audio
client:

**The host PulseAudio socket.** `$XDG_RUNTIME_DIR/pulse/native` (which a PipeWire host exposes
through `pipewire-pulse`, and a native PulseAudio host creates directly) is bound **read-only**
into the cage at a fixed path and named through `PULSE_SERVER`. Same-uid, so a read-only bind
still permits `connect()` (exactly like the Wayland socket).

**For a native PulseAudio client** (Chromium/Electron): the **PulseAudio client library**
(`libpulse.so.0`) is provisioned into sbx's own store and put on the app's loader search path
(`LD_LIBRARY_PATH`). Chromium loads it by soname, and it is absent from a packaged app's own
closure (which carries only ALSA), so without it the PulseAudio backend never loads.

**For an ALSA client** (a terminal tool whose voice mode uses `cpal`/PortAudio/`arecord`): these
speak the ALSA API and do **not** honor `PULSE_SERVER`, so sbx adds the standard **ALSA→PulseAudio
compatibility shim** — the `alsa-plugins` `pcm_pulse`/`ctl_pulse` plugins plus a generated
`asound.conf` routing the default PCM/control to `pulse` (`ALSA_CONFIG_DIR`/`ALSA_PLUGIN_DIR`
point ALSA at them). An ALSA `default` capture/playback is then transparently routed to the same
PulseAudio socket — the same mechanism a desktop uses to let ALSA apps reach PipeWire. `libasound`
itself is provisioned too, for a CLI binary that does not carry its own.

Everything is hermetic (the same pinned nixpkgs as the app, no host library path). The socket bind
and `PULSE_SERVER` are firm; the client libraries and the ALSA shim are **best-effort** — if they
cannot be provisioned (no network on a first launch), the app still runs, it simply finds no audio
client and has no sound, rather than failing the launch.

> **ALSA is not deprecated.** It is the Linux kernel sound layer that every audio server (PulseAudio,
> PipeWire) runs on top of; `libasound` and the `alsa-plugins` pulse bridge are standard and
> maintained. The shim is the normal way an ALSA application reaches a PulseAudio/PipeWire server,
> not a workaround.

## PipeWire and PulseAudio

Most modern desktops run **PipeWire**, which ships a PulseAudio-compatible server
(`pipewire-pulse`) exposing the very socket `audio = true` binds. A classic PulseAudio host
works identically. The app talks the PulseAudio protocol either way — no PipeWire-native client
is required for the microphone.

## Most useful with a display

`audio = true` is independent of `gui`, but its point is a graphical app's microphone and sound,
so it is normally paired with `gui = "wayland"`.

## Why it is trusted-only

The PulseAudio bus grants a connected client the microphone **and** every `.monitor` source —
that is, the ability to record all system audio output (other apps, a meeting), not only the
microphone. That is a choice only a trusted operator makes, so an untrusted project's `audio`
posture is dropped, and a globally-declared app keeps its audio posture even under an untrusted
project (an agent runs *on* untrusted code without that code opening — or closing — the app's
microphone access).

## Per-app posture

An `[app.<name>]` `audio = true`/`false` (or `audio` in an imported profile) sets the posture
**for that app's launches**, overriding the baseline and gated the same way. An untrusted
project's app `audio` is dropped.

```toml
[app.desktop]
audio = true
```

## One-shot override

To set the audio posture for a single launch without editing the file, use `--audio` or
`SBX_AUDIO`:

```sh
sbx app claude-desktop --audio        # bare --audio means true
sbx app claude-desktop --audio=false  # disable the profile's audio for this launch
```

`--audio` is a boolean: bare `--audio` means `true`, or write `--audio=true` / `--audio=false`
(it never takes a space-separated value, so it cannot swallow a following app name). Like the
config field it is trusted by invocation. The command line beats the environment, and both beat
the config file. See [One-shot overrides](overrides.md).

## Viewing the effective posture

```sh
sbx config show                # an `audio:` line only when it is enabled
sbx config show --app desktop  # an app's effective posture, tagged inherited or set
```

## Access, not new privilege

`audio = true` binds the host audio socket; whether a process may capture is still governed by
the host's audio server and the uid the cage runs as (same-uid) — exactly as on the host. `sbx`
grants visibility, not new privilege. The confidentiality point stands: it is a **capability**,
exposing the microphone and all system audio to the cage, which is why it is off by default and
trusted-only.
