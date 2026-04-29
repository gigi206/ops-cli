# Running containers from inside ops

When you're working inside an `ops` shell and need to run a container — for
example to test a Dockerfile, exec into an image, or use a tool that itself
spawns containers (Compose, Testcontainers, devcontainers CLI, …) — the
short answer is: **don't run a container engine inside the container, mount
the host's socket instead**.

This document covers the three host runtimes (`docker`, `podman`, `nerdctl`),
what each one needs to be reachable from a sibling container, and which one
to prefer.

The tooling decision in one line:

> **Mount the host's podman socket and use the docker CLI inside.**

The longer rationale and the other two approaches are below.

---

## Quick comparison

| Runtime | CLI inside | Bind-mounts | Container user | Capabilities | Security | Verdict |
|---|---|---|---|---|---|---|
| **podman rootless** (host) | `docker` (compat) | 1 (socket file) | non-root | none | user-scope | **recommended** |
| **docker rootful** (host) | `docker` | 1 (socket file) + `--group-add` | non-root | none | host-root effective | fine for trusted dev |
| **containerd + nerdctl** | `nerdctl` (binary at host path) | 5 directories | root | `SYS_ADMIN, NET_ADMIN` + `apparmor=unconfined` | host-root + namespace caveats | discouraged upstream |

The image baseline already ships everything you need for the first two: just
add `EXTRA_MISE_TOOLS=nix:docker-client` (~70 MB) to your `OPS_BUILD_ARGS` to
get the `docker` CLI inside.

---

## 1. Podman rootless socket — recommended

Podman serves a Docker-compatible API on its rootless socket. You mount that
socket into the container and point the in-container `docker` CLI at it via
`DOCKER_HOST`. The "daemon" runs entirely in your own user session on the
host — no escalation, no extra capabilities.

### Prerequisites (one-time, host side)

```bash
# Install podman (if not already)
sudo apt install podman              # Debian/Ubuntu
sudo pacman -S podman                # Arch

# Enable and start the rootless socket as a user systemd unit
systemctl --user enable --now podman.socket

# Verify
ls -la /run/user/$(id -u)/podman/podman.sock
```

### Inside ops

Add the docker CLI to the image once:

```bash
ops config set 'OPS_BUILD_ARGS[default]' 'EXTRA_MISE_TOOLS=nix:docker-client'
ops update default
```

Then run with the socket mounted:

```bash
PODMAN_SOCK="/run/user/$(id -u)/podman/podman.sock"
ops -v "$PODMAN_SOCK:$PODMAN_SOCK" \
    -e "DOCKER_HOST=unix://$PODMAN_SOCK" \
    shell

# inside the shell
docker run --rm hello-world
```

To persist the volume + env in `ops.conf`, see the [`ops.conf` examples](#opsconf-examples-three-runtimes-side-by-side) section at the end of this doc.

### What works

- `docker run` / `docker exec` / `docker logs` / `docker ps`
- `docker build` (BuildKit hosted by podman)
- `docker compose` (with `nix:docker-compose` added too)
- `docker images` shows the host's rootless podman storage

### Caveats

- **Volume paths resolve on the host.** A bind-mount like
  `docker run -v $PWD:/x` resolves `$PWD` against the host filesystem
  (where podman runs), not the ops container. If your project sits at
  `/home/you/code/foo` on the host and is bind-mounted into ops at
  `/workspace/foo`, you must use `/home/you/code/foo` for the new mount.
- **Networks are siblings on the host.** Containers spawned this way are
  not on the ops container's network; they're on podman's host network.
  `--network=container:ops-dev` does not do what you may expect.
- **UID `1000` is hard-coded** in the path above. Resolve dynamically with
  `$(id -u)` in scripts.

---

## 2. Docker rootful socket — alternative

Same idea, but you talk to the host's docker daemon. Use this if your team
or workflow already centers on docker (e.g. a shared image cache, plugins
that only docker exposes). The trade-off is security: anyone with access
to `/var/run/docker.sock` is effectively root on the host (a one-line
`docker run -v /:/host --privileged` proves it).

### Prerequisites (host side)

```bash
# Install docker
sudo apt install docker.io           # Debian/Ubuntu
sudo pacman -S docker                # Arch
sudo systemctl enable --now docker

# Add yourself to the docker group (logout/login required)
sudo usermod -aG docker $USER
```

### Inside ops

```bash
ops config set 'OPS_BUILD_ARGS[default]' 'EXTRA_MISE_TOOLS=nix:docker-client'
ops update default

# Resolve the docker group GID dynamically (varies per host)
DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"

ops -v /var/run/docker.sock:/var/run/docker.sock \
    --group-add "$DOCKER_GID" \
    shell

# inside the shell
docker run --rm hello-world
```

`OPS_VOLUMES` persists the bind-mount, but `--group-add` resolves the GID
dynamically — wrap both in a function alias (see the
[`ops.conf` examples](#opsconf-examples-three-runtimes-side-by-side) at the
end of this doc).

### What works / caveats

Same as podman, with two notes:

- **Cache is shared with the host docker.** `docker images` shows what
  `docker images` on the host shows. Useful when you want to avoid
  re-pulling layers.
- **Rootless docker has a different socket path:**
  `/run/user/$UID/docker.sock`. Detect it before falling back to
  `/var/run/docker.sock`.

---

## 3. Containerd socket + nerdctl — discouraged

**Stop and read this section before going down this path.** Unlike docker
and podman, nerdctl is not a thin gRPC client — it generates OCI runtime
specs that contain absolute paths (the nerdctl binary itself, the CNI
plugins, the snapshotter directory, …) which the runtime resolves on the
**host**, not in the sibling container. The upstream maintainer
[explicitly calls this an antipattern](https://github.com/containerd/nerdctl/discussions/2484):

> "Running such things seems like antipattern in kubernetes" — it can
> "impact every thing running on this node".

It is technically possible. The minimum viable invocation:

```bash
# rootful containerd only — rootless adds rootlesskit-namespace problems
ops --user 0:0 \
    --cap-add SYS_ADMIN --cap-add NET_ADMIN \
    --security-opt apparmor=unconfined \
    -v /run/containerd:/run/containerd \
    -v /var/lib/containerd:/var/lib/containerd \
    -v /var/lib/nerdctl:/var/lib/nerdctl \
    -v /home/you/.local/share/ops/nerdctl/bin/nerdctl:/home/you/.local/share/ops/nerdctl/bin/nerdctl:ro \
    -e XDG_RUNTIME_DIR=/tmp/empty \
    shell

# inside, with --net=host (CNI bridge does not work without further alignment)
/home/you/.local/share/ops/nerdctl/bin/nerdctl \
    --address /run/containerd/containerd.sock \
    run --rm --net=host alpine echo "ok"
```

This is fragile, requires `root` and broad capabilities, and even then
default-network containers fail because the CNI plugin path baked into the
spec must exist at the same location on host and inside the container.
**Use approach 1 or 2 instead unless you have a specific reason to talk
directly to containerd.**

If you are stuck with containerd-only (k3s, embedded systems, …), the
maintained pattern is to install nerdctl on the host and shell into the
host directly, not from a sibling container.

---

## Choosing between podman and docker socket

The tie-breaker is your security tolerance:

- **Trusted single-user dev box**, you are the only one running the
  container → either works, podman is cleaner.
- **CI runner**, **shared workstation**, **untrusted code** → podman socket
  is the only safe option. The docker socket gives the container effective
  root on the host.
- **You need a feature only docker supports** (a specific buildx plugin, a
  Docker Hub Pro feature, …) → docker socket.
- **Mixed**: nothing prevents you from configuring both and switching via
  `DOCKER_HOST`.

---

## Why we don't bake an engine inside the image

A `Dockerfile.systemd` variant that runs `dockerd` inside the container is
possible but trades simplicity for problems:

- forces `--privileged` at runtime,
- breaks the rootless model that `nerdctl` and `podman` users rely on,
- doubles the storage (image cache inside the container, separate from the
  host's),
- makes the container slow to start (systemd PID 1 + dockerd boot).

Socket-mounting gives you the same functional result (run a container from
inside the dev shell) for ~50 MB of image bloat and zero runtime
escalation.

---

## `ops.conf` examples — three runtimes side by side

`ops` does not expose a dedicated `OPS_RUN_ENV` knob: extra env vars are
passed via `-e KEY=VAL` flags at invocation time (see
[`run` flags](../README.md#run-flags)). The clean way to make a
nested-container setup permanent is a **function alias**: it bundles the
`-v`, `-e`, and capability flags into one shell function that ops calls
when you type the alias name. UIDs and GIDs are resolved at call time, so
the same snippet works on any host.

Drop one (or more) of the following blocks into `~/.config/ops/ops.conf`.
Form 2 (function aliases) is documented in
[Custom aliases](../README.md#custom-aliases) of the README.

```bash
# ~/.config/ops/ops.conf

# ─────────────────────────────────────────────────────────────────────────
# 1. Podman rootless socket — recommended (no root, no caps)
#    Prereq: systemctl --user enable --now podman.socket
#    Image must include the docker CLI:
#      ops config set 'OPS_BUILD_ARGS[default]' 'EXTRA_MISE_TOOLS=nix:docker-client'
#    Usage: ops podman   (or:  ops podman -- docker run --rm hello-world)
# ─────────────────────────────────────────────────────────────────────────
ops_alias_podman() {
    local sock="/run/user/$(id -u)/podman/podman.sock"
    echo run -v "$sock:$sock" -e "DOCKER_HOST=unix://$sock"
}

# ─────────────────────────────────────────────────────────────────────────
# 2. Docker rootful socket — simple, but socket access ≈ host root
#    Prereq: user must be in the host docker group
#    Image must include the docker CLI (same EXTRA_MISE_TOOLS as above)
#    Usage: ops docker
# ─────────────────────────────────────────────────────────────────────────
ops_alias_docker() {
    local sock=/var/run/docker.sock
    local gid
    gid="$(stat -c '%g' "$sock" 2>/dev/null || echo 999)"
    echo run -v "$sock:$sock" --group-add "$gid"
}

# ─────────────────────────────────────────────────────────────────────────
# 3. Containerd socket + nerdctl — discouraged upstream, exposed for
#    completeness. Requires root in container, broad capabilities, and
#    the nerdctl binary at the SAME absolute path on host and inside.
#    Image must include nerdctl: EXTRA_MISE_TOOLS=nix:nerdctl
#    (or bind-mount the host's nerdctl binary at the host path).
#    Alias is named `containerd` (not `nerdctl`) because `nerdctl` is a
#    reserved ops subcommand — see _OPS_RESERVED in ops.sh.
#    Usage: ops containerd -- nerdctl --address /run/containerd/containerd.sock \
#                                      run --rm --net=host alpine echo ok
# ─────────────────────────────────────────────────────────────────────────
ops_alias_containerd() {
    local nerdctl="/home/$(id -un)/.local/share/ops/nerdctl/bin/nerdctl"
    echo run --user 0:0 \
        --cap-add SYS_ADMIN --cap-add NET_ADMIN \
        --security-opt apparmor=unconfined \
        -v /run/containerd:/run/containerd \
        -v /var/lib/containerd:/var/lib/containerd \
        -v /var/lib/nerdctl:/var/lib/nerdctl \
        -v "$nerdctl:$nerdctl:ro" \
        -e "XDG_RUNTIME_DIR=/tmp/empty"
}
```

Pick one of the three based on your host setup; nothing prevents declaring
several aliases and choosing per session (`ops podman` for daily work,
`ops docker` when you specifically need the host docker cache, `ops containerd`
only as a last resort).

---

## References

- [containerd/nerdctl discussion #2484 — DooD with nerdctl](https://github.com/containerd/nerdctl/discussions/2484)
- [containerd/nerdctl discussion #2008 — accessing host containerd](https://github.com/containerd/nerdctl/discussions/2008)
- [containerd/nerdctl discussion #4337 — createRuntime hook errors](https://github.com/containerd/nerdctl/discussions/4337)
- [OCI runtime-spec — hooks resolve in the runtime namespace](https://github.com/opencontainers/runtime-spec/blob/main/config.md)
- [Podman socket activation guide](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html)
