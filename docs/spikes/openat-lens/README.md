# `openat` lens measurement harnesses

Throwaway instruments, kept only so the numbers in
[`../../openat-lens-measurement.md`](../../openat-lens-measurement.md) can be re-derived rather than
taken on faith — one of them corrects a figure this repo had been carrying, so the instrument is
worth more than usual. They are **not** part of the build: no `Cargo.toml` knows about them, nothing
links them, and deleting this directory changes nothing but reproducibility.

Each is self-contained C (plus one Python trace parser). Build and run:

```bash
cd docs/spikes/openat-lens
gcc -O2 -o notif_openat  notif_openat.c
gcc -O2 -o notif_ceiling notif_ceiling.c
gcc -O2 -o notif_run     notif_run.c
gcc -O2 -o ns_read       ns_read.c
gcc -O2 -o cold_pid      cold_pid.c
gcc -O2 -o openat_cost   openat_cost.c
```

| harness | question it answers |
|---|---|
| `openat_cost` | what a native `openat` costs, and a remote pathname read by three mechanisms |
| `ns_read` | does reading across a descendant user namespace cost more (**no**) |
| `cold_pid` | is the exec supervisor's 11.9 µs per notification or per **new process** (per new process) |
| `notif_openat` | the end-to-end round trip a notified `openat` pays, three verdict shapes |
| `notif_ceiling` | aggregate notifications/s with *W* workers sharing one inherited filter |
| `notif_run` | `notif_run <0\|1 read path> -- <cmd>` — a real workload under the filter |
| `analyse.py` | breaks an `strace -f -e trace=open,openat,openat2` trace down by syscall, intent, path form and outcome |

They install real `SECCOMP_RET_USER_NOTIF` filters and read other processes' memory, so they need
the same unprivileged capabilities `sbx` itself needs (a working `unshare`, `no_new_privs`, and a
`ptrace_scope` that permits an ancestor to read a descendant). Nothing here needs root.

`notif_ceiling` forks a worker fleet into its own session; the workers also carry their own deadline,
so a killed supervisor cannot leave cores spinning.
