"""Break a strace open/openat/openat2 trace down along the three axes that decide whether an
openat user-notification lens can be built cheaply, or at all.

  coverage  which syscall was used — a filter on openat alone is bypassable by openat2 or legacy open
  intent    read-only vs write-intent, the only axis a cBPF pre-filter can see (it cannot deref a path)
  path form absolute vs relative, since a relative path needs an extra readlink to resolve
"""

import re
import sys
from collections import Counter

CALL = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(open|openat|openat2)\((.*)$")


def split_args(rest):
    """Split an strace argument list at top level, ignoring commas inside quotes or brackets."""
    out, depth, cur, in_str, esc = [], 0, [], False, False
    for ch in rest:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            cur.append(ch)
            continue
        if in_str:
            cur.append(ch)
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            if depth == 0 and ch == ")":
                out.append("".join(cur).strip())
                return out
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur).strip())
    return out


def report(path):
    syscalls, intent, form, dirfd, result = (Counter(), Counter(), Counter(), Counter(), Counter())
    total = 0
    for line in open(path, encoding="utf-8", errors="replace"):
        m = CALL.match(line.strip())
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        args = split_args(rest)
        syscalls[name] += 1
        total += 1

        if name == "open":
            path_arg, flags = (args[0] if args else ""), (args[1] if len(args) > 1 else "")
            dirfd["n/a (legacy open)"] += 1
        else:
            d = args[0] if args else ""
            path_arg = args[1] if len(args) > 1 else ""
            flags = args[2] if len(args) > 2 else ""
            dirfd["AT_FDCWD" if d == "AT_FDCWD" else "a directory fd"] += 1

        writeish = any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
        intent["write-intent" if writeish else "read-only"] += 1

        p = path_arg.strip()
        if p.startswith('"'):
            p = p[1:]
        form["absolute" if p.startswith("/") else "relative"] += 1

        # How many opens already fail on the host: the path-probing an in-cage lens would also see,
        # and the share of notifications a refusal-only lens could never be asked about.
        result["failed (ENOENT etc.)" if "= -1" in line else "succeeded"] += 1

    print(f"\n=== {path.rsplit('/', 1)[-1]} — {total} calls ===")
    for label, c in (("syscall", syscalls), ("intent", intent), ("path form", form),
                     ("dirfd", dirfd), ("outcome", result)):
        parts = ", ".join(f"{k} {v} ({100.0 * v / total:.1f}%)" for k, v in c.most_common())
        print(f"  {label:10s}: {parts}")


for arg in sys.argv[1:]:
    report(arg)
