---
description: "Print the version of this sbx build."
---

# `sbx version`

```
sbx version
```

Print the version of this sbx build. Takes no argument: anything extra is refused
(usage, exit 2).

`sbx --version` and `sbx -V` are accepted spellings of the same command, so a script probing
for a version finds it under whichever one it tries. All three write one line to stdout and
exit 0:

```sh
sbx version        # sbx <version>, or sbx <version> (<tag>, <commit>)
sbx --version      # the same line
sbx -V             # the same line
```

A published build adds the release it was published as: the tag it was published under and
the commit it was built from, as in `sbx 0.1.0 (latest, 0a9ad1c)`. That release is the one
[`sbx upgrade self`](upgrade#upgrading-sbx-itself) follows. A build from source prints the
version alone. The version number is the crate's, which every build carries, so it is the tag
and the commit that tell two builds apart.

The version names the sbx build and nothing else. It says nothing about the engines a launch
drives: bubblewrap and nix are resolved at run time, and [`sbx doctor`](doctor) is what
reports the ones a given host offers, along with the store location and the channel revision
in use.

See also: [`sbx doctor`](doctor) · [Installation](../getting-started/installation).
