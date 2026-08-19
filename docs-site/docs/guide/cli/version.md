# `sbx version`

```
sbx version
```

Print the version of this sbx build.

`sbx --version` and `sbx -V` are accepted spellings of the same command, so a script probing
for a version finds it under whichever one it tries. All three write one line to stdout and
exit 0:

```sh
sbx version        # sbx <version>
sbx --version      # the same line
sbx -V             # the same line
```

The version names the sbx build and nothing else. It says nothing about the engines a launch
drives: bubblewrap and nix are resolved at run time, and [`sbx doctor`](doctor) is what
reports the ones a given host offers, along with the store location and the channel revision
in use.

See also: [`sbx doctor`](doctor) · [Installation](../getting-started/installation).
