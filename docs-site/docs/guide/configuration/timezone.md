# `timezone`: the cage's clock

Every sbx cage carries the **IANA zone database** and an `/etc/localtime` pointing into it.
Unset, that link names `UTC`. `timezone` names a different zone:

```toml
timezone = "Europe/Paris"
```

`timezone` is a **free field**: it applies from any project, trusted or not. The value travels
one way, it tells the cage what to display and reads nothing from the host, so no config can
learn where you are by setting it. It defaults to `UTC`.

See also: [`env`](env) · [Configuration overview](../configuration/) · [One-shot overrides](overrides).

## Why the database is always there

A hermetic cage has no host `/usr`, so without this it would carry no zone database and no
`/etc/localtime`. A program that resolves the local zone the FHS way then does not quietly fall
back to UTC, it **fails**: a Rust agent's scheduler reports `local timezone could not be
determined` and gives up. So the database is provisioned unconditionally, bound read-only at
`/usr/share/zoneinfo`, and named in `TZDIR`. It ships only data (no program), so nothing new
appears on the cage's `PATH`.

`UTC` is the default rather than "no zone" for the same reason. It is a real, resolvable answer
that discloses nothing about where the host is, so the failure above cannot happen in a cage
nobody configured.

## Two halves, one answer

Two different mechanisms read a cage's zone, and they have to agree:

- `TZ`, read by glibc and by the language runtimes that defer to it, which is what `date` prints.
- `/etc/localtime`, whose **link target** carries the zone *name*, which is what an FHS resolver
  reads.

sbx moves both from a single value, which only it can do, since only it assembles the cage. That
value is whatever `TZ` will finally read, and `timezone` when nothing set `TZ`. So an
[`[env]`](env) `TZ` (or a one-shot `--env TZ=Asia/Tokyo`) moves the link too, and outranks this
field when both are written: `TZ` is what the cage actually reads, so the link follows it rather
than contradicting it.

```sh
sbx run --env TZ=Asia/Tokyo -- sh -c 'date +%Z; readlink /etc/localtime'
# JST
# /usr/share/zoneinfo/Asia/Tokyo
```

Prefer the field. `[env] TZ` reaches the same place, but it reads as an environment variable and
sets a machine-wide property, and nothing in an `[env]` table says that.

## Which zone, and what happens to a wrong one

The value is an IANA zone name as it appears in the database (`Europe/Paris`, `UTC`,
`America/Argentina/Salta`, `Etc/GMT+3`). A name the database does not carry is **warned and
ignored**: the cage keeps `UTC` rather than failing to start, because a misspelled zone should
cost you a wrong clock, not a session.

## Where it is declared

A zone belongs to the machine and the person using it, not to an application, so it is a
**baseline** field: declare it in the global config and every project and every app inherits it.
There is no per-app override, and a shipped [app profile](apps) cannot carry one (it has no way
to know where its user is). A `timezone` written under an `[app.<name>]` is reported at launch
rather than silently ignored.

```toml
# ~/.config/sbx/sbx.toml: every cage on this machine
timezone = "Europe/Paris"
```

Being a scalar, it must sit **above** the first `[table]` header in the file, or TOML folds it
into that table and sbx never sees it.

## One-shot override

```sh
sbx run --config 'timezone = "Asia/Tokyo"' -- date
```

There is no dedicated flag; the whole-schema blob is the way to move a clock for one launch. See
[One-shot overrides](overrides).

## Viewing the effective zone

```sh
sbx config show    # a `timezone:` line, tagged with its layer, only when a layer named one
```

The line is absent when no layer set it, exactly like `gui: none`, because a cage that reads
`UTC` is the default state rather than something the configuration did.

## Checking it from inside

```sh
sbx run -- date              # the wall clock, from TZ
sbx run -- readlink /etc/localtime  # the zone name an FHS resolver reads
```

Both answer with the same zone, which is the property this field exists to hold.
