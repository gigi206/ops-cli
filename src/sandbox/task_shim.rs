//! The task client the cage gets: a generated shell script, not sbx.
//!
//! # Why not sbx itself
//!
//! The crossing socket has to be reachable from inside — an agent that cannot reach it cannot
//! invoke a declared operation at all. What crosses *with* it is a choice, and handing over the
//! whole sbx binary made the cage's safety rest on a **negative** property: that no part of sbx's
//! data directory or config is ever bound, so every subcommand but `task` has nothing to act on.
//! Nothing enforced that. A cage already binds the project, the app homes and the tool pools; one
//! future mount touching the data directory would have turned an inert binary into a live one with
//! no test failing.
//!
//! So the cage gets a client that **cannot** express anything else: three verbs, one socket, and a
//! default branch that refuses every other word. The property is now positive and readable in forty
//! lines rather than asserted about a binary.
//!
//! # Why a script rather than a second binary
//!
//! Every ingredient is already in the cage unconditionally: the shell, coreutils, and `socat` (the
//! egress forwarder, carried in every cage regardless of network posture). The wire protocol frames
//! payloads by length in both directions, so it needs no parser beyond `read` and a byte copy. A
//! script is therefore generated at launch from this module — nothing to compile, embed, pin or
//! ship, and no build in which the client is accidentally missing.
//!
//! # The drift this must not have
//!
//! Sharing one binary bought one real property: client and server could never disagree about the
//! wire. That is paid back here by testing the generated script against the **real** plane and the
//! **real** response writer, so a change to either side fails a test rather than reaching a user.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Quote a path for the script. Store paths never contain a quote, but a generated file that
/// interpolates a path must not depend on that being true.
fn quote(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

/// Render the in-cage task client.
///
/// Every external command is named by absolute path: the agent owns `PATH` inside the cage, and a
/// client that resolved `head` through it would break — or behave differently — for reasons that
/// have nothing to do with the task plane.
pub(crate) fn render(bash: &Path, socat: &Path, head: &Path, socket: &str) -> String {
    format!(
        r##"#!{bash}
# The task client this sandbox exposes. Generated per session by sbx, and deliberately NOT the sbx
# binary: the only words it understands are the declared-operation verbs, so no code that could act
# on sbx's own state is reachable from inside the cage. Every decision — the program a task runs,
# its bounds, its credential, its ceilings — belongs to the plane behind the socket. This frames a
# request and renders the answer, nothing more.
set -u
# The wire frames every payload by BYTE length, so `${{#value}}` must count bytes rather than
# characters. Without this a non-ASCII parameter would announce fewer bytes than it writes and
# desynchronise the stream.
LC_ALL=C
export LC_ALL

sock={socket}
socat={socat}
head={head}

# How long to keep reading the answer after the request has been written. socat's default is half a
# second: it treats "this side stopped talking" as "the exchange is nearly over" and tears the
# connection down. An operation is a *command being run* on the other end — the default timeout is
# thirty seconds and a declaration may raise it — so at the default this client reads a truncated
# answer for anything but an instant operation, while the same call succeeds host-side. Waiting is
# safe: the plane closes the connection when the operation ends, and a plane that died closes it too,
# so this bound is only ever reached by a plane that is alive and stuck.
wait_for_answer=86400

die() {{
    printf 'sbx: %s\n' "$1" >&2
    exit "$2"
}}

unreachable() {{
    printf 'sbx: task: cannot reach the task plane\n' >&2
    printf '       the session may have ended, or its config declares no `[task.<name>]`.\n' >&2
    exit 1
}}

# The plane answered and the answer stopped early. Distinct from never reaching it: the operation may
# well have run, so the one thing this must not do is invent an exit code for it.
truncated_answer() {{
    printf 'sbx: task run: the answer from the task plane stopped early\n' >&2
    printf '       the operation may have run; its result is unknown.\n' >&2
    exit 1
}}

usage() {{
    printf 'sbx task — the declared operations this sandbox offers\n\n' >&2
    printf 'Usage:\n' >&2
    printf '  sbx task list                           what this session offers\n' >&2
    printf '  sbx task secrets                        the credentials they carry\n' >&2
    printf '  sbx task run <name> [-p KEY=VALUE]...   invoke one\n' >&2
}}

# A task name and a parameter key travel on a header line, which spaces and newlines delimit.
# Refusing the rest of the character set here turns a request that would desynchronise the stream
# into a local error, rather than a puzzling refusal from the far side.
safe_word() {{
    case $1 in
        '' | *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}}

# `list`/`secrets` take an optional session id on the host; in the cage there is exactly one plane
# to reach, so an id is accepted and ignored — the same invocation then works unchanged on both
# sides. A flag is refused: it would name something this client does not do.
check_inventory_args() {{
    local verb=$1 arg seen=0
    shift
    for arg in "$@"; do
        case $arg in
            -*) die "task $verb: unexpected argument \"$arg\"" 2 ;;
            *)
                [ "$seen" = 0 ] || die "task $verb: unexpected argument \"$arg\"" 2
                seen=1
                ;;
        esac
    done
}}

# `LIST` and `SECRETS` answer with `<prefix> <tab-separated fields>` lines and close with `ok`. The
# response is plain text bounded by the inventory's size, so it is read in one go; only `run` needs
# byte-exact streaming.
inventory() {{
    local command=$1 prefix=$2 empty=$3 response line shown=0
    response=$(printf '%s\n' "$command" | "$socat" -t "$wait_for_answer" - "UNIX-CONNECT:$sock" 2>/dev/null) ||
        unreachable
    while IFS= read -r line; do
        case $line in
            ok) break ;;
            'err '*) die "task: ${{line#err }}" 1 ;;
            "$prefix "*)
                shown=1
                line=${{line#"$prefix "}}
                printf '%s\n' "${{line//$'\t'/  }}"
                ;;
        esac
    done <<< "$response"
    [ "$shown" = 1 ] || printf '%s\n' "$empty"
    exit 0
}}

# Copy one length-framed stream from the response to a file descriptor. `-1` means the declaration
# hides that stream: nothing follows it, not even a framing newline. `head` reads exactly the
# announced count from the pipe, so the bytes reach the caller untouched — a payload carrying NUL or
# the protocol's own keywords is copied, never interpreted.
copy_stream() {{
    local len=$1 fd=$2
    [ "$len" = '-1' ] && return 0
    case $len in
        '' | *[!0-9]*) unreachable ;;
    esac
    if [ "$len" -gt 0 ]; then
        if [ "$fd" = 1 ]; then
            "$head" -c "$len" <&3
        else
            "$head" -c "$len" <&3 >&2
        fi
    fi
    # The payload is followed by a newline that frames it and is not part of it. An empty payload
    # still carries one, so it is consumed unconditionally and the next header line starts clean.
    IFS= read -r -u 3 _ || true
}}

run_task() {{
    local name='' kind kv key value i=0
    local kinds=() pairs=()
    while [ $# -gt 0 ]; do
        case $1 in
            --param | -p | --env | -e)
                case $1 in
                    --param | -p) kind=param ;;
                    *) kind=env ;;
                esac
                [ $# -ge 2 ] || die "task run: \`$1\` needs KEY=VALUE" 2
                kv=$2
                case $kv in
                    ?*=*) ;;
                    *) die "task run: \`$1 $kv\` is not KEY=VALUE" 2 ;;
                esac
                key=${{kv%%=*}}
                safe_word "$key" || die "task run: \`$key\` is not a usable name" 2
                kinds+=("$kind")
                pairs+=("$kv")
                shift 2
                ;;
            --session)
                # One plane is reachable from here, so the id is accepted and ignored.
                [ $# -ge 2 ] || die 'task run: `--session` needs a session id' 2
                shift 2
                ;;
            -*) die "task run: unexpected argument \"$1\"" 2 ;;
            *)
                [ -z "$name" ] || die "task run: unexpected argument \"$1\"" 2
                name=$1
                shift
                ;;
        esac
    done
    [ -n "$name" ] || die 'task run: name the operation to run' 2
    safe_word "$name" || die "task run: \`$name\` is not an operation name" 2

    # The whole request is known before any of the answer is, so it is written in one direction and
    # the reply read back from the same connection — no interleaving to get wrong.
    exec 3< <(
        {{
            printf 'RUN %s\n' "$name"
            i=0
            while [ "$i" -lt "${{#pairs[@]}}" ]; do
                kv=${{pairs[$i]}}
                value=${{kv#*=}}
                printf '%s %s %s\n' "${{kinds[$i]}}" "${{kv%%=*}}" "${{#value}}"
                printf '%s\n' "$value"
                i=$((i + 1))
            done
            printf 'run\n'
        }} | "$socat" -t "$wait_for_answer" - "UNIX-CONNECT:$sock" 2>/dev/null
    )

    local line complete=0 code=0 redacted=0 truncated=0 timed_out=0 elapsed=0 nonce='' refused=''
    while IFS= read -r -u 3 line; do
        case $line in
            ok) complete=1; break ;;
            'err '*)
                # A refusal is not the command failing: nothing ran. 125 keeps the two tellable
                # apart, the convention `env` uses for the same distinction.
                exec 3<&-
                die "task run: ${{line#err }}" 125
                ;;
            'exit '*) code=${{line#exit }} ;;
            'redacted '*) redacted=${{line#redacted }} ;;
            'truncated '*) truncated=${{line#truncated }} ;;
            'timed-out '*) timed_out=${{line#timed-out }} ;;
            'elapsed-ms '*) elapsed=${{line#elapsed-ms }} ;;
            'nonce '*) nonce=${{line#nonce }} ;;
            'refused-exec '*) refused="$refused${{line#refused-exec }}
" ;;
            'stdout '*) copy_stream "${{line#stdout }}" 1 ;;
            'stderr '*) copy_stream "${{line#stderr }}" 2 ;;
        esac
    done
    exec 3<&-
    # A response that stopped before `ok` was cut short; reporting the command's exit code from a
    # truncated answer would be inventing a result.
    [ "$complete" = 1 ] || truncated_answer

    [ "$timed_out" = 1 ] &&
        printf 'sbx: warning: the operation was killed at its timeout after %sms\n' "$elapsed" >&2
    [ "$truncated" = 1 ] &&
        printf 'sbx: warning: the output reached the operation'"'"'s `max_output` and was truncated\n' >&2
    # What the operation was not allowed to run. Said out loud because the refusal is invisible
    # otherwise: the program that was refused decides for itself whether to mention it, and many say
    # nothing — leaving an empty result that reads like a command that simply found nothing.
    if [ -n "$refused" ]; then
        printf 'sbx: warning: the operation was not allowed to run:\n' >&2
        printf '%s' "$refused" | while IFS= read -r target; do
            [ -n "$target" ] && printf '  %s\n' "$target" >&2
        done
        printf 'sbx: note: this operation declares `spawn`; a program it needs must be listed there.\n' >&2
    fi
    if [ "$redacted" != 0 ]; then
        if [ -n "$nonce" ]; then
            # With the nonce on, report it: a `${{NAME@nonce}}` in the text is unforgeable only
            # because the nonce arrives out of band, here.
            printf 'sbx: warning: %s credential value(s) were substituted out of the output (this invocation'"'"'s nonce is %s)\n' \
                "$redacted" "$nonce" >&2
        else
            printf 'sbx: warning: %s credential value(s) were substituted out of the output\n' "$redacted" >&2
        fi
    fi

    # The plane writes an integer here; anything else means a response this client cannot trust, so
    # it reports success rather than passing a word to `exit`. The clamp matches the host's: a
    # process returns one byte.
    [ "$code" -eq "$code" ] 2>/dev/null || code=0
    [ "$code" -lt 0 ] && code=0
    [ "$code" -gt 255 ] && code=255
    exit "$code"
}}

case ${{1-}} in
    task) shift ;;
    *)
        # The refusal is the DEFAULT branch, not a denylist: a verb this client has never heard of
        # is not exposed, so a new sbx subcommand cannot become reachable here by being added.
        printf 'sbx: only the task plane is exposed inside the sandbox — try `sbx task list`\n' >&2
        exit 2
        ;;
esac

case ${{1-}} in
    list | ls)
        shift
        check_inventory_args list "$@"
        inventory LIST task 'no declared operations'
        ;;
    secrets)
        shift
        check_inventory_args secrets "$@"
        inventory SECRETS secret 'no credentials are carried by the declared operations'
        ;;
    run)
        shift
        run_task "$@"
        ;;
    logs | log)
        # Host-only by construction: the recorded party does not get to read the record.
        die 'task logs: the invocation log is not readable from inside the cage' 2
        ;;
    -h | --help | help | '')
        usage
        exit 2
        ;;
    *) die "task: unknown subcommand \`$1\`" 2 ;;
esac
"##,
        bash = bash.display(),
        socket = quote(Path::new(socket)),
        socat = quote(socat),
        head = quote(head),
    )
}

/// Write the client at `path`, replacing any leftover, and make it executable and read-only.
///
/// Mode `0555`: it is bound read-only into the cage anyway, but a file the *host* side cannot
/// accidentally rewrite is one less way for the two to disagree.
pub(crate) fn write(
    path: &Path,
    bash: &Path,
    socat: &Path,
    head: &Path,
    socket: &str,
) -> io::Result<()> {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, render(bash, socat, head, socket))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rendered() -> String {
        render(
            Path::new("/store/bash/bin/bash"),
            Path::new("/store/socat/bin/socat"),
            Path::new("/store/coreutils/bin/head"),
            "/tmp/sbx-task.sock",
        )
    }

    // The shebang and every external command are absolute. The agent owns `PATH` inside the cage,
    // so a client that resolved any of them through it would be resolving through the adversary.
    #[test]
    fn every_program_the_client_runs_is_named_by_absolute_path() {
        let script = rendered();
        assert!(script.starts_with("#!/store/bash/bin/bash\n"), "{script}");
        assert!(
            script.contains("socat='/store/socat/bin/socat'"),
            "{script}"
        );
        assert!(
            script.contains("head='/store/coreutils/bin/head'"),
            "{script}"
        );
        // Nothing is invoked bare: the only command words are the quoted variables above.
        for bare in [" socat ", " head ", "$(socat", "`socat"] {
            assert!(
                !script.contains(bare),
                "a bare `{bare}` would resolve through the agent's PATH: {script}"
            );
        }
    }

    // The socket is baked in rather than read from the environment: the agent controls its own
    // environment, and a client that followed `$SBX_TASK_SOCKET` would follow whatever it was
    // pointed at.
    #[test]
    fn the_socket_is_baked_in_not_taken_from_the_environment() {
        let script = rendered();
        assert!(script.contains("sock='/tmp/sbx-task.sock'"), "{script}");
        assert!(
            !script.contains("SBX_TASK_SOCKET"),
            "the client must not resolve its socket through the environment: {script}"
        );
    }

    // The whole point of the split: no word but `task` reaches anything, and the refusal is the
    // default branch rather than a list of denied verbs — so a subcommand added to sbx tomorrow
    // cannot become reachable here by omission.
    #[test]
    fn the_client_exposes_the_task_plane_and_refuses_every_other_word() {
        let script = rendered();
        // The first `case` is the whole gate. Read it back and check what it can match: `task`,
        // and a catch-all that refuses. Anything else appearing here would be a second door.
        let gate = script
            .split_once("case ${1-} in")
            .and_then(|(_, rest)| rest.split_once("esac"))
            .map(|(gate, _)| gate)
            .expect("the client opens with the top-level gate");
        let labels: Vec<&str> = gate
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_suffix(')')
                    .or_else(|| l.trim().split_once(')').map(|(head, _)| head))
            })
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(
            labels,
            vec!["task", "*"],
            "the gate must admit `task` and refuse everything else: {gate}"
        );
        assert!(
            gate.contains("only the task plane is exposed"),
            "the refusal must say what is and is not here: {gate}"
        );
    }

    // Byte semantics are load-bearing: `${#value}` announces the length the wire reads back, and
    // under a UTF-8 locale it would count characters and desynchronise the stream.
    #[test]
    fn the_client_pins_byte_semantics_for_payload_lengths() {
        let script = rendered();
        assert!(script.contains("LC_ALL=C"), "{script}");
        assert!(script.contains("${#value}"), "{script}");
    }

    // A path carrying a quote must not be able to end the string it is interpolated into.
    #[test]
    fn an_interpolated_path_cannot_escape_its_quoting() {
        let quoted = quote(&PathBuf::from("/store/it's/bin/socat"));
        assert_eq!(quoted, r"'/store/it'\''s/bin/socat'");
    }

    // The client is executable and not writable: it is bound read-only into the cage, and a host
    // side that cannot rewrite it either is one fewer way for the two ends to disagree.
    #[test]
    fn the_written_client_is_executable_and_read_only() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("task-client");
        write(
            &path,
            Path::new("/store/bash/bin/bash"),
            Path::new("/store/socat/bin/socat"),
            Path::new("/store/coreutils/bin/head"),
            "/tmp/sbx-task.sock",
        )
        .expect("write the client");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o555, "mode was {mode:o}");
    }
}
