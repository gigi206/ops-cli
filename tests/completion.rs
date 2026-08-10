//! Integration tests for `sbx completion <shell>` and the hidden `__complete` oracle.
//!
//! Two properties matter here and neither is visible to a unit test. First, **silence**: a
//! completion script is `eval`'d at shell startup and its oracle runs on every completion
//! request, so a stray byte on either stream would corrupt the eval or spatter the user's
//! prompt. Second, the emitted text has to be **valid shell** and actually complete something
//! — a script that parses and completes nothing looks identical to a working one until a
//! human presses Tab. The bash case is therefore driven for real (`COMPREPLY` is inspected),
//! and the zsh case is checked to register itself with the completion system.
//!
//! Shell-driven cases skip, rather than fail, where the shell is not installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sbx(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .output()
        .expect("spawn sbx")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The directory holding the test binary, so a driven shell finds `sbx` on its `PATH` —
/// the emitted scripts call the command by name, exactly as an installed one would.
fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_sbx"))
        .parent()
        .expect("binary directory")
        .to_path_buf()
}

/// A unique scratch directory for one test, removed by the caller.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sbx-completion-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

/// The candidate names the oracle offers after `path`, for the given cursor word.
fn oracle(path: &[String], cursor: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec!["__complete".into(), "--".into()];
    argv.extend(path.iter().cloned());
    argv.push(cursor.to_string());
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    stdout_of(&sbx(&borrowed))
        .lines()
        .filter_map(|l| l.split('\t').next().map(str::to_string))
        .collect()
}

/// Every command path the binary's completion can reach, found by walking it from the root.
///
/// The sweeps below run over this rather than over a list kept by hand, so they cover
/// whatever the binary actually offers: a subcommand added tomorrow is swept the day it
/// lands. The `help` verb mirrors the whole tree beneath itself, so the walk covers each
/// path twice, once directly and once through `sbx help ...`.
///
/// Only names that resolve to a page are descended into: the menus also hold value
/// vocabulary — live ids, literal targets — that is machine state, not command tree, and
/// walking into it would loop on a real registry the moment one exists.
fn walk() -> Vec<Vec<String>> {
    /// Whether a path names a page, and so is command tree rather than a value.
    ///
    /// A leading `help` is stripped before asking, because it is exactly what the page
    /// tree does not contain: `sbx help` has no page of its own (`sbx help help` is
    /// refused), so probing the path verbatim would answer "not a page" for `help` and
    /// prune the mirrored half of the tree — the half this walk exists to cover.
    fn is_page(path: &[String]) -> bool {
        let under_help = path.first().is_some_and(|w| w == "help");
        let probed: Vec<&str> = path
            .iter()
            .skip(usize::from(under_help))
            .map(String::as_str)
            .collect();
        // `sbx help` itself: a real verb, and the root of the mirror.
        if probed.is_empty() {
            return under_help;
        }
        let mut argv = vec!["help"];
        argv.extend(probed.iter().copied());
        let out = sbx(&argv);
        out.status.success() && stdout_of(&out).contains(&format!("sbx {} —", probed.join(" ")))
    }
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut queue: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(path) = queue.pop() {
        // A tree this deep would mean the walk is looping, not that the CLI grew: stop loudly
        // rather than spin (an earlier `help` that offered itself did exactly that).
        assert!(path.len() < 6, "the completion tree loops at {path:?}");
        for child in oracle(&path, "") {
            let mut deeper = path.clone();
            deeper.push(child);
            if !is_page(&deeper) {
                continue;
            }
            queue.push(deeper.clone());
            found.push(deeper);
        }
    }
    found
}

/// One line per case for a shell driver: `expected US cursor US words-before-the-cursor`.
///
/// The field separator is the ASCII unit separator, not a tab: a tab is IFS *whitespace*, so
/// both shells collapse a run of them into one delimiter and drop the empty cursor field,
/// silently shifting every column by one.
const US: char = '\x1f';

fn cases(paths: &[Vec<String>]) -> String {
    let mut out = String::new();
    for path in paths {
        let (name, parent) = path.split_last().expect("a walked path is never empty");
        // The name is offered where it belongs, from an empty cursor word.
        out.push_str(&format!("{name}{US}{US}{}\n", parent.join(" ")));
        // And the flags of that command are reachable: every page accepts `--help`.
        out.push_str(&format!("--help{US}-{US}{}\n", path.join(" ")));
    }
    out
}

fn shell_available(shell: &str) -> bool {
    Command::new(shell)
        .arg("-c")
        .arg("exit 0")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run a script through `shell`, with the sbx under test first on `PATH`.
fn run_shell(shell: &str, script: &str) -> Output {
    let path = match std::env::var_os("PATH") {
        Some(p) => format!("{}:{}", bin_dir().display(), p.to_string_lossy()),
        None => bin_dir().display().to_string(),
    };
    Command::new(shell)
        .arg("-c")
        .arg(script)
        .env("PATH", path)
        .output()
        .unwrap_or_else(|e| panic!("spawn {shell}: {e}"))
}

#[test]
fn every_supported_shell_emits_a_script_in_silence() {
    for shell in ["bash", "zsh"] {
        let out = sbx(&["completion", shell]);
        assert!(
            out.status.success(),
            "`sbx completion {shell}` should exit 0"
        );
        assert!(
            !out.stdout.is_empty(),
            "`sbx completion {shell}` emitted nothing"
        );
        // The script is `eval`'d: anything on stderr lands in the user's terminal at shell
        // startup, and anything unexpected on stdout is evaluated as shell code.
        assert!(
            out.stderr.is_empty(),
            "`sbx completion {shell}` wrote to stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn the_oracle_answers_in_silence() {
    // Called on every completion request, so silence on stderr is load-bearing, and the
    // answer must be one plain `name<TAB>description` line per candidate.
    let out = sbx(&["__complete", "--", ""]);
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "the oracle wrote to stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = stdout_of(&out);
    assert!(stdout.lines().count() > 10, "expected the command list");
    for line in stdout.lines() {
        assert_eq!(
            line.matches('\t').count(),
            1,
            "a candidate line carries exactly one separator: {line:?}"
        );
        let name = line.split('\t').next().unwrap();
        assert!(!name.is_empty(), "empty candidate in {line:?}");
        assert!(
            !name.contains(' '),
            "a candidate is a single word: {name:?}"
        );
    }
    let names: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split('\t').next())
        .collect();
    assert!(names.contains(&"run"));
    assert!(names.contains(&"completion"));
}

#[test]
fn the_oracle_narrows_as_the_path_deepens() {
    let names = |args: &[&str]| -> Vec<String> {
        let mut argv = vec!["__complete", "--"];
        argv.extend_from_slice(args);
        stdout_of(&sbx(&argv))
            .lines()
            .filter_map(|l| l.split('\t').next().map(str::to_string))
            .collect()
    };
    assert!(names(&["app", ""]).contains(&"import".to_string()));
    assert_eq!(names(&["plugins", "store", "publ"]), ["publish"]);
    assert!(names(&["run", "--det"]).contains(&"--detach".to_string()));
    // Past a `--` the words belong to the launched command: none of sbx's own names, and
    // the file marker rather than an empty answer, so the shell completes that word.
    assert_eq!(names(&["run", "--", ""]), ["__sbx_files__"]);
    assert_eq!(names(&["run", "--", "ls", ""]), ["__sbx_files__"]);
}

#[test]
fn an_unsupported_shell_is_refused_by_name() {
    // Fail closed: emitting nothing, or a bash script for an unknown shell, would leave the
    // user with a silently broken completion instead of an answer.
    let out = sbx(&["completion", "fish"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "nothing may be emitted for a refusal"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("fish"), "the refusal must name the shell");
    assert!(stderr.contains("bash") && stderr.contains("zsh"));

    // No shell at all shows the page, and a second operand is rejected rather than ignored.
    assert_eq!(sbx(&["completion"]).status.code(), Some(2));
    assert_eq!(sbx(&["completion", "bash", "zsh"]).status.code(), Some(2));

    // A help flag is not a shell name: it is intercepted before the verb runs, so it shows
    // the page rather than being refused as an unsupported shell called `--help`.
    let help = sbx(&["completion", "--help"]);
    assert!(
        help.status.success(),
        "`sbx completion --help` should exit 0"
    );
    assert!(stdout_of(&help).contains("sbx completion —"));
}

#[test]
fn the_bash_script_parses_and_completes() {
    if !shell_available("bash") {
        eprintln!("skipping bash completion drive: bash is not installed");
        return;
    }
    let script = stdout_of(&sbx(&["completion", "bash"]));
    let dir = std::env::temp_dir().join(format!("sbx-completion-bash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let path = dir.join("sbx.bash");
    std::fs::write(&path, &script).expect("write script");

    // Valid shell first: a syntax error would make every assertion below meaningless.
    let syntax = run_shell("bash", &format!("bash -n {}", path.display()));
    assert!(
        syntax.status.success(),
        "the emitted bash script does not parse: {}",
        String::from_utf8_lossy(&syntax.stderr)
    );

    // Then drive the real completion function the way bash does: set the words and the
    // cursor index, call it, and read back what it offered.
    let drive = |words: &[&str], cword: usize| -> Vec<String> {
        let quoted: Vec<String> = words.iter().map(|w| format!("'{w}'")).collect();
        let out = run_shell(
            "bash",
            &format!(
                "source {}; COMP_WORDS=({}); COMP_CWORD={cword}; \
                 _sbx_complete; printf '%s\\n' \"${{COMPREPLY[@]}}\"",
                path.display(),
                quoted.join(" ")
            ),
        );
        assert!(
            out.status.success(),
            "driving the function failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout_of(&out)
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    };

    // A bare prefix completes commands; an empty cursor word lists them all.
    assert_eq!(drive(&["sbx", "comp"], 1), ["completion"]);
    assert!(drive(&["sbx", ""], 1).contains(&"run".to_string()));
    // A subcommand, then a flag.
    assert!(drive(&["sbx", "app", "imp"], 2).contains(&"import".to_string()));
    assert!(drive(&["sbx", "run", "--det"], 2).contains(&"--detach".to_string()));
    // Three levels deep.
    assert_eq!(drive(&["sbx", "plugins", "store", "rek"], 3), ["rekey"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_path_position_completes_files_in_a_real_bash() {
    if !shell_available("bash") {
        eprintln!("skipping the bash file-completion drive: bash is not installed");
        return;
    }
    let dir = scratch("bash-files");
    let script = dir.join("sbx.bash");
    std::fs::write(&script, stdout_of(&sbx(&["completion", "bash"]))).expect("write script");
    std::fs::write(dir.join("plain.toml"), b"").expect("a fixture file");
    // A name holding a space: the case word splitting quietly turns into two candidates.
    std::fs::write(dir.join("spaced name.toml"), b"").expect("a fixture file");

    let drive = |words: &[&str], cword: usize| -> Vec<String> {
        let quoted: Vec<String> = words.iter().map(|w| format!("'{w}'")).collect();
        let out = run_shell(
            "bash",
            &format!(
                "cd {dir}; source {script}; COMP_WORDS=({words}); COMP_CWORD={cword}; \
                 _sbx_complete; printf '%s\\n' \"${{COMPREPLY[@]}}\"",
                dir = dir.display(),
                script = script.display(),
                words = quoted.join(" ")
            ),
        );
        assert!(
            out.status.success(),
            "driving the function failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout_of(&out)
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    };

    // `--config <toml|@file>` names a path sbx cannot enumerate, so the marker hands the
    // word to bash. One file, one candidate — the space must not split it in two.
    assert_eq!(
        drive(&["sbx", "run", "--config", "spaced"], 3),
        ["spaced name.toml"]
    );
    // Past a `--` the line belongs to the launched command. Answering nothing there would
    // leave `sbx run -- ls <TAB>` completing nothing at all, so the word is the shell's.
    assert_eq!(drive(&["sbx", "run", "--", "ls", "pl"], 4), ["plain.toml"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_path_position_reaches_zshs_own_file_completion() {
    if !shell_available("zsh") {
        eprintln!("skipping the zsh file-completion drive: zsh is not installed");
        return;
    }
    let dir = scratch("zsh-files");
    let script = dir.join("_sbx");
    std::fs::write(&script, stdout_of(&sbx(&["completion", "zsh"]))).expect("write script");

    // `_files` is zsh's own file completion and needs a real completion context, which a
    // driven function does not have, so it stands in for itself here. What that still pins
    // is the half this script owns, and the half whose shape differs from bash's: the
    // marker branch is reached from *inside* the loop reading the oracle, and it hands the
    // word over rather than rendering the marker as a candidate. The bash sibling above
    // drives the real file completion end to end.
    let driver = format!(
        r#"
        compdef() {{ : }}
        _files() {{ print -r -- FILES }}
        _describe() {{ local n=${{@[-1]}}; local -a a; a=( ${{(P)n}} ); print -rl -- ${{a%%:*}} }}
        source {script}
        drive() {{ words=(sbx "$@"); CURRENT=${{#words}}; _sbx }}
        print -r -- "config=$(drive run --config spa)"
        print -r -- "dashdash=$(drive run -- ls pl)"
        print -r -- "verb=$(drive comp)"
        "#,
        script = script.display()
    );
    let out = run_shell("zsh", &driver);
    let stdout = stdout_of(&out);
    let says = |line: &str| stdout.lines().any(|l| l == line);
    // A path a flag names, and every word past a `--`, are zsh's to complete.
    assert!(
        says("config=FILES"),
        "`--config` did not reach _files:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        says("dashdash=FILES"),
        "the line past a `--` did not reach _files:\n{stdout}"
    );
    // A command position still completes verbs, and never reaches file completion.
    assert!(says("verb=completion"), "a verb position broke:\n{stdout}");
    // The marker is an instruction, never something the user can be offered.
    assert!(
        !stdout.contains("__sbx_files__"),
        "the marker leaked into the menu:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_zsh_script_parses_and_registers_itself() {
    if !shell_available("zsh") {
        eprintln!("skipping zsh completion check: zsh is not installed");
        return;
    }
    let script = stdout_of(&sbx(&["completion", "zsh"]));
    let dir = std::env::temp_dir().join(format!("sbx-completion-zsh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let path = dir.join("_sbx");
    std::fs::write(&path, &script).expect("write script");

    let syntax = run_shell("zsh", &format!("zsh -n {}", path.display()));
    assert!(
        syntax.status.success(),
        "the emitted zsh script does not parse: {}",
        String::from_utf8_lossy(&syntax.stderr)
    );

    // Sourced into a shell whose completion system is up, the script must define `_sbx` and
    // bind it to the `sbx` command — the half a `zsh -n` cannot see. `compinit -u -d` keeps
    // the run off the user's own dump and skips the insecure-directory prompt.
    let out = run_shell(
        "zsh",
        &format!(
            "autoload -U compinit && compinit -u -d {dump}; source {script}; \
             print -r -- \"defined=${{+functions[_sbx]}} bound=${{_comps[sbx]}}\"",
            dump = dir.join("zcompdump").display(),
            script = path.display()
        ),
    );
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("defined=1"),
        "the script must define _sbx: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("bound=_sbx"),
        "the script must bind _sbx to the sbx command: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- exhaustive sweeps over the whole command tree ---------------------------------
//
// The tests above pin the shapes that matter one at a time. These three walk the tree the
// binary actually offers and assert the property for every path in it, in the real shells.

#[test]
fn the_completion_tree_and_the_help_tree_are_the_same_tree() {
    // Completion is only trustworthy if what it offers is what the CLI accepts. Every name
    // the walk reaches must resolve to a real page, so a candidate can never name a command
    // that does not exist.
    let paths = walk();
    assert!(
        paths.len() > 150,
        "the walk found only {} paths — did it stop early?",
        paths.len()
    );
    let mut checked = 0;
    for path in &paths {
        // `help` is a real verb with no page of its own; under it the tree is mirrored, so
        // the page to look for is the one for the rest of the path.
        let effective: Vec<&str> = path
            .iter()
            .map(String::as_str)
            .skip_while(|w| *w == "help")
            .collect();
        if effective.is_empty() {
            continue; // the bare `help` verb itself
        }
        let mut argv = vec!["help"];
        argv.extend(effective.iter().copied());
        let out = sbx(&argv);
        assert!(
            out.status.success(),
            "completion offers `sbx {}` but there is no page for it",
            path.join(" ")
        );
        assert!(
            stdout_of(&out).contains(&format!("sbx {} —", effective.join(" "))),
            "`sbx {}` rendered the wrong page",
            argv.join(" ")
        );
        checked += 1;
    }
    assert!(checked > 150, "only {checked} paths cross-checked");
}

#[test]
fn every_command_path_completes_in_a_real_bash() {
    if !shell_available("bash") {
        eprintln!("skipping the bash sweep: bash is not installed");
        return;
    }
    let dir = scratch("bash-sweep");
    let script = dir.join("sbx.bash");
    std::fs::write(&script, stdout_of(&sbx(&["completion", "bash"]))).expect("write script");
    let paths = walk();
    let case_file = dir.join("cases.tsv");
    std::fs::write(&case_file, cases(&paths)).expect("write cases");

    // One bash process for the whole sweep: sourcing the script once and driving the
    // function per case, exactly as bash does on a keypress.
    let driver = format!(
        r#"
        source {script}
        bad=0; n=0
        while IFS=$'\x1f' read -r expected cursor parent; do
            read -ra ws <<< "$parent"
            COMP_WORDS=(sbx "${{ws[@]}}" "$cursor")
            COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
            COMPREPLY=()
            _sbx_complete
            hit=0
            for c in "${{COMPREPLY[@]}}"; do
                [ "$c" = "$expected" ] && hit=1 && break
            done
            if [ $hit -eq 0 ]; then
                echo "MISS: '$expected' after 'sbx $parent' with cursor '$cursor'"
                bad=1
            fi
            n=$((n+1))
        done < {cases}
        echo "CHECKED=$n"
        [ $bad -eq 0 ] && echo SWEEP_OK
        "#,
        script = script.display(),
        cases = case_file.display()
    );
    let out = run_shell("bash", &driver);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("SWEEP_OK"),
        "bash sweep failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let checked: usize = stdout
        .lines()
        .find_map(|l| l.strip_prefix("CHECKED="))
        .and_then(|n| n.parse().ok())
        .expect("the driver reports how many cases it ran");
    assert_eq!(checked, paths.len() * 2, "the driver skipped cases");
    assert!(checked > 300, "only {checked} bash cases run");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_command_path_completes_in_a_real_zsh() {
    if !shell_available("zsh") {
        eprintln!("skipping the zsh sweep: zsh is not installed");
        return;
    }
    let dir = scratch("zsh-sweep");
    let script = dir.join("_sbx");
    std::fs::write(&script, stdout_of(&sbx(&["completion", "zsh"]))).expect("write script");
    let paths = walk();
    let case_file = dir.join("cases.tsv");
    std::fs::write(&case_file, cases(&paths)).expect("write cases");

    // Driving `_sbx` outside a real completion context means standing in for the three
    // completion-system entry points it uses. `_describe` receives the *name* of the
    // candidate array as its last argument, and each entry is `name:description`.
    let driver = format!(
        r#"
        compdef() {{ : }}
        _files() {{ : }}
        _describe() {{ local n=${{@[-1]}}; local -a a; a=( ${{(P)n}} ); print -rl -- ${{a%%:*}} }}
        source {script}
        bad=0; n=0
        while IFS=$'\x1f' read -r expected cursor parent; do
            ws=(${{=parent}})
            words=(sbx $ws "$cursor")
            CURRENT=${{#words}}
            got=(${{(f)"$(_sbx)"}})
            if (( ${{got[(I)$expected]}} == 0 )); then
                print -r -- "MISS: '$expected' after 'sbx $parent' with cursor '$cursor'"
                bad=1
            fi
            n=$((n+1))
        done < {cases}
        print -r -- "CHECKED=$n"
        (( bad == 0 )) && print -r -- SWEEP_OK
        "#,
        script = script.display(),
        cases = case_file.display()
    );
    let out = run_shell("zsh", &driver);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("SWEEP_OK"),
        "zsh sweep failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let checked: usize = stdout
        .lines()
        .find_map(|l| l.strip_prefix("CHECKED="))
        .and_then(|n| n.parse().ok())
        .expect("the driver reports how many cases it ran");
    assert_eq!(checked, paths.len() * 2, "the driver skipped cases");
    assert!(checked > 300, "only {checked} zsh cases run");

    let _ = std::fs::remove_dir_all(&dir);
}
