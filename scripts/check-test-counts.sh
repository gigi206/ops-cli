#!/bin/bash
# Verify (or update) the test counts in README.md.
#
# Counts the @test lines per `tests/*.bats` file and compares against the
# values declared in the README's `### Files` block plus the total
# `**N tests across M files.**` line.
#
# Usage:
#   scripts/check-test-counts.sh           # exit 0 if in sync, 1 otherwise
#   scripts/check-test-counts.sh --update  # rewrite the README values in-place
#
# CI calls the bare form so a contributor who adds a test without touching
# the README fails the build instead of letting the doc drift unnoticed.

set -euo pipefail

# `for f in dir/*.bats` would otherwise pass the literal `dir/*.bats` to
# grep when the directory is empty, and `set -e` would abort the script
# instead of reporting "0 tests across 0 files". nullglob expands a
# non-matching glob to zero arguments, which the loop handles gracefully.
shopt -s nullglob

# Resolve symlinks so the script works when invoked through one (e.g.
# /usr/local/bin/check-test-counts → …/scripts/check-test-counts.sh).
# Mirrors the SCRIPT_DIR=readlink-f convention in ops.sh.
script_path="$(readlink -f "$0" 2>/dev/null || echo "$0")"
repo_root="$(cd "$(dirname "$script_path")/.." && pwd)"
readme="$repo_root/README.md"
tests_dir="$repo_root/tests"

mode="check"
[ "${1:-}" = "--update" ] && mode="update"

if [ ! -f "$readme" ]; then
    echo "check-test-counts: $readme not found" >&2
    exit 2
fi
if [ ! -d "$tests_dir" ]; then
    echo "check-test-counts: $tests_dir not found" >&2
    exit 2
fi

# ---- compute reality ------------------------------------------------------

total=0
file_count=0
declare -A real_counts=()
for f in "$tests_dir"/*.bats; do
    base="$(basename "$f")"
    n=$(grep -c '^@test ' "$f" || true)
    real_counts[$base]=$n
    total=$((total + n))
    file_count=$((file_count + 1))
done

# ---- verify / update the README -------------------------------------------

errors=0

# 1. Per-file lines: `├── <name>.bats <padding> — N tests:`
#    or `└── <name>.bats … — N integration tests …`
update_file_line() {
    local base="$1" expected="$2"
    # Match "<name>.bats" then any padding to the em-dash, then a number
    # followed by " test" (singular or plural) — "tests:" / "tests" /
    # "integration tests".
    local pattern="^(├── |└── )${base//./\\.}([[:space:]]+— )([0-9]+)( (integration )?tests?)"
    local current
    current=$(grep -E "$pattern" "$readme" | head -1 || true)
    if [ -z "$current" ]; then
        return 0  # file not listed in README — silently ignore (helpers.bash etc.)
    fi
    local actual_n
    actual_n=$(echo "$current" | sed -E "s/$pattern.*/\3/")
    if [ "$actual_n" = "$expected" ]; then
        return 0
    fi
    if [ "$mode" = "update" ]; then
        # Replace just the count digits, preserving the surrounding format
        # (the box-drawing prefix, padding to the em-dash, the suffix).
        # Use `#` as the s/// delimiter (not `|`) because the alternation
        # `(├── |└── )` in the pattern contains a literal `|` — with `|`
        # as the delimiter sed terminates the pattern at the first `|`
        # and aborts with "option inconnue pour « s »". `#` doesn't
        # appear in any of the box-drawing / em-dash / digit / tests
        # tokens we match, so it's safe.
        sed -i -E "s#^(├── |└── )(${base//./\\.})([[:space:]]+— )([0-9]+)( (integration )?tests?)#\1\2\3${expected}\5#" "$readme"
        echo "  updated: $base $actual_n → $expected"
    else
        echo "  drift: $base actual=${expected} README=${actual_n}"
        errors=$((errors + 1))
    fi
}

for base in "${!real_counts[@]}"; do
    update_file_line "$base" "${real_counts[$base]}"
done

# 2. Total line: `**N tests across M files.**`
total_pattern='^\*\*[0-9]+ tests across [0-9]+ files\.\*\*'
current_total_line=$(grep -E "$total_pattern" "$readme" | head -1 || true)
if [ -n "$current_total_line" ]; then
    actual_total=$(echo "$current_total_line" | sed -E 's/^\*\*([0-9]+) tests across ([0-9]+) files\.\*\*.*/\1/')
    actual_files=$(echo "$current_total_line" | sed -E 's/^\*\*([0-9]+) tests across ([0-9]+) files\.\*\*.*/\2/')
    if [ "$actual_total" != "$total" ] || [ "$actual_files" != "$file_count" ]; then
        if [ "$mode" = "update" ]; then
            sed -i -E "s|^\*\*[0-9]+ tests across [0-9]+ files\.\*\*|**${total} tests across ${file_count} files.**|" "$readme"
            echo "  updated: total ${actual_total}/${actual_files} → ${total}/${file_count}"
        else
            echo "  drift: total actual=${total}/${file_count} README=${actual_total}/${actual_files}"
            errors=$((errors + 1))
        fi
    fi
else
    echo "  warning: total line not found in $readme (looked for '**N tests across M files.**')"
fi

# ---- summary --------------------------------------------------------------

if [ "$mode" = "update" ]; then
    echo "Test counts in README.md updated."
    exit 0
fi
if [ "$errors" -gt 0 ]; then
    echo
    echo "Test counts in README.md are out of date ($errors discrepancies)."
    echo "Re-run with --update to fix:"
    echo "    scripts/check-test-counts.sh --update"
    exit 1
fi
echo "Test counts in README.md match reality (${total} tests across ${file_count} files)."
exit 0
