#!/bin/sh
# Mesure : une cage bubblewrap sans `--new-session` conserve-t-elle le terminal de
# contrôle du lanceur ? Trois bras, dont un témoin. Les drapeaux reproduisent ceux que
# `src/sandbox/mise.rs` et `src/storage.rs` assemblent à la main.
#
# Le shell d'un agent n'a pas de terminal de contrôle (`tty_nr=0`), d'où `script`, qui en
# fabrique un : sans lui les trois bras répondent la même chose et la mesure ne dit rien.
#
# Résultat au 2026-09-06, avant correctif : le bras B rend le même `tty_nr` que le témoin,
# ouvre `/dev/tty` et écrit dessus ; le bras C rend `tty_nr=0` et refuse les deux.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/probe.sh" <<'EOF'
#!/bin/sh
read -r line < /proc/self/stat
set -- $line
printf 'tty_nr=%s  ' "$7"
if (exec </dev/tty) 2>/dev/null; then printf 'ouvrir=OUI  '; else printf 'ouvrir=non  '; fi
if (echo "ECRITURE-DEPUIS-LA-CAGE" >/dev/tty) 2>/dev/null; then printf 'ecrire=OUI\n'; else printf 'ecrire=non\n'; fi
EOF
chmod +x "$work/probe.sh"
binds="--ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind $work $work"
flags="--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup --clearenv --die-with-parent --cap-drop ALL --proc /proc --dev /dev --tmpfs /tmp"
echo "A. témoin, sous un pty, sans cage"
script -qec "$work/probe.sh" /dev/null
echo "B. cage aux drapeaux de mise/storage, sans --new-session"
script -qec "bwrap $flags $binds -- $work/probe.sh" /dev/null
echo "C. la même, avec --new-session"
script -qec "bwrap $flags --new-session $binds -- $work/probe.sh" /dev/null
