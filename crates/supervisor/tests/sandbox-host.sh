#!/bin/sh
# Tests du bac à sable des workers (L06) SUR L'HÔTE : espaces de noms utilisateur, landlock,
# seccomp et cgroup v2 délégué. Depuis le flatpak de développement :
#
#   host-spawn sh crates/supervisor/tests/sandbox-host.sh
#
# Chaque binaire de test tourne SEUL dans un scope systemd utilisateur délégué (Delegate=yes) :
# le superviseur doit pouvoir se placer dans une feuille et activer memory/pids/cpu pour ses
# workers, ce qu'un cgroup partagé avec cargo interdit. Cible de compilation hors de /tmp.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/synco-l06-host-target}"
case "$CARGO_TARGET_DIR" in
/tmp/*) echo "refus : CARGO_TARGET_DIR sous /tmp" >&2; exit 2 ;;
esac
cd "$ROOT"
cargo build -q -p synco-ai-runtime --bin synco-ai-runtime
test_bin() {
    cargo test -q -p synco-ai-runtime --test "$1" --no-run --message-format=json 2>/dev/null |
        sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
}
SANDBOX=$(test_bin sandbox)
INTEGRATION=$(test_bin integration)
echo "== tests/sandbox.rs (tous, y compris #[ignore])"
systemd-run --user --scope -q -p Delegate=yes "$SANDBOX" --include-ignored --test-threads=1 --nocapture
echo "== tests/integration.rs : aller-retour client -> superviseur -> worker isolé"
systemd-run --user --scope -q -p Delegate=yes "$INTEGRATION" --ignored aller_retour_avec_bac_a_sable --nocapture
