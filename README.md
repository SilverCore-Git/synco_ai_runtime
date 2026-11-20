# Synco AI Runtime

Service **auto-hébergé** qui fait tourner les conversations Synco AI en arrière-plan, chez le client : chaque conversation
basculée en mode runtime s'exécute dans un **worker isolé** (un processus par conversation, sans accès disque ni réseau),
et continue même quand l'utilisateur a fermé Synco. Le runtime détient ses propres clés : Synco ne voit jamais le contenu
des conversations.

## Rôle

```
navigateur (app Synco) ── wss:// ──▶ mandataire TLS ──▶ superviseur ──▶ worker isolé (1 / conversation)
                                      (nginx, Caddy)        │                │ (aucun réseau, aucun disque)
                                                            │                └─▶ mandataire LLM du superviseur ─▶ fournisseur / passerelle
                                                            └─ requêtes signées ─▶ API Synco
```

- **Superviseur** (`synco-ai-runtime`) : clés (scellées au repos), appairage, canal signé vers l'API, WebSocket des clients,
  lancement des workers, dashboard de l'administrateur.
- **Worker** : même binaire, relancé par le superviseur dans un bac à sable (espaces de noms, seccomp, landlock, cgroup v2).
  Il ne reçoit que les clés de **sa** conversation et n'appelle le LLM que par le mandataire du superviseur, qui ajoute lui-même
  la clé du fournisseur.
- Spécification complète : [`docs/plan/`](docs/plan/00-vue-ensemble.md). Bac à sable : [`docs/plan/10-bac-a-sable.md`](docs/plan/10-bac-a-sable.md).

## Installation rapide (Podman, chemin officiel)

Prérequis : Linux ≥ 5.14, cgroups v2 (`cpu`, `memory`, `pids`), espaces de noms utilisateur, Podman ≥ 5, un nom DNS avec un
**certificat TLS reconnu** devant le runtime ([prérequis détaillés](docs/deploiement.md#1-prérequis)).

```bash
podman build --format docker -t localhost/synco-ai-runtime:latest .
mkdir -p ~/.config/synco-ai-runtime ~/.config/containers/systemd
cp deploy/config.container.example.toml ~/.config/synco-ai-runtime/config.toml      # à adapter
PP=$(head -c 32 /dev/urandom | base64 | tr -d '\n'); echo "À noter dans un coffre : $PP"
printf '%s' "$PP" | podman secret create synco-ai-runtime-passphrase - ; unset PP      # modèle de menace : docs/deploiement.md §2.2
cp deploy/podman/synco-ai-runtime.container deploy/podman/synco-ai-runtime-state.volume ~/.config/containers/systemd/
systemctl --user daemon-reload && systemctl --user start synco-ai-runtime.service && loginctl enable-linger "$USER"

podman exec synco-ai-runtime synco-ai-runtime pair        # URL, empreinte, code d'appairage → à saisir dans Synco
podman exec -it synco-ai-runtime synco-ai-runtime dashboard-password
```

Puis : mandataire inverse **TLS obligatoire** ([`deploy/nginx/`](deploy/nginx/synco-ai-runtime.conf),
[`deploy/caddy/`](deploy/caddy/Caddyfile)), dans Synco *Paramètres de l'organisation → Synco AI → Runtime* : URL et code ;
**comparer l'empreinte** affichée par Synco avec celle du terminal.

| Je veux… | Voir |
|---|---|
| Tout le guide (prérequis, appairage, mise à jour, sauvegarde de la clé, désappairage, pièges réseau) | [`docs/deploiement.md`](docs/deploiement.md) |
| Docker (variante avancée, **non testée, non prise en charge en l'état** : seccomp et AppArmor dédiés, cgroup délégué) | [`docs/deploiement.md §3`](docs/deploiement.md#3-docker-variante-avancée) |
| Sans conteneur (systemd, `LoadCredentialEncrypted=`, `Delegate=yes`) | [`docs/deploiement.md §4`](docs/deploiement.md#4-systemd-sans-conteneur), [`unité`](crates/supervisor/systemd/synco-ai-runtime.service) |
| Compose, avec la passerelle Synco AI et Ollama | [`compose.example.yml`](compose.example.yml) |
| Recette manuelle de la porte C | [`docs/recette-porte-c.md`](docs/recette-porte-c.md) |
| Toutes les options de configuration | [`crates/supervisor/synco-ai-runtime.example.toml`](crates/supervisor/synco-ai-runtime.example.toml), [README du superviseur](crates/supervisor/README.md) |

### Capacités et options du conteneur

L'image est unique (un binaire, utilisateur `10001`, `/tmp` présent, superviseur processus 1 sans script d'entrée). Le
conteneur tourne avec `--read-only`, `--cap-drop=all`, **une seule capacité** (`DAC_OVERRIDE`, pour écrire dans son propre cgroup),
`no-new-privileges`, `unmask=/sys/fs/cgroup` (cgroup privé inscriptible) et, sur un hôte SELinux, `label=disable`.
**Jamais `--privileged`**, jamais le `/sys/fs/cgroup` de l'hôte. Chaque option est justifiée dans
[`docs/deploiement.md §2.1`](docs/deploiement.md#21-pourquoi-ces-options-une-à-une).

### Pièges réseau (résumé)

HTTPS obligatoire (contenu mixte bloqué), certificat **reconnu** y compris sur mobile (l'auto-signé ne fonctionne pas), CORS géré
par le runtime (`allowed_origins`), et **un runtime limité à l'intranet n'est pas joignable hors réseau** : pas de relais par l'API en
v1 (D10), mode dégradé côté app. Détails : [`docs/deploiement.md §8`](docs/deploiement.md#8-pièges-réseau).

## Développement

```bash
cargo fmt --all --check                           # toolchain épinglée par rust-toolchain.toml (1.98.1)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
host-spawn sh crates/supervisor/tests/sandbox-host.sh   # tests du bac à sable SUR L'HÔTE (flatpak de développement)
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) : fmt, clippy, tests, `cargo-audit` (version épinglée), contrôle des
secrets, construction de l'image. Journal des lots : [`docs/journal.md`](docs/journal.md).

## Hook git (secrets)

Le dépôt est public : `git config core.hooksPath .githooks` active le hook `pre-commit` qui exécute `scripts/check-secrets.mjs` (Node ou Bun requis) sur chaque commit. `node scripts/check-secrets.mjs --all` contrôle tout le dépôt.
