# Déploiement du Synco AI Runtime (L09)

Guide d'installation pour l'administrateur d'une organisation qui héberge son runtime. Trois chemins :

| Chemin | Statut | Quand |
|---|---|---|
| **[Podman](#2-podman-chemin-officiel)** (rootless, une image OCI) | **officiel, testé** | par défaut, y compris avec Quadlet (service systemd utilisateur) ou `podman compose` |
| **[Docker](#3-docker-variante-avancée)** (profils seccomp et AppArmor dédiés, cgroup délégué) | variante avancée, **non testée** dans ce lot | si Podman n'est pas une option |
| **[systemd sans conteneur](#4-systemd-sans-conteneur)** | fourni, unité système **non essayée** (recette manuelle) | machine dédiée, TPM2 disponible |

Dans tous les cas, **un mandataire inverse TLS est obligatoire** ([§5](#5-mandataire-inverse-tls)) : le runtime ne termine
pas TLS en v1 (D10) et les navigateurs exigent `wss://` avec un certificat reconnu.

Rappel d'architecture : le **superviseur** détient les clés, parle à l'API Synco et lance un **worker isolé par
conversation** (espaces de noms, seccomp, landlock, cgroup v2 : [`docs/plan/10-bac-a-sable.md`](plan/10-bac-a-sable.md)).
Le worker et le superviseur sont le **même binaire** (`synco-ai-runtime`) : une seule image, un seul exécutable.

## 1. Prérequis

| Besoin | Détail | Vérification |
|---|---|---|
| Noyau Linux | ≥ 5.14 (`cgroup.kill`) ; landlock en « meilleur effort » (le noyau applique l'ABI qu'il connaît, refus s'il n'en applique aucune) ; seccomp. Testé : 7.2 (Fedora). | `uname -r` |
| cgroups v2 | hiérarchie unifiée avec les contrôleurs **`cpu`, `memory`, `pids`** | `stat -fc %T /sys/fs/cgroup` → `cgroup2fs` ; `cat /sys/fs/cgroup/cgroup.controllers` |
| Espaces de noms utilisateur | non privilégiés, `user.max_user_namespaces` > 0 ; sous Ubuntu ≥ 23.10 : `kernel.apparmor_restrict_unprivileged_userns` ne doit pas bloquer le conteneur (profil dédié, §3) | `sysctl user.max_user_namespaces` |
| Espace d'échange | de préférence **aucun** (les pages d'un worker, donc des clés, ne doivent pas aller sur disque). Si le noyau n'expose pas `memory.swap.max`, le démarrage est refusé tant qu'un swap est actif (`cgroup_swap_uncontrolled`). | `swapon --show` |
| Horloge | synchronisée (NTP) : les tickets ont une fenêtre de ±30 s | `timedatectl` |
| Podman | ≥ 5 (testé : 5.8.9, rootless, crun, cgroup v2) | `podman info` |
| Réseau sortant | HTTPS vers l'API Synco et vers les fournisseurs LLM (aucun relais : D10) | |
| Nom DNS + certificat TLS **reconnu** | `runtime.example.com` (et un nom pour le dashboard) | [§5](#5-mandataire-inverse-tls), [§8](#8-pièges-réseau) |

Si une fonction du noyau manque, le runtime **refuse de démarrer** avec un code et une explication
(`userns_unavailable`, `cgroup_not_delegated`, `cgroup_base_has_processes`, `landlock_unavailable`…).
`run --insecure-no-sandbox` existe pour le développement : **jamais en production**.

## 2. Podman (chemin officiel)

### 2.1 Pourquoi ces options (une à une)

Le bac à sable a besoin de créer un espace de noms utilisateur, d'y monter, et d'écrire dans un cgroup v2 **privé au
conteneur**. Chaque option ci-dessous a été vérifiée (`sandbox-check` passe ; sans l'option, la sortie en dessous).

| Option | Rôle | Sans elle |
|---|---|---|
| `--user 10001:10001` | le superviseur ne tourne pas en root, même dans le conteneur | (valeur par défaut de l'image) |
| `--read-only` | système de fichiers du conteneur en lecture seule ; `/tmp` et `/run` sont des tmpfs automatiques ; seul le volume d'état est inscriptible | état et journaux ailleurs que dans le volume impossibles |
| `--cap-drop=all` | aucune capacité par défaut (pas de `CHOWN`, `SETUID`, `NET_RAW`, `SYS_CHROOT`, `KILL`…) | capacités inutiles conservées |
| `--cap-add=DAC_OVERRIDE` | **seule capacité conservée** : le cgroup du conteneur appartient au *root du conteneur* (uid 0, ici l'utilisateur de l'hôte), pas à l'uid 10001 ; sans cette capacité le superviseur ne peut pas y créer `supervisor/` ni les cgroups de workers | `cgroup_not_delegated` |
| `--security-opt unmask=/sys/fs/cgroup` | rend le cgroup privé inscriptible (Podman le monte autrement en lecture seule, `unmask` retire la protection) ; l'espace de noms cgroup reste privé : le conteneur ne voit que **son** sous-arbre, jamais celui de l'hôte | `cgroup_not_delegated` |
| `--security-opt label=disable` | hôtes **SELinux** (Fedora, RHEL) : sans cela, le type `container_t` n'a pas le droit d'écrire dans cgroupfs, même avec les droits Unix (constaté : `mkdir` refusé en root, accepté avec `label=disable`). **Retirer sur un hôte sans SELinux.** Alternative plus étroite, non testée : `sudo setsebool -P container_manage_cgroup on` | `cgroup_not_delegated` sur Fedora |
| `--security-opt no-new-privileges` | aucune élévation par `setuid` / capacités de fichier | |
| profil seccomp par défaut de Podman | **suffisant** : `unshare`, `clone`, `mount`, `pivot_root` y passent sans `CAP_SYS_ADMIN` (vérifié) ; ne pas le remplacer | |
| port publié sur `127.0.0.1` seulement | seul le mandataire TLS de l'hôte atteint le runtime | |

Capacités **non** nécessaires (donc absentes) : `SYS_ADMIN` (les montages se font dans l'espace de noms utilisateur
que le worker crée lui-même), `SETUID`/`SETGID` (le superviseur écrit seulement sa propre identité dans `uid_map`),
`SETFCAP` (utile seulement si le superviseur était uid 0 : voir ci-dessous), `NET_BIND_SERVICE` (ports > 1024),
`CHOWN`, `FOWNER`, `KILL`. **Jamais `--privileged`, jamais tout `/sys/fs/cgroup` de l'hôte monté.**

> **Pourquoi pas un cgroup détenu par l'uid 10001 ?** Constaté : sous Podman rootless, le cgroup du conteneur est
> toujours détenu par le root du conteneur, même avec `--userns=keep-id`. Lancer le superviseur en uid 0 résoudrait
> l'écriture du cgroup mais **casse le bac à sable** : un uid 0 ne peut pas se mapper lui-même dans le nouvel espace
> de noms sans `CAP_SETFCAP` (`uid_map : Operation not permitted`, vérifié). D'où l'uid 10001 + `DAC_OVERRIDE`. Cette
> capacité n'existe que dans l'espace de noms utilisateur du conteneur (rootless : aucun pouvoir sur l'hôte) ; le bac à
> sable de chaque worker retire toutes les capacités.

Le superviseur est le **processus 1 et seul de son cgroup** : l'image n'a pas de script d'entrée (`ENTRYPOINT` en forme
exec), pas d'init (`--init` ne doit PAS être ajouté), et `podman exec` n'est à utiliser que pour des commandes
d'administration brèves (`pair`, `dashboard-password`).

### 2.2 Installation pas à pas (Quadlet, service systemd utilisateur)

```bash
# 1. Construire l'image (format Docker : conserve le HEALTHCHECK ; le fichier Quadlet le redéclare de toute façon)
git clone <dépôt synco_ai_runtime> && cd synco_ai_runtime
podman build --format docker -t localhost/synco-ai-runtime:latest .

# 2. Configuration (éditer public_url, api_url, allowed_origins, allowed_hosts)
mkdir -p ~/.config/synco-ai-runtime ~/.config/containers/systemd
cp deploy/config.container.example.toml ~/.config/synco-ai-runtime/config.toml
$EDITOR ~/.config/synco-ai-runtime/config.toml

# 3. Phrase de passe qui scelle la clé du runtime (secret Podman, jamais sur disque en clair)
head -c 32 /dev/urandom | base64 | tr -d '\n' | podman secret create synco-ai-runtime-passphrase -

# 4. Service
cp deploy/podman/synco-ai-runtime.container deploy/podman/synco-ai-runtime-state.volume ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start synco-ai-runtime.service
loginctl enable-linger "$USER"            # démarre au boot, survit à la déconnexion
systemctl --user status synco-ai-runtime.service
podman ps                                  # « healthy » après ~20 s
```

Le fichier [`deploy/podman/synco-ai-runtime.container`](../deploy/podman/synco-ai-runtime.container) porte toutes les
options du tableau ci-dessus ; la sortie de `systemctl --user start` puis `podman ps` doit montrer
`synco-ai-runtime  Up … (healthy)`.

**Sans Quadlet**, la commande équivalente :

```bash
podman run -d --name synco-ai-runtime \
  --user 10001:10001 --read-only \
  --cap-drop=all --cap-add=DAC_OVERRIDE \
  --security-opt no-new-privileges --security-opt unmask=/sys/fs/cgroup --security-opt label=disable \
  --secret synco-ai-runtime-passphrase,target=synco-ai-runtime-passphrase,uid=10001,gid=10001,mode=0400 \
  -v synco-ai-runtime-state:/var/lib/synco-ai-runtime \
  -v ~/.config/synco-ai-runtime/config.toml:/etc/synco-ai-runtime/config.toml:ro \
  -p 127.0.0.1:8790:8790 -p 127.0.0.1:8791:8791 \
  --health-cmd 'bash -c "echo > /dev/tcp/127.0.0.1/8790"' \
  --health-interval 30s --health-timeout 3s --health-retries 3 --health-start-period 20s \
  localhost/synco-ai-runtime:latest
```

> **HEALTHCHECK et Podman** : Podman **ignore** l'instruction `HEALTHCHECK` d'une image au format OCI (avertissement
> à la construction). Deux solutions : `--health-cmd` au `podman run` (ci-dessus, ou `HealthCmd=` dans Quadlet), ou
> `podman build --format docker`. Docker exécute le `HEALTHCHECK` de l'image.

**Avec `podman compose`** (fournisseur `docker-compose` ou `podman-compose`, socket `systemctl --user start
podman.socket`) : [`compose.example.yml`](../compose.example.yml) (testé avec Docker Compose 5.6 sur Podman). Le profil
`gateway` ajoute la passerelle Synco AI et Ollama (`podman compose --profile gateway up -d`). Les secrets de Compose
ignorent `uid` et `mode` : suivre les commentaires du fichier (`chown 10001` de `passphrase.txt` via `podman unshare`).

### 2.3 Appairage pas à pas

1. Vérifier l'environnement, **dans un conteneur jetable** (volume d'état anonyme : ne jamais lancer `sandbox-check` sur le
   volume d'un runtime en marche, il nettoie le répertoire des sockets des workers) :

   ```bash
   podman run --rm --user 10001:10001 --read-only --cap-drop=all --cap-add=DAC_OVERRIDE \
     --security-opt no-new-privileges --security-opt unmask=/sys/fs/cgroup --security-opt label=disable \
     -v /var/lib/synco-ai-runtime \
     -v ~/.config/synco-ai-runtime/config.toml:/etc/synco-ai-runtime/config.toml:ro \
     localhost/synco-ai-runtime:latest sandbox-check
   ```

   Attendu : huit lignes `ok …` puis « toutes les tentatives d'évasion ont échoué ou tué le seul worker concerné »,
   code de sortie 0. Toute ligne `ÉCHEC`, ou un refus de démarrer, est à corriger avant d'aller plus loin.
2. Valider la configuration : `podman exec synco-ai-runtime synco-ai-runtime --check-config` (avertissements éventuels, scellement, fournisseurs).
3. Afficher les informations d'appairage :

   ```bash
   podman exec synco-ai-runtime synco-ai-runtime pair
   # URL publique   : https://runtime.example.com
   # Identifiant    : <uuid>
   # Empreinte      : 3D8B D72A 50F1 …            ← à comparer avec Synco
   # Code d'appairage : 7P5X-EAJG-Y7ZQ-…
   ```

4. Dans Synco : **Paramètres de l'organisation → Synco AI → Runtime**, saisir l'URL et le code. Synco affiche
   l'empreinte de la clé : **elle doit être identique** à celle du terminal (mesure 4, détection d'une substitution de
   clé). Si elle diffère, ne pas continuer.
5. Mot de passe du dashboard (obligatoire pour qu'il démarre ; 12 caractères minimum) :

   ```bash
   podman exec -it synco-ai-runtime synco-ai-runtime dashboard-password
   systemctl --user restart synco-ai-runtime.service       # le dashboard démarre au redémarrage suivant
   ```

   Puis ouvrir `https://runtime-admin.example.com/` (mandataire, [§5](#5-mandataire-inverse-tls)).
6. Fournisseurs LLM : renseigner `[llm.providers.*]` dans `config.toml` (clé par `api_key_file` sur un secret monté, jamais
   dans le fichier), redémarrer. Pour la passerelle Synco AI, voir [§7](#7-passerelle-synco-ai-et-ollama).

### 2.4 Mise à jour

```bash
git pull && podman build --format docker -t localhost/synco-ai-runtime:latest .
systemctl --user restart synco-ai-runtime.service
```

Le volume d'état (clés, historique, mot de passe du dashboard) est conservé ; l'identifiant et l'empreinte restent
identiques (constaté au redémarrage). À l'arrêt, les workers disposent de `limits.shutdown_grace_secs` (30 s) pour finir
l'étape en cours (`TimeoutStopSec=45s` dans le service) ; les conversations en cours reprennent à la prochaine bascule.
Les images de base sont épinglées par digest dans le [`Dockerfile`](../Dockerfile) : pour les mettre à jour, remplacer
le digest (procédure en tête du fichier) puis reconstruire.

### 2.5 Sauvegarde de la clé

Deux éléments, **à conserver séparément** (l'un sans l'autre ne sert à rien, c'est voulu) :

| Élément | Où | Sauvegarde |
|---|---|---|
| `keys.sealed` (clé privée du runtime scellée : Argon2id + AES-256-GCM) | volume `synco-ai-runtime-state` | `podman volume export synco-ai-runtime-state > etat.tar` (contient aussi `dashboard.pass` et l'historique) |
| Phrase de passe | secret Podman `synco-ai-runtime-passphrase` | à noter dans un coffre : `podman secret inspect` ne la montre **pas** ; conservez-la à la création (étape 3) |

Sans la clé **ou** sans la phrase : le runtime est perdu pour son identité actuelle. Il faut `reset-keys --yes` (nouvelle
identité, **nouvel appairage**, les délégations existantes sont perdues). Restauration :
service arrêté, `podman volume create synco-ai-runtime-state`, `podman volume import synco-ai-runtime-state etat.tar`, puis
**rendre la racine du volume à l'utilisateur du runtime** (l'import la laisse en root 0755, vérifié) :

```bash
podman run --rm --user 0 -v synco-ai-runtime-state:/v --entrypoint sh localhost/synco-ai-runtime:latest \
  -c 'chown 10001:10001 /v && chmod 0700 /v'
```

Recréer le secret avec **la même phrase**, démarrer.

### 2.6 Désappairage

- Depuis Synco (administrateur de l'organisation), ou
- depuis le serveur : `podman exec synco-ai-runtime synco-ai-runtime unpair`.

Le runtime garde ses clés et redevient « non appairé » (réappairage possible avec le même identifiant). Pour repartir de
zéro avec de nouvelles clés (obligatoire si la clé a pu fuiter) : arrêter le service, puis
`podman run --rm … reset-keys --yes` avec le même volume et le même secret, redémarrer, appairer à nouveau.
Pour tout supprimer : `systemctl --user disable --now synco-ai-runtime`, `podman volume rm synco-ai-runtime-state`,
`podman secret rm synco-ai-runtime-passphrase`.

## 3. Docker (variante avancée)

> **Non testée dans ce lot** : le démon Docker n'était pas accessible sur la machine de développement (permission refusée
> sur le socket). Le principe vient de [`plan/10-bac-a-sable.md §10`](plan/10-bac-a-sable.md) et des sources de moby
> (`docker-v29.9.2`). Les profils ont été validés **sous Podman/crun** (le profil seccomp, voir plus bas), pas sous
> Docker. À passer par la recette `sandbox-check` avant tout usage.

Docker, par défaut, bloque trois choses dont le bac à sable a besoin :

1. **seccomp** (profil moby) : `unshare`, `mount`, `umount2`, `setns`, `sethostname`, `clone` avec drapeaux d'espaces de
   noms exigent `CAP_SYS_ADMIN`, `pivot_root` est absent. → profil dédié
   [`deploy/docker/seccomp-synco-ai-runtime.json`](../deploy/docker/seccomp-synco-ai-runtime.json) : le profil par défaut
   de moby plus **une seule règle** (`unshare`, `clone`, `mount`, `umount2`, `pivot_root`, `sethostname`), régénérable par
   [`make-seccomp.sh`](../deploy/docker/make-seccomp.sh). **Vérifié sous Podman** : avec le profil moby brut,
   `sandbox-check` → `userns_unavailable` ; avec le profil dérivé → toutes les évasions bloquées.
   (`seccomp=unconfined` fonctionne aussi mais prive le superviseur du filtre de Docker.)
2. **AppArmor** (`docker-default`, hôtes Ubuntu/Debian) : `deny mount`. → profil dédié
   [`deploy/docker/apparmor-synco-ai-runtime`](../deploy/docker/apparmor-synco-ai-runtime) (docker-default sans
   `deny mount`, plus `userns`, `mount`, `pivot_root` ; **jamais écrit ni chargé sur un hôte AppArmor ici**).
   `sudo apparmor_parser -r -W deploy/docker/apparmor-synco-ai-runtime`.
3. **cgroup v2** : Docker monte `/sys/fs/cgroup` en lecture seule hors `--privileged`, même en `--cgroupns=private`
   (moby#46763). Selon la décision du projet : un **sous-arbre cgroup délégué de l'hôte**, dédié au conteneur, désigné par
   `[sandbox] cgroup_root`. **Jamais** tout `/sys/fs/cgroup`.

Schéma de la recette (à valider) :

```bash
# Hôte : sous-arbre délégué dédié (contrôleurs memory, pids, cpu activés), propriété de l'uid du conteneur.
sudo mkdir /sys/fs/cgroup/synco-ai-runtime
echo "+memory +pids +cpu" | sudo tee /sys/fs/cgroup/cgroup.subtree_control   # si nécessaire
sudo chown -R 10001:10001 /sys/fs/cgroup/synco-ai-runtime

docker build -t synco-ai-runtime .
docker run -d --name synco-ai-runtime --restart unless-stopped \
  --user 10001:10001 --read-only --tmpfs /tmp --cap-drop=ALL --cap-add=DAC_OVERRIDE \
  --security-opt no-new-privileges \
  --security-opt seccomp=deploy/docker/seccomp-synco-ai-runtime.json \
  --security-opt apparmor=synco-ai-runtime \
  --cgroupns=host -v /sys/fs/cgroup/synco-ai-runtime:/run/synco-cgroup:rw \
  -v synco-ai-runtime-state:/var/lib/synco-ai-runtime \
  -v "$PWD/config.toml:/etc/synco-ai-runtime/config.toml:ro" \
  -v "$PWD/passphrase.txt:/run/secrets/synco-ai-runtime-passphrase:ro" \
  -p 127.0.0.1:8790:8790 -p 127.0.0.1:8791:8791 \
  synco-ai-runtime
# config.toml : [sandbox] cgroup_root = "/run/synco-cgroup"
# passphrase.txt : chmod 0400 puis chown 10001:10001 (le runtime exige ce propriétaire).
```

Points à vérifier sur un vrai Docker (non résolus) :

- le superviseur se déplace lui-même dans `<cgroup_root>/supervisor` : le noyau exige l'écriture sur le plus proche
  ancêtre commun des deux cgroups et que la destination soit dans l'espace de noms cgroup du processus ; d'où
  `--cgroupns=host` et `DAC_OVERRIDE` dans la recette ci-dessus. Si cela échoue, le message est `cgroup_not_delegated` ou
  `cgroup_join`.
- **Variante plus simple à évaluer** : les sources de moby 29.9.2 contiennent l'option
  `--security-opt writable-cgroups=true` (cgroup **du conteneur** inscriptible, incompatible avec `userns-remap` et le
  mode rootless de Docker). Avec elle, plus besoin de `cgroup_root` ni de `--cgroupns=host` : seul le cgroup du conteneur
  est exposé. Non essayée ; c'est une décision à confirmer par l'utilisateur ([question ouverte](journal.md)).
- `userns-remap` et Docker sans root : incompatibles avec la recette ci-dessus (cgroup délégué) ; imbrication à étudier.
- `HEALTHCHECK` : exécuté nativement par Docker (aucune option à ajouter).

## 4. systemd sans conteneur

Unité de référence (une seule, pas de doublon) : [`crates/supervisor/systemd/synco-ai-runtime.service`](../crates/supervisor/systemd/synco-ai-runtime.service) :
`Delegate=yes`, `ProtectControlGroups=private` (systemd ≥ 257), `RestrictNamespaces=user pid net mnt ipc uts cgroup`,
`SystemCallFilter=@system-service @mount @sandbox sethostname`, `LoadCredentialEncrypted=` pour la clé, plus tout le
durcissement (`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=` vide, `MemoryDenyWriteExecute`, `MemorySwapMax=0`…).
Ces options ont été validées par `sandbox-check` dans une unité **utilisateur** transitoire ; l'unité **système** n'a pas
pu être essayée (recette manuelle, [`docs/recette-porte-c.md`](recette-porte-c.md)). `systemd-analyze verify` ne signale
que l'absence du binaire.

```bash
cargo build --release -p synco-ai-runtime && sudo install -m 0755 target/release/synco-ai-runtime /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin synco-ai-runtime
sudo install -d -m 0755 /etc/synco-ai-runtime
sudo cp crates/supervisor/synco-ai-runtime.example.toml /etc/synco-ai-runtime/config.toml   # éditer ; [key_sealing] mode = "systemd-creds"
sudo cp crates/supervisor/systemd/synco-ai-runtime.service /etc/systemd/system/
sudo synco-ai-runtime --config /etc/synco-ai-runtime/config.toml pair            # EN ROOT, une fois : crée keys.cred (TPM2 / clé de l'hôte)
sudo systemctl enable --now synco-ai-runtime.service
```

- La création de `keys.cred` exige root (`systemd-creds encrypt` refuse à un utilisateur non privilégié : constaté) ; le
  service lit ensuite l'identifiant déchiffré dans `$CREDENTIALS_DIRECTORY` (ramfs propre au service).
- `keys.cred` est lié à la machine (clé de l'hôte, TPM2) : **non restaurable sur une autre machine**. Sauvegarde : sceller
  par phrase de passe (`mode = "passphrase"`, `LoadCredentialEncrypted=` pour la phrase) ou prévoir un `reset-keys`.
- `sandbox-check` doit se lancer **dans les mêmes conditions que le service** : `sudo systemd-run --wait --pipe
  -p Delegate=yes -p ProtectControlGroups=private -p RestrictNamespaces='user pid net mnt ipc uts cgroup'
  -p User=synco-ai-runtime -p StateDirectory=synco-ai-runtime-check … synco-ai-runtime --config … sandbox-check`
  (adapter ; non essayé en unité système). Dashboard : `sudo -u synco-ai-runtime synco-ai-runtime --config … dashboard-password`.
- Le dashboard et l'API publique écoutent sur `127.0.0.1` (valeurs par défaut) ; pas besoin de `allow_non_loopback_plain_http`.

## 5. Mandataire inverse TLS

**Obligatoire.** Deux vhosts (noms distincts) : l'API publique (WebSocket, fiche) et le dashboard.

| | Fichier | Notes |
|---|---|---|
| nginx | [`deploy/nginx/synco-ai-runtime.conf`](../deploy/nginx/synco-ai-runtime.conf) + [`connection-upgrade.conf`](../deploy/nginx/connection-upgrade.conf) | `map $http_upgrade` dans le contexte `http` ; `nginx -t` vérifié (image `nginx:alpine`) |
| Caddy | [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile) | certificat ACME automatique ; `caddy validate` vérifié (image `caddy:alpine`) |

Ce que les deux font, et pourquoi :

- redirection HTTP → HTTPS, TLS ≥ 1.2, HSTS ; **un certificat reconnu** (sinon `wss://` échoue dans le navigateur) ;
- `/v1/` seulement vers `127.0.0.1:8790` (tout le reste : 404) ; WebSocket (`Upgrade`/`Connection`), pas de tampon, délais longs ;
- **`X-Forwarded-For` et `X-Forwarded-Proto` écrasés** (jamais transmis tels quels) pour la cohérence avec
  `listen.trust_proxy_hops = 1` et **`dashboard.trust_proxy_hops = 1`** : le dashboard ne croit ces en-têtes que
  derrière **un** mandataire, qui doit les réécrire (cookie `Secure`, limites de débit par adresse) ;
- dashboard : `Host` transmis tel quel et déclaré dans `dashboard.allowed_hosts = ["runtime-admin.example.com"]` (sinon 403) ;
  restreindre le vhost par réseau (`allow`/`deny`, `remote_ip`) dès que possible ;
- **aucun en-tête CORS** ajouté par le mandataire : le runtime gère l'origine (`allowed_origins`) ;
- ne pas journaliser les corps ni les en-têtes d'autorisation (les tickets ne sont jamais dans l'URL).

Conteneur : si le mandataire tourne **dans** le même réseau Compose, publier les ports sur ce réseau interne seulement ;
`listen.allow_non_loopback_plain_http = true` (nécessaire dans un conteneur) n'est sûr que si 8790/8791 ne sont jamais
exposés hors boucle locale / réseau interne.

## 6. Configuration

- Modèle pour conteneur : [`deploy/config.container.example.toml`](../deploy/config.container.example.toml) (adresses
  d'écoute `0.0.0.0`, `trust_proxy_hops = 1`, scellement par phrase de passe).
- Référence commentée de toutes les options : [`crates/supervisor/synco-ai-runtime.example.toml`](../crates/supervisor/synco-ai-runtime.example.toml).
- `public_url` (https, sans `/` final) entre dans le certificat signé par l'admin : la changer impose une recertification.
- `state_dir` : `<state_dir>/workers/w-<n>-<pid>/llm.sock` doit tenir en 108 octets ; `run_dir` (par défaut
  `<state_dir>/workers`) ≤ **72 octets**. `/var/lib/synco-ai-runtime/workers` fait 33 octets : ne pas choisir un chemin long.
- Dimensionnement : un worker plafonne à `worker_memory_max_mib` (512 Mio) ; prévoir `max_workers × 512 Mio` + marge. Si vous
  fixez `--memory` au conteneur, l'inclure.
- Valider : `podman run --rm … synco-ai-runtime --check-config` (ou `podman exec`).

## 7. Passerelle Synco AI et Ollama

Pour utiliser un modèle local, déployer la **passerelle** (dépôt `Synco_AI_Gateway`, Ollama derrière une authentification par
ticket) : `podman compose --profile gateway up -d` avec [`compose.example.yml`](../compose.example.yml) (Ollama épinglé par
digest, jamais publié ; passerelle construite depuis `SYNCO_AI_GATEWAY_SRC`). Dans `config.toml` : table
`[llm.providers.gateway]` **vide** (aucune clé : le worker obtient un ticket `sgt1` par l'API). L'URL de la passerelle est
celle saisie dans les paramètres IA de l'organisation (**HTTPS**, identique à `SYNCO_GATEWAY_URL`) et doit être joignable
**depuis le conteneur du runtime** : le superviseur refuse les adresses internes (ex. 169.254.169.254) ; le nom interne
`http://synco-ai-gateway:8787` ne convient donc pas. La passerelle a son propre vhost TLS.

## 8. Pièges réseau

- **HTTPS obligatoire** : l'app Synco est en HTTPS ; un `ws://` ou un `http://` est du **contenu mixte**, bloqué par le
  navigateur (sauf `localhost`). Pas de TLS natif en v1 (D10) : mandataire inverse.
- **Certificat reconnu** par les navigateurs **et les applications mobiles** (Capacitor/Tauri) des membres : Let's Encrypt,
  ou le CA de l'entreprise installé sur **tous** les postes et mobiles. Un certificat auto-signé fait échouer le `wss://`
  sans message utile côté utilisateur.
- **CORS** : `allowed_origins` du runtime = origine de l'app web (`https://app.example.com`) + `capacitor://localhost`,
  `tauri://localhost` pour les applications. Le runtime répond lui-même ; ne pas ajouter d'en-têtes `Access-Control-*` dans
  le mandataire (doublons refusés). Une origine absente de la liste → `403` à l'ouverture du WebSocket.
- **Runtime limité à l'intranet, utilisateurs mobiles (D10, Q7)** : le client parle **directement** au runtime (pas de relais
  par l'API en v1). Un membre hors du réseau (mobile en 4G sans VPN, télétravail) **ne joint pas** le runtime : l'app passe
  alors en mode dégradé (historique lisible via l'API, suivi en direct et envoi indisponibles : `plan/05 §9`). Choisir : exposer
  le nom du runtime sur Internet (derrière TLS), ou exiger un VPN, en connaissance de cause.
- **Délais** du mandataire : le runtime ferme un WebSocket sans trame depuis 60 s (échanges de maintien) ; les délais
  `proxy_read_timeout` des exemples (1 h) sont volontairement plus longs que cela.
- **Pare-feu** : seul 443 (et 80 pour la redirection) arrive sur l'hôte ; 8790/8791 restent sur la boucle locale.
- **Sortie** : le conteneur doit joindre l'API Synco et les fournisseurs LLM en HTTPS ; un proxy sortant n'est pas géré
  par le runtime en v1.

## 9. Ce qui a été vérifié, et comment

Voir la section du lot L09 dans [`journal.md`](journal.md) : construction de l'image avec Podman, `sandbox-check` dans le
conteneur, démarrage jusqu'à l'état d'appairage (`pair`, fiche publique), dashboard, persistance de l'état au
redémarrage, Quadlet, Compose (Podman). **Non vérifiés** : Docker, AppArmor, unité système, mandataire en conditions
réelles (WebSocket de bout en bout), SELinux avec le booléen `container_manage_cgroup`.
