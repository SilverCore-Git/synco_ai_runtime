# Déploiement du Synco AI Runtime (L09)

Guide d'installation pour l'administrateur d'une organisation qui héberge son runtime. Trois chemins :

| Chemin | Statut | Quand |
|---|---|---|
| **[Podman](#2-podman-chemin-officiel)** (rootless, une image OCI) | **officiel, testé** | par défaut, y compris avec Quadlet (service systemd utilisateur) ou `podman compose` |
| **[Docker](#3-docker-variante-avancée)** (profils seccomp et AppArmor dédiés, cgroup délégué) | variante avancée, **non testée, non prise en charge en l'état** | si Podman n'est pas une option |
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
| `--security-opt label=disable` | hôtes **SELinux** (Fedora, RHEL) : sans cela, `container_t` n'a pas le droit d'écrire dans cgroupfs, même avec les droits Unix (constaté : `mkdir` refusé en root, accepté avec `label=disable`). **Attention : cette option désactive TOUT le confinement SELinux du conteneur** (le processus tourne en `spc_t`, non confiné), pas seulement l'accès au cgroup : c'est une perte de défense en profondeur. Si on la retire, les montages de fichiers de l'hôte exigent `:Z` (sinon `EACCES` sur `config.toml`) et le cgroup redevient inaccessible. Alternative plus étroite, **non testée faute de root** : `sudo setsebool -P container_manage_cgroup on`. **Retirer l'option sur un hôte sans SELinux.** | `cgroup_not_delegated` sur Fedora |
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

# 3. Phrase de passe qui scelle la clé du runtime. Elle est AFFICHÉE UNE FOIS : la noter dans un coffre
#    (sans elle, la sauvegarde de keys.sealed est inutilisable). Lire le modèle de menace juste après.
PP=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
printf 'Phrase de passe à noter dans un coffre : %s\n' "$PP"
printf '%s' "$PP" | podman secret create synco-ai-runtime-passphrase -
unset PP

# 4. Service
cp deploy/podman/synco-ai-runtime.container deploy/podman/synco-ai-runtime-state.volume ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start synco-ai-runtime.service
loginctl enable-linger "$USER"            # démarre au boot, survit à la déconnexion
systemctl --user status synco-ai-runtime.service
podman ps                                  # « healthy » après ~20 s
```

> **Modèle de menace de la phrase de passe (à lire).** Le pilote de secrets Podman par défaut est `file` : la phrase est
> stockée **en base64, non chiffrée**, dans `~/.local/share/containers/storage/secrets/filedriver/secretsdata.json`, et
> `podman secret inspect --showsecret synco-ai-runtime-passphrase` l'affiche. Or `keys.sealed` vit dans le volume, sous le
> **même `$HOME`** (`~/.local/share/containers/storage/volumes/`). Une sauvegarde du compte, un vol du disque ou un accès
> au compte donne donc **la clé scellée et sa phrase ensemble** : le scellement ne protège alors que contre la lecture de
> `keys.sealed` seule (fuite du volume exporté, d'une sauvegarde du seul volume). C'est le compromis retenu pour un
> **redémarrage sans intervention**. Atténuations : compte dédié au runtime (voir §5, M5), disque chiffré, sauvegarde du
> volume **sans** `~/.local/share/containers/storage/secrets/`.
>
> Alternatives (la question de fond reste à trancher) : (1) pilote de secrets `pass` (`podman secret create --driver pass …`,
> phrase dans le trousseau `pass`/GPG) ou `shell` (commande à vous : coffre d'entreprise, TPM…), sous réserve que le
> déverrouillage soit disponible au démarrage du service ; (2) **saisie au démarrage** : le superviseur lit la phrase sur un
> terminal sans écho quand `passphrase_file` est absent (`seal.rs`, `PassphraseSource::Terminal`, vérifié dans le code), donc
> `podman run -it` sans secret ; aucun redémarrage automatique possible (il faut quelqu'un) ; (3) mode systemd
> (`systemd-creds`, TPM2) sans conteneur, §4. Aucun mode « saisie » n'existe pour un service détaché : ne pas l'attendre.

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
ignorent `uid` et `mode` : suivre les commentaires du fichier (`chown 10001` de `~/.config/synco-ai-runtime/passphrase.txt` via `podman unshare`).

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

   Attendu : sept lignes `ok …` puis « toutes les tentatives d'évasion ont échoué ou tué le seul worker concerné »,
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

Deux éléments, **à conserver séparément, hors de ce `$HOME`** (l'un sans l'autre ne sert à rien : c'est le but, que la sauvegarde du volume seule ne donne pas la clé) :

| Élément | Où | Sauvegarde |
|---|---|---|
| `keys.sealed` (clé privée du runtime scellée : Argon2id + AES-256-GCM) | volume `synco-ai-runtime-state` | `podman volume export synco-ai-runtime-state > ~/sauvegardes/etat.tar` (**hors du dépôt**, droits 0600) (contient aussi `dashboard.pass` et l'historique) |
| Phrase de passe | secret Podman `synco-ai-runtime-passphrase` (pilote `file` : en base64 dans `secretsdata.json`, visible par `podman secret inspect --showsecret`) | notée dans un coffre **à la création** (étape 3, affichée une fois) ; ne pas compter sur le secret Podman comme seule copie |

Sans la clé **ou** sans la phrase : le runtime est perdu pour son identité actuelle. Il faut `reset-keys --yes` (nouvelle
identité, **nouvel appairage**, les délégations existantes sont perdues). Restauration :
service arrêté, `podman volume create synco-ai-runtime-state`, `podman volume import synco-ai-runtime-state ~/sauvegardes/etat.tar`, puis
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

> **NON TESTÉE ET NON PRISE EN CHARGE EN L'ÉTAT.** Le démon Docker n'était pas accessible sur la machine de développement
> (socket refusé) : rien de ce qui suit n'a tourné sous Docker. Le principe vient de
> [`plan/10-bac-a-sable.md §10`](plan/10-bac-a-sable.md) et de la **lecture** des sources de moby (`docker-v29.9.2`) ; la
> revue a relevé des défauts de conception dans la première version de cette recette (corrigés ci-dessous ou présentés comme
> problèmes ouverts). **Utiliser Podman (§2).** Seuls le profil seccomp (sous Podman/crun) a été exécuté.

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
   `deny mount`, plus `userns`, `mount`, `pivot_root`). **Jamais chargé ni testé** : pas d'hôte AppArmor ici. Le profil
   déclare `abi <abi/4.0>` (la règle `userns` n'est appliquée qu'avec AppArmor ≥ 4.0 ; en ABI 4.0, `network` n'inclut plus
   `network unix`, d'où une règle `unix,` ajoutée, à vérifier). `sudo apparmor_parser -r -W deploy/docker/apparmor-synco-ai-runtime`.
3. **cgroup v2** : Docker monte `/sys/fs/cgroup` en lecture seule hors `--privileged`, même en `--cgroupns=private`
   (moby#46763). Décision du projet : un **sous-arbre cgroup délégué de l'hôte**, dédié au conteneur, désigné par
   `[sandbox] cgroup_root`. **Jamais** tout `/sys/fs/cgroup`.

### Problèmes connus de la recette (relevés en revue, établis par lecture)

- **Capacité ambiante** : Docker ne place pas les capacités ajoutées par `--cap-add` dans l'ensemble *ambiant* pour un
  utilisateur non root (moby#8460, #38664) : **`DAC_OVERRIDE` est inopérant pour l'uid 10001** (contrairement à Podman, où
  c'est vérifié). La recette ne doit donc pas compter dessus : les fichiers de cgroup doivent appartenir à l'uid 10001.
- **Migration de cgroup** : avec `--cgroupns=host`, le superviseur se déplace vers `<cgroup_root>/supervisor` ; le noyau
  exige l'écriture de `cgroup.procs` du plus proche **ancêtre commun** des deux cgroups, ici la racine ou une tranche de
  l'hôte, qui appartient à root : refus probable (`cgroup_join` / `cgroup_not_delegated`). Piste : placer le cgroup du
  conteneur **sous** le sous-arbre délégué (`--cgroup-parent`), pour que l'ancêtre commun soit le sous-arbre délégué.
- **Délégation minimale** : ne **pas** faire `chown -R` du sous-arbre : cela donnerait au conteneur la propriété de
  `memory.max`, `pids.max`… de la racine du sous-arbre, donc le pouvoir de **lever ses propres plafonds**. Comme systemd,
  ne déléguer que le répertoire, `cgroup.procs`, `cgroup.subtree_control` et `cgroup.threads`.
- **Plafonds** : les cgroups des workers sont dans le sous-arbre délégué, **hors** du cgroup du conteneur : `--memory` et
  `--pids-limit` de Docker **ne les bornent pas**. Les limites globales (`memory.max`, `pids.max`, `cpu.max`) sont à poser
  **par l'hôte, root, sur la racine du sous-arbre**, et dimensionnées sur `max_workers × 512 Mio`.
- **Fuite d'information** : `--cgroupns=host` expose au conteneur la **hiérarchie cgroup de l'hôte** (noms de services,
  PID, identifiants de conteneurs voisins) via `/proc/self/cgroup` et les chemins.

Recette corrigée (toujours **non testée**) :

```bash
# Hôte, en root : sous-arbre dédié ; seuls le répertoire et trois fichiers de contrôle sont délégués à l'uid 10001.
CG=/sys/fs/cgroup/synco-ai-runtime
mkdir "$CG"
echo "+memory +pids +cpu" > /sys/fs/cgroup/cgroup.subtree_control           # si nécessaire
chown 10001:10001 "$CG" "$CG/cgroup.procs" "$CG/cgroup.subtree_control" "$CG/cgroup.threads"
# Plafonds posés PAR L'HÔTE (fichiers restés à root) : exemple pour max_workers = 8
echo 4608M > "$CG/memory.max"; echo 1024 > "$CG/pids.max"; echo "800000 100000" > "$CG/cpu.max"

docker build -t synco-ai-runtime .
docker run -d --name synco-ai-runtime --restart unless-stopped \
  --user 10001:10001 --read-only --tmpfs /tmp --cap-drop=ALL \
  --security-opt no-new-privileges \
  --security-opt seccomp=deploy/docker/seccomp-synco-ai-runtime.json \
  --security-opt apparmor=synco-ai-runtime \
  --cgroupns=host -v "$CG":/run/synco-cgroup:rw \
  -v synco-ai-runtime-state:/var/lib/synco-ai-runtime \
  -v "$HOME/.config/synco-ai-runtime/config.toml:/etc/synco-ai-runtime/config.toml:ro" \
  -v "$HOME/.config/synco-ai-runtime/passphrase.txt:/run/secrets/synco-ai-runtime-passphrase:ro" \
  -p 127.0.0.1:8790:8790 -p 127.0.0.1:8791:8791 \
  synco-ai-runtime
# config.toml : [sandbox] cgroup_root = "/run/synco-cgroup"
# passphrase.txt (hors du dépôt) : chmod 0400 puis chown 10001:10001 (le runtime exige ce propriétaire).
```

Cette recette **ne résout pas** le problème de l'ancêtre commun (ci-dessus) : à valider ou à abandonner sur un vrai Docker.

### Piste : `--security-opt writable-cgroups=true`

Les sources de moby 29.9.2 contiennent cette option (`daemon/daemon_unix.go`, `daemon/oci_linux.go`) : le cgroup **du
conteneur** est monté inscriptible, sans `cgroup_root` ni `--cgroupns=host` ; incompatible avec `userns-remap` et le mode
rootless de Docker. Elle ne règle **pas** la propriété : ce cgroup appartient à root, l'uid 10001 ne peut pas y écrire
(même problème que sous Podman, sans la capacité ambiante pour le contourner). Non essayée ; décision à confirmer par l'utilisateur.

Autres points : `userns-remap` et Docker sans root sont incompatibles avec la recette ; `HEALTHCHECK` est exécuté
nativement par Docker.

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
