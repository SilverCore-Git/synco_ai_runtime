# 10 — Bac à sable des workers (L06)

Un processus isolé par conversation active (P3), qui ne reçoit que les clés de sa conversation par
le pipe (mesure 7). Ce document justifie la conception ; le code est dans
`crates/supervisor/src/sandbox/` (lanceur, étapes enfant, politique, cgroups, mandataire LLM,
autotest) et `crates/worker/src/{entry,llm}.rs`. Conventions : [00 §3](00-vue-ensemble.md) ;
protocole du pipe : [06](06-superviseur-worker.md) ; plafonds : [09 §2](09-limites-et-valeurs-par-defaut.md).

## 1. Ce que le worker peut et ne peut pas faire

| Ressource | Accès du worker | Mécanisme |
|---|---|---|
| Pipe vers le superviseur | descripteur 3 seulement | `socketpair` hérité par stdin puis déplacé ; tout autre descripteur hérité → refus |
| Système de fichiers | aucun : racine `tmpfs` vide en lecture seule, plus `/run/synco/` (le socket du mandataire, lecture seule) | espace de noms mount + `pivot_root` ; landlock (tous droits gérés, seule règle : `ResolveUnix` sous `/run/synco`) ; seccomp (aucun `open*`) |
| `/proc`, `/sys`, `/home`, état du superviseur | invisibles (non montés) | ancienne racine détachée |
| Autres processus | aucun : le worker est PID 1 de son espace de noms | espaces de noms pid, ipc ; landlock (portée « signal ») |
| Réseau IP | aucun : pas d'interface active | espace de noms net ; seccomp (`socket` seulement `AF_UNIX`) ; landlock (TCP géré, aucune règle) |
| Sockets Unix abstraits de l'hôte | aucun | espace de noms net ; landlock (portée « socket abstrait ») |
| LLM | uniquement le fournisseur de **sa** conversation, par le mandataire | §4 |
| API Synco | uniquement par `signed_request` (signé par le superviseur, chemins en liste fermée) | 06 §4 (L05) |
| Nouveaux processus, `exec` | interdits ; fils d'exécution seulement | seccomp (`clone` exige `CLONE_THREAD`, `clone3` → `ENOSYS`, `execve` → tué) ; racine sans binaire |
| Privilèges | aucun : capacités retirées (ensemble limitant compris), bits de sécurité verrouillés, `no_new_privs` | `policy::drop_capabilities` |
| Mémoire / CPU / processus | `memory.max` 512 Mio, pas d'espace d'échange, `cpu.max` 1 CPU, `pids.max` 64 | cgroup v2 par worker (§5) |

L'identité dans l'espace de noms utilisateur est « root » (une seule correspondance, vers
l'utilisateur du service) **sans aucune capacité** ; hors du worker, ses fichiers et processus sont
ceux de l'utilisateur du service, qui n'a lui-même aucun privilège (unité systemd).

## 2. Lancement : `fork` + `exec`, deux étapes, aucun `exec` après le filtre

Le superviseur (multi-fil, détient les clés) ne fait **jamais** de `fork` seul : il lance son propre
binaire par `tokio::process::Command` (`fork` + `exec` immédiat), environnement vidé
(`env_clear` : `api_key_env` reste dans le superviseur), répertoire `/`, stdin = l'extrémité worker
du `socketpair`, stdout = `/dev/null`, stderr = tube lu par le superviseur (seules les lignes
`sandbox_error:<code>` sont retenues, jamais journalisées autrement).

1. **`__sandbox-helper`** (exécuté avant tout moteur asynchrone, un seul fil — condition de
   `CLONE_NEWUSER`) : `PR_SET_PDEATHSIG(SIGKILL)` ; vérifie que seuls 0, 1, 2 sont ouverts ;
   s'inscrit dans le cgroup du worker (`cgroup.procs`) ; `unshare(USER|NS|PID|NET|IPC|UTS|CGROUP)` ;
   `setgroups=deny`, `uid_map`/`gid_map` = `0 <uid du service> 1` ; lance l'étape 2 et attend
   (code rendu : celui du worker, ou 128 + signal).
2. **`__sandbox-worker`** (PID 1 du nouvel espace de noms) : pipe → descripteur 3, stdin →
   `/dev/null` ; `PR_SET_PDEATHSIG` ; vérifie 0–3 seulement ; racine (`tmpfs` 16 Kio sur `/tmp`,
   montage du répertoire du socket depuis un descripteur ouvert avant, `pivot_root(".", ".")`,
   ancienne racine détachée, racine remontée en lecture seule `nosuid,nodev,noexec`) ; nom d'hôte
   `synco-worker` (au mieux) ; capacités retirées ; `no_new_privs` ; landlock ; seccomp ; stderr →
   `/dev/null` ; puis le code du worker **dans ce même processus**
   (`synco_ai_runtime_worker::entry::run`).

Choix : le worker est le binaire du superviseur, pas `synco-ai-runtime-worker`. Raisons : aucun
`execve` n'est nécessaire après seccomp (il est donc **fatal**), la racine peut rester **vide**
(bibliothèques déjà chargées, pas de règle landlock d'exécution, pas d'analyse des dépendances
ELF), un seul binaire à déployer. Le code n'est pas un secret ; la mémoire du superviseur n'est pas
héritée (nouvelle image après `exec`). Le binaire `synco-ai-runtime-worker` ne fait qu'expliquer
cela et quitter.

`unsafe` : un seul bloc, `rustix::thread::unshare_unsafe` (non sûr seulement pour `CLONE_FILES`,
exclu), dans `sandbox/sys.rs`, seul module à lever l'interdiction (`unsafe_code = "deny"` dans le
workspace, `#![forbid(unsafe_code)]` à la racine des autres crates, test `tests/unsafe_scope.rs`).
Tout le reste passe par des API sûres : `rustix`, `landlock`, `seccompiler`, `std`.

## 3. seccomp

Deux filtres (`policy::seccomp_programs`), le plus sévère l'emporte :

1. **Fatals** (processus tué, `SIGSYS`) : `ptrace`, `process_vm_*`, `mount`, `umount2`,
   `pivot_root`, `chroot`, `unshare`, `setns`, `bpf`, `perf_event_open`, `kexec_*`, modules,
   `keyctl`/`add_key`/`request_key`, `userfaultfd`, `io_uring_*`, `execve`, `execveat`,
   `memfd_create`, `open_by_handle_at`, nouvelle API de montage, `pidfd_open`/`pidfd_getfd`, horloge,
   `reboot`, `swapon`, `personality`, `iopl`/`ioperm`…
2. **Liste blanche**, tout le reste → `ENOSYS` (comme un noyau qui ne connaît pas l'appel ; c'est ce
   qui fait replier la glibc de `clone3` vers `clone`) : E/S sur descripteurs, `epoll`, `eventfd`,
   `futex`, mémoire, signaux, horloge, `getrandom`, `connect`, `socket`/`socketpair` (`AF_UNIX`
   seulement ; `tokio` crée une paire pour son pilote de signaux), `clone` (avec `CLONE_THREAD`),
   `prctl` (`PR_SET_NAME`/`PR_GET_NAME`), `prlimit64` (lecture), `ioctl` (`FIONBIO`/`FIOCLEX`).
   Aucun `open*`.

La liste blanche est installée en dernier (chaque installation exige `prctl(PR_SET_NO_NEW_PRIVS)`
et `seccomp`). L07 : un appel système nouveau (bibliothèque ajoutée) renvoie `ENOSYS` ; l'ajouter à
`allowed_syscalls` avec une justification, et relancer `tests/sandbox-host.sh`.

## 4. Réseau : espace de noms sans interface + mandataire LLM du superviseur

**Choix** : le worker n'a **aucun** réseau IP ; son seul accès est un socket Unix vers un
**mandataire LLM** du superviseur, propre à ce worker et limité au fournisseur de sa conversation.

Alternatives écartées :

- *Espace de noms réseau avec une interface (veth/slirp) + pare-feu par liste blanche* : exige
  `CAP_NET_ADMIN` sur l'hôte ou un outil externe (slirp4netns, pasta), un résolveur DNS, et une liste
  blanche par **nom** d'hôte que l'IP ne permet pas d'appliquer (CDN partagés). La clé LLM devrait
  aussi être dans le worker.
- *landlock réseau seul* (ABI ≥ 4) : filtre des ports TCP, pas des hôtes.
- *Relais générique (CONNECT)* : le worker ferait le TLS et détiendrait la clé ; aucun contrôle des
  chemins.

Le mandataire (`sandbox/proxy.rs`) :

- un socket `<run_dir>/w-<n>-<pid>/llm.sock` (répertoire `0700`, socket `0600`) servi par une tâche
  du superviseur tant que le worker vit, monté en lecture seule dans le bac à sable sous
  `/run/synco/llm.sock` ;
- le worker parle HTTP/1.1 **clair** (`crates/worker/src/llm.rs`, client `hyper` prêt pour L07).

**Destination et clé (B1, révisé après relecture)** — `Runtime::build_init` :

- l'identifiant du fournisseur vient de la politique de l'org (`defaultProvider`) ; l'**URL** et la
  **clé** viennent de la **configuration du runtime**, cherchées avec ce **même** identifiant
  (`[llm.providers.<id>]`, `base_url` obligatoire pour tout fournisseur sauf `gateway`, contrôlé par
  `validate`). Aucune URL fournie par l'API ne reçoit jamais une clé du runtime ;
- `gatewayUrl` de la politique ne sert qu'au fournisseur `gateway`, qui n'injecte aucune clé (le
  worker y passe son ticket `sgt1`) ; elle doit être en `https` (port 443), sans identifiants ni
  requête, vers un nom public (ni `localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, ni IP
  privée, de lien local, CGNAT, de métadonnées, ULA…, `gateway_url_allowed`) ; à la connexion, un
  résolveur écarte toute adresse non publique (`PublicOnlyResolver`, pas de mandataire HTTP
  système). Une `base_url` configurée pour `gateway` dans le runtime l'emporte ;
- fournisseur inconnu ou absent de la configuration, ou URL de passerelle refusée : **aucun worker**
  n'est lancé, la conversation passe en `failed` avec `provider_error` (code écrit aujourd'hui par le
  superviseur, `workers.rs:130`). **Depuis L03d (2026-11-21, Q30 / PC16)** l'API accepte
  `provider_not_configured` (08 §6) : c'est le code prévu pour ce cas, **non encore adopté** par le
  superviseur (ouvert) ; la cause exacte, `llm_provider_not_configured` ou `llm_gateway_url_refused`, est
  au journal du runtime) et le bail est rendu ;
- pour `openai`, `mistral`, `gemini`, `custom` : l'`authorization` du worker est retiré et remplacé
  par `Bearer <clé>` ; la clé **ne passe plus par le pipe** (`WorkerLauncher::injects_llm_credentials`,
  aucune trame `llm_credential`).

**Requêtes admises (I2)** : exactement deux couples (méthode, chemin relatif à l'URL de base), sans
chaîne de requête — API compatibles OpenAI : `POST /chat/completions`, `GET /models` ; passerelle
Synco : `POST /v1/chat/completions`, `GET /models` (routes de `Synco_AI_Gateway`). Cette liste blanche est la raison pour laquelle Gemini passe par son endpoint **compatible OpenAI**
(06 §9) : l'API native (`models/{m}:streamGenerateContent`) serait refusée. Tout le reste
(`/files`, `/files/<id>/content`, `/organization/users`, `/./files`, `GET /chat/completions?…`) →
`404 proxy_path` (`405 proxy_method` hors `GET`/`POST`), sans appel au fournisseur.

**Mémoire du superviseur (I1)** : un worker hostile ne peut pas la saturer :

| Borne | Valeur | Justification |
|---|---|---|
| Connexions par socket de worker | 4 (les suivantes attendent dans la file du noyau) | une requête à la fois par connexion HTTP/1.1 |
| Corps de requête | **8 Mio** (`413 proxy_body_too_large`, y compris `Content-Length` annoncé) | l'historique d'une conversation est plafonné à 8 Mio (09 §4) ; une requête de chat (historique, outils, résultats ≤ 256 Kio) n'a pas de raison de le dépasser ; la passerelle accepte 1 Mio |
| Lecture du corps | 30 s (`408 proxy_body_timeout`) | client lent |
| Octets de corps en tampon | 16 Mio par worker, 64 Mio pour le runtime, réservés **pendant** la lecture (`429`/`503 proxy_busy`) | 2 corps maximaux par worker ; 8 workers ne dépassent pas 64 Mio |

La place de connexion est prise à l'acceptation, donc **avant** toute lecture ; les octets sont
rendus dès que le corps est parti vers le fournisseur.

**Quotas (I3, application de D6)**, comptés par le mandataire, refus `429` avec code machine sans
appel au fournisseur (le worker le reçoit comme réponse HTTP) :

| Quota | Valeur | Code |
|---|---|---|
| Appels par tour | `maxStepsPerTurn` par fenêtre fixe de `maxTurnDurationSecs`, remise à zéro à son terme (le mandataire ne voit pas les tours) | `proxy_call_budget` |
| Tokens par tour | `maxTokensPerTurn` sur la même fenêtre | `proxy_token_budget` |
| Tokens par conversation | `maxTokensPerConversation` sur la vie du worker | `proxy_token_budget` |
| Débit par worker | 2 appels / s, rafale 5 | `proxy_rate_limited` |
| Débit du runtime | 20 appels / s, rafale 40 | `proxy_runtime_rate_limited` |
| Tokens du runtime | `max_workers × maxTokensPerTurn × tours par heure` par heure (8 × 300 000 × 2 par défaut) | `proxy_runtime_token_budget` |
| Durée d'un appel | min(`maxTurnDurationSecs`, 10 min) ; 120 s sans octet | `502 proxy_upstream_timeout` |

Avant l'appel, la réservation estimée vaut `octets de la requête / 4 + maxOutputTokensPerCall` ; après,
le mandataire facture `usage.total_tokens` (ou `prompt + completion`) lu dans la réponse (JSON
≤ 1 Mio, ou lignes SSE `data: {…}` ≤ 256 Kio), sinon l'estimation bornée `(requête + réponse) / 4`
(flux interrompu compris). Les tokens consommés au-delà de la conversation précédente (autre worker)
restent du ressort du worker (L07) : le compteur du mandataire repart à zéro à chaque worker.

En-têtes relayés : `content-type`, `accept` (requête) ; `content-type`, `retry-after` (réponse).
Aucun corps ni en-tête journalisé.

Risque résiduel : un worker compromis peut **utiliser** la clé via le mandataire, dans ses quotas,
pour le chat ou la liste des modèles du fournisseur de sa conversation ; jamais l'exfiltrer, joindre
un autre hôte ni appeler une autre route de l'API du fournisseur. Pour `gateway`, un serveur Synco
malveillant peut désigner un autre hôte public : il n'en reçoit que le ticket `sgt1` (émis par lui)
et le contenu, que le fournisseur voit de toute façon (risque assumé, 03 §2).

## 5. cgroups v2 (D6)

Disposition (règle « pas de processus dans un nœud interne ») : `<base>/supervisor` (le
superviseur s'y place au démarrage) et `<base>/w-<n>-<pid>` par worker. `<base>` = le cgroup du
service (`Delegate=yes`) ou `[sandbox] cgroup_root`. Contrôleurs `memory pids cpu` activés dans
`<base>/cgroup.subtree_control`. Par worker : `memory.max` = `worker_memory_max_mib`,
`memory.swap.max = 0` (les pages du worker, donc ses clés, ne vont jamais sur disque),
`memory.oom.group = 1` (l'assistant et le worker meurent ensemble), `pids.max`, `cpu.max`
(`worker_cpu_percent × 1000` sur 100 000 µs). Si le noyau n'expose pas `memory.swap.max`, le
démarrage est **refusé** (`cgroup_swap_uncontrolled`) sauf si aucun espace d'échange n'est actif
(`/proc/swaps` vide). Arrêt : `cgroup.kill`, puis suppression quand le
cgroup est vide. Métriques (06 §5, L08) : `WorkerProcess::usage()` lit `memory.current`,
`memory.peak`, `cpu.stat usage_usec`.

**D6 révisée le 2026-11-21 (porte C, Q22 tranchée) : `memory.high` est retiré, `memory.max` seul
s'applique.** Sans espace d'échange, la mémoire anonyme n'est pas récupérable : sous `memory.high` =
448 Mio, le worker de test était encore vivant après 120 s, ralenti indéfiniment (5 141 évènements
`high`, aucun OOM), au lieu d'être tué à `memory.max`. Le worker qui dépasse `memory.max` est tué par
l'OOM du noyau (avec son assistant, `memory.oom.group`). Le code du superviseur écrit encore
`memory.high = max` et lit `limits.worker_memory_high_mib` (ignoré, `--check-config` avertit) : ce
nettoyage appartient à un lot du superviseur (journal, L07c).

## 6. Repli si une fonction noyau manque

Au démarrage (`run`), **avant** de desceller les clés, `SandboxLauncher::new` prépare le cgroup
délégué puis lance une **sonde** (un worker vide qui franchit toutes les étapes). Tout échec →
le superviseur **refuse de démarrer** avec le code et une explication (`userns_unavailable`,
`cgroup_not_delegated`, `cgroup_base_has_processes`, `landlock_unavailable`, `seccomp_unavailable`,
`mount_*`…). landlock : mode « meilleur effort » sur l'ABI (le noyau applique ce qu'il connaît,
ABI 9 sur le noyau 7.2 de test) ; refus seulement si landlock n'est pas appliqué du tout.

`run --insecure-no-sandbox` (développement) : processus séparé, environnement vidé, pipe sur le
descripteur 3, mandataire LLM (la clé reste dans le superviseur), mais ni espaces de noms, ni
seccomp, ni landlock, ni cgroup ; avertissement fort au journal et sur stderr.

`synco-ai-runtime --config … sandbox-check` : sonde puis tentatives d'évasion (§8) dans
l'environnement réel ; code de sortie non nul si l'une n'est pas bloquée.

## 7. Coût mesuré (argument de P3)

Hôte : Fedora, noyau 7.2.15, binaire `--release`, 10 lancements (`tests/sandbox.rs`,
`vrai_worker_et_cout`) :

| Mesure | Valeur |
|---|---|
| Lancement → `ready` (fork + exec ×2, espaces de noms, montages, landlock, seccomp, moteur `tokio`) | médiane **3,9 ms** (3,8 – 4,3) ; 6 ms en `debug` |
| Mémoire facturée au cgroup du worker vide (`memory.current`, assistant + worker) | **≈ 1,3 Mio** |
| RSS / PSS des deux processus (pages du binaire partagées entre workers) | 10,8 Mio / **4,6 Mio** |
| Processus par worker | 2 (assistant en attente + worker) |
| Autotest complet (`sandbox-check`, 8 workers dont un OOM à 512 Mio) | 0,45 s |

Conséquence pour 09 §2 : le coût fixe d'un worker est négligeable devant `memory.max` ; le
dimensionnement ⌊RAM libre × 0,6 / 512 Mio⌋ reste dicté par le plafond, pas par l'isolement.
Lancer à la demande et arrêter après 60 s d'inactivité (P3) ne coûte que ~4 ms par reprise.

## 8. Tests (sur l'hôte : `host-spawn sh crates/supervisor/tests/sandbox-host.sh`)

Chaque binaire de test tourne seul dans `systemd-run --user --scope -p Delegate=yes`.

| Tentative (worker isolé) | Résultat attendu et constaté |
|---|---|
| Lire `/etc/passwd`, `/home`, `/proc/self/status`, `/sys/fs/cgroup/…`, le répertoire d'état du superviseur et ses fichiers, `/proc/<pid superviseur>/environ` | échec (`ENOSYS` par seccomp ; sans seccomp `ENOENT`, racine vide) |
| Lister `/proc`, ouvrir `/proc/<pid superviseur>/{status,environ,mem}`, `kill(pid superviseur, 0)` | échec ; le worker est PID 1 |
| TCP/UDP vers 1.1.1.1:443 et vers un écouteur du superviseur en 127.0.0.1, socket abstrait du superviseur | échec ; l'écouteur ne reçoit rien |
| Écrire dans `/`, `/run/synco/`, `/tmp` | échec |
| Créer un processus ; créer des fils d'exécution en boucle | processus refusé ; 62 fils puis `EAGAIN` (`pids.max` 64) |
| Appel `mount` | worker tué (`SIGSYS`) |
| Toucher 2 Gio | worker tué par l'OOM de **son** cgroup (`SIGKILL`, `oom_kill` ≥ 1) |
| Pendant OOM, boucle et appel fatal d'autres workers | un worker témoin répond toujours, sa mémoire reste < 64 Mio |
| Couches retirées une à une (`--without`, tests seulement) | chaque couche réseau suffit seule ; sans aucune, le test constate l'évasion (`tcp_ok`) |
| Mutation : `memory.max` et `pids.max` non écrits | `sandbox-check` échoue (`oom`, `threads` « escaped ») |
| Mandataire (worker isolé) | clé ajoutée, clé forgée par le worker retirée ; ticket relayé pour la passerelle ; `/files`, `/files/<id>/content`, `GET /chat/completions?limit=100`, `/organization/users`, `/./files`, `..`, `POST /models` → 404 ; `DELETE` → 405 ; aucun appel au fournisseur |
| Mandataire attaqué directement (`tests/proxy.rs`, partout) | corps de 31 Mio annoncé ou envoyé en morceaux → 413 ; 5ᵉ connexion en attente ; 4 corps de 7 Mio → au moins un `429 proxy_busy` ; quotas d'appels, de tokens (`usage` et estimation), du runtime et de débit |
| Fournisseur non configuré (`integration.rs`, `fournisseur_non_configure_refuse`) | `mistral` non configuré, identifiant inconnu, passerelle vers 169.254.169.254 : `failed` / `provider_error`, aucun worker, bail rendu |
| Descripteur hérité sans `O_CLOEXEC` | lancement refusé (`inherited_fd`) |
| Lancement refusé après création du répertoire du worker | aucun reste |
| Aller-retour client → superviseur → worker isolé → API simulée (`aller_retour_avec_bac_a_sable`) | identique au bouchon en processus |
| Refus de démarrer (cgroup absent) avant toute clé ; `--insecure-no-sandbox` démarre | vérifié (aussi dans le flatpak) |

## 9. systemd

Unité d'exemple `crates/supervisor/systemd/synco-ai-runtime.service` : `Delegate=yes`,
`ProtectControlGroups=private` (systemd ≥ 257 ; `=yes` met cgroupfs en lecture seule et fait
refuser le démarrage — vérifié), `RestrictNamespaces=user pid net mnt ipc uts cgroup` (sans `user`
→ `userns_unavailable`, vérifié), `SystemCallFilter=@system-service @mount @sandbox sethostname`,
`ProtectHostname=yes` (interdit `sethostname` : le nom d'hôte du worker reste celui de la machine),
plus le durcissement de L05 (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateDevices`,
`ProtectProc=invisible`, `ProcSubset=pid`, `CapabilityBoundingSet=` vide, `MemoryDenyWriteExecute`,
`MemorySwapMax=0`…). Ces options ont été validées par `sandbox-check` dans une unité **utilisateur**
transitoire (`systemd-run --user --wait -p …`) ; une unité **système** n'a pas pu être essayée
(recette manuelle). Sans `Delegate=yes`, une unité système refuse de démarrer
(`cgroup_not_delegated`) ; dans le gestionnaire utilisateur, les cgroups sont déjà délégués.

## 10. Docker (pour L09, non écrit ici)

Besoins : créer un espace de noms utilisateur sans privilège, monter dans cet espace de noms, et un
cgroup v2 **en écriture** pour le conteneur. Pas de socket Docker, pas de `--privileged`, pas de
root sur l'hôte.

- **seccomp de Docker** (profil par défaut de moby) : `unshare`, `mount`, `umount2`, `setns`,
  `sethostname` exigent `CAP_SYS_ADMIN` ; `clone` avec drapeaux d'espaces de noms refusé ;
  `pivot_root` absent (EPERM) ; `clone3` → `ENOSYS` ; landlock et `seccomp` permis. Il faut donc un
  profil dérivé ajoutant `unshare`, `clone`/`clone3` avec drapeaux d'espaces de noms, `mount`,
  `umount2`, `pivot_root`, `sethostname` (`--security-opt seccomp=<profil>`), ou
  `seccomp=unconfined` (le filtre propre du worker s'applique quand même ; le superviseur perd celui
  de Docker).
- **AppArmor** (`docker-default`) refuse `mount` : profil dédié ou `apparmor=unconfined`. Ubuntu
  ≥ 23.10 : `kernel.apparmor_restrict_unprivileged_userns=1` bloque les espaces de noms utilisateur
  non privilégiés sauf profil qui les autorise.
- **Espaces de noms utilisateur** : `user.max_user_namespaces` > 0 sur l'hôte ; fonctionne aussi
  avec `userns-remap` / Docker sans root (imbrication).
- **cgroup v2** : Docker monte `/sys/fs/cgroup` en lecture seule hors `--privileged`, même avec
  `--cgroupns=private` (moby#46763, non résolu). Options à valider par L09 : Podman
  (`--security-opt unmask=/sys/fs/cgroup` rend le cgroup privé inscriptible) ; containerd ≥ 2.1
  (`cgroup_writable`) ou Kubernetes (KEP-5474) ; à défaut sous Docker, monter un sous-arbre
  **délégué** de l'hôte dédié au conteneur et le désigner par `[sandbox] cgroup_root` (ne jamais
  monter tout `/sys/fs/cgroup` de l'hôte). Le superviseur doit être **seul** dans son cgroup
  (processus 1 du conteneur, sans script d'entrée qui reste en vie dans le même cgroup).
- `/tmp` doit exister dans l'image (point de montage de la racine du worker) ; le répertoire d'état
  (`run_dir` ≤ 72 octets) en volume.
- Vérification dans le conteneur : `synco-ai-runtime --config … sandbox-check`.

## 11. Pour L07

- Entrée : `synco_ai_runtime_worker::entry::run(pipe, llm_socket)` (remplacé par la vraie boucle d'agent en L07).
  Moteur `tokio` mono-fil ; `spawn_blocking` crée des fils (comptés dans `pids.max`).
- LLM : `synco_ai_runtime_worker::llm::send(socket, LlmRequest::new("POST", "/chat/completions")
  .header("content-type", "application/json").body(…))` puis `next_chunk()` pour le flux SSE. Ne
  jamais mettre de clé ; pour la passerelle, `.header("authorization", "Bearer sgt1…")`. `init.llm`
  `baseUrl` reste l'URL réelle (information) : le worker ne s'y connecte jamais.
- Pas de fichier, pas de DNS, pas de TLS dans le worker ; pas de `std::process::Command`.
- Un appel système manquant se voit comme `ENOSYS` (§3).
- Seuls `POST /chat/completions` (`/v1/chat/completions` pour la passerelle) et `GET /models`
  passent ; les refus du mandataire sont des `4xx`/`5xx` avec `{"error":"proxy_<code>"}` : traiter
  `proxy_call_budget`, `proxy_token_budget` (fin du tour : `budget_exceeded` / `step_limit`) et
  `proxy_*rate_limited` (attendre, `retry-after` absent). Demander `usage` dans le flux
  (`stream_options.include_usage`) pour un décompte exact.
