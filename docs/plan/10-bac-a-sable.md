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
| Web (L00i) | seulement si `webAllowed` : le service de recherche configuré et des `GET` de pages publiques, par le proxy `web` du superviseur (`/run/synco/web.sock`) ; jamais d'IP directe | §4.2 |
| CDN (L00i, étape 2) | seulement un `GET` d'objet par ticket, vers le CDN configuré, par le relais `cdn` (`/run/synco/cdn.sock`) | §4.3 |
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

### 4.1 Mandataire LLM

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

### 4.2 Proxy `web` du superviseur (L00i, 2026-11-24 ; catalogue L14 §8 ; PC90 à PC93)

**Choix (PC90)** : la recherche passe par un **service de recherche** appelé par le superviseur, jamais
par la recherche native du fournisseur d'IA : c'est la seule voie où le runtime voit et contrôle chaque
requête avant qu'elle ne parte. Même mécanique que le mandataire LLM (§4) : le worker reste sans réseau
IP, la clé du service reste chez le superviseur.

**Socket.** `<run_dir>/w-<n>-<pid>/web.sock` (`0600`), monté en lecture seule sous `/run/synco/web.sock`,
**seulement** si (a) la prise du bail a rendu `features.webAllowed = true` (04 §4.2, 12 §11.2) et (b) la
configuration du runtime a une section `[web.search]` valide. Sinon pas de socket, et le worker ne
montre ni `web_search` ni `web_fetch` au modèle (`init.web.available = false`, 06 §3). Une trame
`feature.revoked` (04 §6) ou un renouvellement de bail qui rend `webAllowed = false` fait **fermer** le
socket : requêtes en cours coupées, connexions suivantes refusées (`web_unavailable`).

**Configuration** (fichier du runtime ; aucune valeur ne vient de l'API ni du pipe) :

| Clé | Règle |
|---|---|
| `[web.search] provider` | `staan` (**défaut recommandé**, PC91), `mojeek` (**repli** si le DPA ou la durée de conservation de Staan ne conviennent pas), `searxng` (auto-hébergé), `brave` ; un adaptateur par service derrière une interface unique (L15-web) |
| `[web.search] base_url` | obligatoire ; `https` port 443, sans identifiants ni requête, nom public (mêmes refus que `gateway_url_allowed`, §4) ; seule exception : `provider = "searxng"` avec `allow_private_host = true` explicite (instance sur le réseau de l'org) |
| `[web.search] api_key` | injectée par le superviseur dans l'en-tête propre au service ; jamais dans le pipe ni dans un journal |
| `[web.fetch] enabled` | `true` par défaut ; `false` retire `web_fetch` seul |
| `[web] synco_hosts` | noms refusés par `web_fetch` en plus de ceux déduits de la configuration (API, CDN, passerelle, keyguard) |

Au démarrage, le superviseur **déclare** le service à l'API (`PUT /api/runtime/v1/web-provider
{ provider }`, S, 04 §4.1 ; `null` si aucun), pour la page « Mes données » et l'avertissement de
`web_access` (12 §11.3). PC91 : avant de livrer Staan par défaut, obtenir son DPA et sa durée de
conservation des requêtes (non publiés au 2026-11-24) ; à défaut, Mojeek devient le défaut.

**Requêtes admises** (HTTP/1.1 clair sur le socket, corps JSON ≤ 4 Kio, tout le reste → `404 web_path` /
`405 web_method`, sans appel sortant) :

| Requête | Corps | Réponse `200` |
|---|---|---|
| `POST /search` | `{ "query": <2 à 200 caractères>, "freshness"?: "day"\|"week"\|"month"\|"year", "lang"?: <2 lettres>, "count"?: 1..10 }`, strict | `{ "results": [{ "title" (≤ 200), "url" (≤ 2 000, `https` ou `http` seulement), "snippet" (≤ 500), "age"? }] }`, 10 au plus, **8 Kio** au plus (extraits tronqués, puis résultats retirés depuis la fin) ; jamais la ville ni l'IP de l'utilisateur |
| `POST /fetch` | `{ "url": <≤ 2 000>, "maxBytes"?: 1 024..2 097 152 }`, strict | octets bruts du corps (≤ `maxBytes`, défaut et maximum **2 Mio**), en-têtes `content-type` et `x-synco-final-url` (URL après redirections) |

Erreurs : `{ "error": "<code>", "status"?: <HTTP du site> }`, codes `web_bad_request` (400), `web_quota`
(429), `web_url_refused` (403 : schéma, port, identifiants, IP littérale, nom ou adresse refusés),
`web_redirect_limit`, `web_too_large`, `web_unsupported_type`, `web_http_status` (statut ≠ 2xx du site),
`web_timeout` (504), `web_provider` (502 : service de recherche en échec), `web_unavailable` (503).

**Contrôles de `/fetch`** (catalogue §8.7, faits par le **superviseur**, qui ne fait que borner et relayer) :

- `https` (port 443) ou `http` (port 80) seulement ; pas d'identifiants dans l'URL ; pas d'IP littérale ;
- résolution par le `PublicOnlyResolver` (§4) : refus des adresses privées, de bouclage, de lien local,
  CGNAT, métadonnées de nuage (`169.254.169.254`, `fd00:ec2::254`), ULA, multicast, réservées ; refus des
  noms `localhost`, `.local`, `.internal`, `.lan`, `.home.arpa` et des hôtes de Synco ; l'adresse
  résolue est **épinglée** pour la connexion (anti-rebinding) ;
- 5 redirections au plus, chacune recontrôlée en entier ; une redirection n'exige **pas** de nouvelle
  provenance (c'est le site qui la choisit, pas le modèle) ;
- `GET` seulement ; en-têtes envoyés : `User-Agent: SyncoAI-Fetch/1`, `Accept: text/html, text/plain,
  text/markdown, application/json, application/xml`, **`Accept-Encoding: identity`** ; aucun cookie,
  `Authorization`, `Referer` ni `Origin` ; cookies reçus jetés ;
- types admis : `text/html`, `text/plain`, `text/markdown`, `application/json`, `application/xml` ; un
  corps compressé (`Content-Encoding` ≠ `identity`) est refusé `web_unsupported_type` (le superviseur ne
  décompresse rien : pas de bombe de décompression) ;
- délais : connexion 10 s, total 20 s ; recherche : 10 s au total.

**Quotas** (comptés par le superviseur, qui ne voit pas les tours ; le worker applique en plus les
quotas par tour et par conversation, 09 §4.2) :

| Quota | `search` | `fetch` |
|---|---|---|
| par fenêtre de `maxTurnDurationSecs` et par worker | 10 | 20 |
| par worker (vie du worker) | 50 | 100 |
| par heure, tout le runtime | 200 | 500 |
| connexions simultanées | 2 par worker, 8 pour le runtime | idem (même socket) |

Au-delà : `429 web_quota`, sans appel sortant. Valeurs réglables dans la configuration du runtime.

**Conversion et marquage dans le worker.** La conversion HTML → texte se fait **dans le bac à sable**
(un HTML hostile n'est jamais analysé par le superviseur) ; texte rendu au modèle : 20 000 caractères par
défaut, 100 000 au plus (`maxChars`) ; résultat enveloppé `<untrusted source="web:<hôte>">…</untrusted>`
(balises du contenu neutralisées). Dès qu'un résultat web est entré dans un tour, l'app suspend
« toujours accepter » pour les plans de ce tour et affiche « l'agent a lu des pages web pendant ce tour »
(catalogue §8.8 ; l'app le déduit du transcript, aucun champ nouveau).

**Journaux et métriques** : aucun corps, aucune requête, aucune URL ; comptes seulement (P9).

**Risque résiduel (signalé).** Le proxy ouvre au worker une **sortie** qu'il n'avait pas : la garde de
fuite et la provenance (§4.4) vivent dans le worker, si bien qu'un worker **compromis** (exécution de code
dans le bac à sable, par exemple par une faille de l'analyse HTML) pourrait faire sortir des données de
**sa** conversation dans une URL ou une requête, dans la limite des quotas. Il ne joint toujours ni l'API
hors liste, ni les clés des autres workers. Durcissement possible, non retenu en v1 : contrôle de
provenance recopié dans le superviseur pour les URL issues de `/search`.

### 4.3 Relais `cdn` (L00i ; catalogue L14 §5.2 ; étape 2, livrée avec le proxy `web` par L15-web)

**v1 (étape 1)** : `read_file` est **appareil seulement** (retiré du manifeste du runtime, 04 §4.2) ; le
worker garde `tool_unavailable_in_runtime` pour les outils de fichiers (06 §9).

**Étape 2** : socket `/run/synco/cdn.sock`, même mécanique, une seule requête admise :
`GET /object` avec les en-têtes `x-synco-object` (chemin d'objet rendu par
`POST /api/runtime/v1/e2ee/files/:fileId/download`, 04 §4.3) et `x-synco-cdn-ticket` (ticket `down` de la
même réponse). Le superviseur appelle **seulement** le CDN de sa configuration (`[cdn] base_url`, hôte
fixe, jamais une URL fournie par l'API ou le worker) avec la route de téléchargement d'objet de
`synco_cdn` (chemin exact fixé par L15-web d'après `synco_cdn`), corps ≤ 256 Kio + 4 Kio (chiffré et
étiquettes), connexion 10 s, total 20 s ; 20 lectures par fenêtre et par worker, 100 par worker. Le
worker déchiffre (clé du fichier déballée sous la clé d'espace déléguée) et enveloppe le texte en
`<untrusted source="file:<id>">`. Erreurs : `cdn_refused`, `cdn_too_large`, `cdn_timeout`, `cdn_status`.

### 4.4 Garde de fuite et provenance (worker ; PC93)

Faites par le worker **avant** toute requête au proxy `web`. Elles ne bloquent ni ne réécrivent jamais :
elles **demandent confirmation** à l'utilisateur, avec le texte exact qui partirait (PC93). Vecteurs :
`vectors/web-guard.json`.

**Normalisation** `N(t)` : NFKC, puis décomposition NFD et retrait des marques combinantes (catégorie
`Mn`), puis minuscules (correspondance simple Unicode). **Mots** : suites maximales de caractères
alphabétiques ou numériques (propriétés Unicode `Alphabetic`, `Numeric`) ; tout autre caractère sépare.

**Empreintes** (mémoire du worker seulement, jamais écrites ni journalisées), tenues pour **chaque texte
E2EE déchiffré par un outil** de la conversation (messages, fichiers ; plus tard tickets) :

| Ensemble | Contenu |
|---|---|
| `G5` | HMAC-SHA-256 (clé aléatoire de 32 octets tirée au démarrage du worker), tronqué à 8 octets, de chaque suite de **5 mots consécutifs** de `N(texte)` jointe par une espace ; 500 000 entrées au plus |
| `R` (jetons rares) | adresses e-mail (`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, en minuscules) ; suites d'au moins **6 chiffres**, séparateurs simples (espace, point, tiret) permis entre chiffres, gardées en chiffres seuls ; identifiants (CUID `c[a-z0-9]{24}`, UUID) ; URL `http(s)://` du texte, réduites à `hôte + chemin` (hôte en minuscules) |
| `M` (noms) | noms des membres (`GET …/web-guard/names`, 04 §4.2) et du propriétaire, chacun comme suite de mots de `N(nom)` ; un nom d'**un seul mot de moins de 4 caractères** est ignoré |

**Contrôle d'une chaîne `q`** (la requête de `web_search` ; pour `web_fetch`, le chemin et la chaîne de
requête de l'URL, décodés du pourcentage) — motifs, dans cet ordre, tous rapportés :

| Motif (`reason`) | Condition |
|---|---|
| `e2ee_passage` | une suite de 5 mots consécutifs de `N(q)` est dans `G5` |
| `e2ee_token` | un jeton rare extrait de `q` (mêmes règles que `R`) est dans `R` |
| `member_name` | la suite de mots d'un nom de `M` apparaît comme mots consécutifs de `N(q)` |
| `guard_saturated` | `G5` a atteint 500 000 entrées : **toute** requête web demande confirmation |

**Provenance de `web_fetch`** (catalogue §8.7). Forme canonique `C(u)` : analyse WHATWG, schéma et hôte en
minuscules (hôte en punycode), port par défaut retiré, fragment retiré, chemin et requête inchangés.
`web_fetch` est **sans confirmation** seulement si `C(url)` appartient à (a) l'ensemble des URL rendues par
`web_search` dans **cette** conversation (le worker le reconstruit depuis les résultats d'outils du
transcript), ou (b) l'ensemble des URL écrites par **l'utilisateur** dans ses messages de la conversation.
Toute autre URL (inventée par le modèle, trouvée dans une page, un message d'un autre membre, un fichier)
→ confirmation, motif **`url_provenance`**, avec l'URL complète. Les liens d'une page lue ne rejoignent
jamais (a).

**Confirmation.** Le worker n'envoie rien, écrit la conversation en `awaiting_confirmation` avec le
`pendingToolCall` classique (C1 §7 : `args = "__pending__"`, `category: "agent"`), plus un champ
**`guard`** = `gcm1:` sous `CK`, AAD `sessionId:<toolCallId>:web_guard`, clair
`JCS({ v: 1, reasons: [<motifs>], spans: [{ start, end }] })` (positions en unités UTF-16 dans la chaîne
affichée : requête ou URL ; `spans` vide pour `url_provenance` et `guard_saturated`). Lecture rétrocompatible :
un `pendingToolCall` sans `guard` se confirme comme avant. L'app montre la requête ou l'URL **exacte**,
les passages soulignés et le motif en clair (« contient un passage d'un message chiffré », « contient le
nom d'un membre », « adresse non issue d'une recherche ni de vous ») ; boutons « Envoyer » et « Ne pas
envoyer ». Décision par l'élément `confirm` existant (05 §6.2) ; « toujours accepter » ne s'applique
**jamais**. Refus → résultat d'outil `{"error":"web_refused_by_user"}`, le tour continue.

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
