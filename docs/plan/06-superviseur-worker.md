# 06 — Protocole superviseur ↔ worker (pipe)

Le superviseur lance **un process worker par conversation active** (P3, L06) et lui parle par un
**seul** canal : une paire de descripteurs hérités (`socketpair` `AF_UNIX`, `SOCK_STREAM`) sur le
descripteur 3 du worker (**révisé après L06** : le superviseur la passe d'abord en stdin du
processus assistant, qui la déplace sur le descripteur 3 ; le worker est le **binaire du
superviseur** relancé en `__sandbox-worker`, pas `synco-ai-runtime-worker`, 10 §2). Aucun autre descripteur n'est hérité (en dehors de stdin/stdout/stderr
redirigés vers `/dev/null` ou un journal sans contenu). Les types sont dans la crate
`runtime-protocol` (L05). Conventions : [00 §3](00-vue-ensemble.md).

## 1. Cadrage (révisé après L05, 2026-11-20)

```
trame = longueur (u32 gros-boutiste, octets qui suivent) ‖ genre (u8) ‖ charge
```

| `genre` | Charge |
|---|---|
| `0x01` | Message JSON (UTF-8, un objet, §3–§4) |
| `0x02` | Message de clés binaire (§2) |

- Longueur : la valeur en tête compte **le genre (1 octet) plus la charge** ; les **plafonds portent sur
  la charge** : 1 Mio pour `0x01`, 64 Kio pour `0x02` (`header`, `read_frame`,
  `crates/runtime-protocol/src/pipe.rs:98-129`). Une charge vide (longueur = 1), une longueur nulle,
  une charge au-delà du plafond, ou un genre inconnu : le lecteur ferme le canal ; côté superviseur, le worker est tué (`SIGKILL`) et la
  conversation suit 08 §5.
- JSON : `{ "type": "<type>", … }`, désérialisation **stricte** (`deny_unknown_fields`), un seul
  objet par trame.
- Les clés ne passent **jamais** en JSON : une chaîne JSON désérialisée ne s'efface pas de façon
  fiable. Elles passent dans des trames `0x02`, lues directement dans des tampons `Zeroizing`.

## 2. Trame de clés (`0x02`)

```
op        u8         0x01 = ajouter, 0x02 = retirer
nombre    u16 BE
répété « nombre » fois :
  kind    u8         0x01 = conv, 0x02 = thread, 0x03 = space, 0x10 = llm_credential (voir ci-dessous)
  refLen  u16 BE
  ref     refLen octets UTF-8 (identifiant, 00 §3.2 ; pour llm_credential : identifiant du fournisseur)
  version u32 BE
  keyLen  u16 BE     (32 pour conv/thread/space ; ≤ 4 096 pour llm_credential)
  key     keyLen octets   (absent si op = retirer, keyLen = 0)
```

Le superviseur n'envoie au worker que les clés de **la délégation du propriétaire de la
conversation** (03 §9), et parmi elles : `conv` de cette conversation (obligatoire), puis les
`thread` et `space` de l'org. Il n'envoie jamais `DK`, la clé de délégation, ni aucune clé du runtime.
Le worker ne peut pas demander une clé d'un autre utilisateur ni d'une autre conversation.

Taille : une délégation peut contenir des centaines de clés ; le superviseur découpe en plusieurs
trames de ≤ 64 Kio.

**`llm_credential` n'est plus envoyée (révisé après L06, D1 = A, 2026-11-20)** : le superviseur est un
mandataire LLM qui **injecte lui-même** la clé du fournisseur dans la requête (10 §4) ; la clé ne
passe jamais par le pipe (`WorkerLauncher::injects_llm_credentials`). Le `kind` `0x10` reste défini
dans `runtime-protocol` (le décodeur le lit encore), mais aucune trame n'en contient avec le bac à
sable. Il n'existe pas non plus de `net_request` / `net_response` : le seul accès réseau du worker
est le socket du mandataire (10 §4).

### 2.1 Trame `0x02` du **worker** vers le superviseur (extension L07, révisée après les corrections de L07)

Le sens worker → superviseur n'admet **qu'un seul cas** : l'annonce de la clé d'un salon que le
worker vient de créer (outil `create_thread`, 03 §10). `KeyFrame::is_created_thread_key` exige
exactement : `op = ajouter`, **une** entrée, `kind = thread`, `version = 1`, clé de 32 octets. Toute
autre trame `0x02` du worker (retrait, `space`, `conv`, `llm_credential`, plusieurs entrées, version
≠ 1) est un incident de sécurité : worker tué (`BadKeys`). Réponse : message `created_key` (§3.2).

## 3. Superviseur → worker

| `type` | Champs | Moment |
|---|---|---|
| `init` | `sessionId`, `userId`, `orgId`, `runtimeId`, `authId`, `leaseEpoch`, `apiBaseUrl`, `llm` (§3.1), `limits` (§3.2), `toolPolicy` (D5 : `{ "<outil>": "auto" \| "ask" \| "deny" }`), `logLevel` | Première trame, suivie des trames de clés, puis `start` |
| `start` | — | Le worker peut commencer (toutes les clés initiales reçues) |
| `inbox` | `items` : éléments de boîte de réception tels que reçus (05 §6.2, champs encore chiffrés) | Message, décision ou annulation arrivés par WebSocket. **Révisé après L05, 2026-11-20** : un même élément peut arriver **deux fois** au worker (`GET …/inbox` à la reprise, puis `inbox` en direct, 04 §4.2) ; **L07 déduplique la boîte par `id`** (`docs/journal.md`, L05, écart 10) |
| `keys` | (trame `0x02`) | Clé ajoutée (synchro P11) ou retirée (révocation) |
| `shutdown` | `graceMs`, `reason` (`idle` \| `revoked` \| `unpaired` \| `sigterm` \| `limit`) | Arrêt demandé : terminer l'étape en cours si `graceMs > 0`, enregistrer, quitter |
| `net_response` | — | **Non retenu (L06)** : pas de relais réseau par le pipe, le mandataire est un socket Unix à part (10 §4) |
| `signed_request_response` | `id`, `status`, `headers`, `body`, `part?`, `last?`, `error?` | Réponse à `signed_request` (§4), en une ou plusieurs parties |
| `snapshot_request` | `requestId` | **Ajout L05** : un client reprend hors du tampon de rejeu (05 §3) ; le worker répond par `snapshot` (§4) |
| `created_key` | `ref`, `envelope?`, `error?` | **Ajout L07** : réponse à la trame `0x02` du worker (§2.1, §3.2) |

### 3.1 Configuration LLM (`llm`)

`{ "provider": "openai" | "mistral" | "gemini" | "gateway" | "custom", "model": "…", "baseUrl": "…", "reasoningEffort": "low" | "medium" | "high", "pricing": { "inputPerMTok": <€>, "outputPerMTok": <€> } | null }`.
**Aucun secret ne passe dans `init` ni en trame `0x02`** (révisé après L06, D1 = A) : le superviseur
injecte la clé du fournisseur (configuration du runtime, `[llm.providers.<id>]`) dans la requête que
le worker envoie au mandataire (10 §4) ; `baseUrl` est l'URL réelle, à titre d'information (le worker
ne s'y connecte jamais). Pour `gateway`, le worker obtient un ticket `sgt1` par `signed_request` vers
`POST /api/runtime/v1/tickets/llm` et le met lui-même dans `authorization`.

### 3.2 Plafonds (`limits`)

`{ "maxStepsPerTurn", "maxTokensPerConversation", "maxTokensPerTurn", "maxTurnDurationSecs", "maxOutputTokensPerCall", "maxToolResultBytes", "idleShutdownSecs" }`
— valeurs de 09 §2, bornées par la politique de l'org (07 §6). **Révisé après L05, 2026-11-20** :
`maxTokensPerTurn` et `maxOutputTokensPerCall` (09 §2) font partie de `limits` (`WorkerLimits`,
`pipe.rs`), les sept champs sont tous obligatoires (désérialisation stricte).

### 3.3 `created_key` (extension L07, 03 §10 et §10.1)

Le worker n'a ni `csk` ni `DK` (mesure 7) : pour poser l'enveloppe `rt1` et l'entrée de délégation
d'un salon qu'il vient de créer, il envoie la trame `0x02` de §2.1 et reçoit :

```json
{ "type": "created_key", "ref": "<threadId>",
  "envelope": { "delegationId": "…", "commitment": "<b64>", "signature": "<b64>", "ciphertext": "sre1.…" } }
{ "type": "created_key", "ref": "<threadId>", "error": "created_key_unknown_thread" }
```

Désérialisation stricte ; `envelope` et `error` s'excluent. Le superviseur calcule `commitment` depuis
la clé, signe `synco-key-envelope-rt-v1|ctx|1|commitment|delegationId` avec `csk` (03 §10), chiffre
l'entrée sous `DK` de la délégation **courante du propriétaire** (03 §5) ; il **n'installe pas** la
clé dans son coffre (elle y entre par `delegation.entries_added`). Le **worker** pose ensuite lui-même,
par `signed_request` et avec le bail : `POST /e2ee/threads/:id/key-envelope` (04 §4.3) puis
`POST /delegations/:delegationId/entries`.

Codes d'`error` :

| Code | Sens |
|---|---|
| `created_key_unknown_thread` | Le salon n'est pas un salon dont **ce** worker a fait relayer la création réussie (réponse `2xx` de `POST /e2ee/threads`, identifiant lu dans la réponse et noté **avant** que le worker la voie), ou la clé de ce salon a déjà été annoncée. Empêche de faire signer une enveloppe `rt1` pour un salon quelconque |
| `created_key_limit` | Plus de 32 clés signées pour ce worker (`MAX_CREATED_KEYS_PER_WORKER`) |
| `delegation_unavailable` | Pas de délégation active du propriétaire dans le coffre (retirée ou expirée) |
| `created_key_failed` | Autre échec (clé illisible, signature ou chiffrement impossibles, worker absent) |

Au plus **64** salons créés en attente de leur clé par worker. **Écart assumé** : le superviseur ne
connaît que la délégation courante du propriétaire, pas le `delegationId` de l'autorisation de
session ; si les deux diffèrent un instant, l'échec est **fermé** côté API (signature refusée `400`,
entrée `out_of_scope`) et le salon reste en TOFU (03 §10.1), aucune enveloppe fausse n'est posée.
Le coffre ne remplace jamais une clé différente déjà ouverte pour le même salon (la première est
gardée). Source : `crates/runtime-protocol/src/pipe.rs` (`CreatedKeyMsg`),
`crates/supervisor/src/workers.rs` (`created_key`, `note_created_thread`), `docs/journal.md` (L07).

## 4. Worker → superviseur

| `type` | Champs | Usage |
|---|---|---|
| `ready` | `pid`, `version` | Après `init`, prêt à recevoir les clés |
| `event` | `event` : trame runtime → client complète (05 §5), déjà chiffrée, avec `epoch` et `seq` | Le superviseur la met dans le tampon de reprise et la diffuse aux WebSocket de la conversation **sans la lire** |
| `status` | `status`, `reason?` | Changement d'état (le worker l'a déjà enregistré dans l'API) |
| `need_key` | `kind`, `ref` | Clé absente de la délégation (03 §11) ; le superviseur répond par `keys` si elle arrive |
| `signed_request` | `id`, `method`, `path`, `body` (b64), `withAuth` (bool), `part?`, `last?` | Requête vers l'API que **le superviseur signe** avec `sig` (le worker n'a jamais la clé privée, mesure 7) ; `path` doit commencer par `/api/runtime/v1/conversations/<sessionId>`, `/api/runtime/v1/e2ee/`, `/api/runtime/v1/tickets/llm` ou `/api/runtime/v1/delegations/<délégation du propriétaire>/entries` ; sinon refus |
| `snapshot` | `requestId`, `event` | **Ajout L05** : réponse à `snapshot_request` ; `event` = la trame `snapshot` complète de 05 §5.2, déjà chiffrée (seul le worker peut produire `state`). Le superviseur ne l'envoie qu'au client demandeur, sans la mettre dans le tampon |
| `inbox_ack` | `ids` | Éléments consommés (après écriture de l'historique) |
| `metrics` | §5 | Toutes les 10 s et à la fin du tour |
| `net_request` | — | **Non retenu (L06)**, voir `net_response` ci-dessus |
| `log` | `level`, `code`, `fields` (sans contenu) | Journal structuré |
| `done` | `reason` (`idle` \| `awaiting` \| `failed` \| `cancelled` \| `shutdown`) | Le worker va quitter (code 0) |

Le superviseur limite le débit des `signed_request` (09 §2) et refuse un chemin hors liste
(journalisé comme incident de sécurité, worker tué).

**Trame `0x02` du worker** : voir §2.1 (seulement l'annonce d'une clé de salon créée ; autre trame =
worker tué).

### 4.1 Relais `signed_request` en parties (révisé après L05, 2026-11-20)

Un corps de requête ou de réponse dépasse vite la charge maximale d'une trame (l'historique va
jusqu'à 8 Mio, 09 §4). Source : `crates/runtime-protocol/src/pipe.rs:600-760`,
`crates/supervisor/src/workers.rs:420-540`, `docs/journal.md` (L05, correction 2).

- **Parties** : un corps est envoyé en plusieurs trames de même `id`, `part` = 0, 1, 2… (absent = 0),
  la dernière avec `last = true` (absent = vrai), de **≤ 512 Kio bruts** chacune (`RELAY_CHUNK_BYTES`) ;
  `method`, `path`, `withAuth` (requête) ou `status`, `headers` (réponse) sont répétés à l'identique.
  Une partie hors ordre, illisible ou changeant `method` / `path` / `withAuth` → réponse d'échec
  `relay_bad_part`. Corps maximal : 8 Mio + 64 Kio (requête), 9 Mio (réponse) ; au-delà
  `relay_too_large`.
- **Réponse d'échec** : `status = 0` et `error` = code machine, sans corps. Codes `relay_*` :
  `relay_refused` (requête refusée **localement** : chemin non conforme ou dont la forme envoyée
  diffère de la forme signée), `relay_busy` (trop de requêtes en vol ou de corps en réassemblage),
  `relay_too_large` (aussi : réponse de l'API illisible ou trop grande), `relay_bad_part`, `relay_network` (échec réseau ou délai ; une réponse HTTP d'erreur de l'API n'est pas un échec : son `status` et son corps sont relayés), `relay_rate_limited`
  (débit dépassé : alors `status = 429` et corps `{"error":"rt_rate_limited"}`, **sans appel** à l'API).
  `headers` est réduit à `content-type`.
- **Bornes** : au plus **4** requêtes en vol par worker et **8** pour tout le runtime (au-delà :
  `status = 0`, `relay_busy`) ; 2 corps en réassemblage par worker ; débit de 09 §2. Un refus
  `relay_*` **ne ferme pas** le pipe (seul un chemin hors liste tue le worker).
- **Lecture côté worker (L07, après correction I2)** : après l'envoi d'une action **mutante**
  (`POST …/tools/:name/execute`, `POST /e2ee/threads`), un délai, un pipe fermé, `relay_network`,
  `relay_too_large` (réponse illisible ou trop grande) ou un `5xx` donnent une **issue inconnue**
  (`unknown_outcome`, 08 §5) ; une erreur explicite de l'API est un échec. En revanche les refus
  **locaux** du relais, émis **avant** tout envoi à l'API (`relay_busy`, `relay_refused`,
  `relay_rate_limited`, `relay_bad_part`), sont un **échec simple** (`tool_failed`) : rien n'est parti,
  donc l'issue n'est pas inconnue (décision de l'orchestrateur, acceptée).
- Autres incidents qui tuent le worker (journalisés, sans contenu) : évènement `event` mal formé,
  hors d'ordre (`epoch` ≠ celui du bail, ou `seq` non croissant) ou de plus de 1 Mio.

### 4.2 `snapshot_request` / `snapshot` (révisé après L05, 2026-11-20)

Quand un client se reconnecte hors du tampon de rejeu (05 §3), le superviseur répond
`ready { mode: "snapshot" }` **seulement si** la demande est réellement partie : il envoie au worker
`snapshot_request { requestId }` (identifiant propre à la connexion) ; sinon (canal plein, worker pas
démarré) il répond `ready { mode: "reload" }`. Le worker répond par `snapshot { requestId, event }`.
Le superviseur ne peut pas fabriquer la trame lui-même : `state` est chiffré par `CK` (05 §4) que
seul le worker détient. Une trame de plus de 1 Mio est remplacée par `ready { mode: "reload" }`
(05 §2). Source : `crates/supervisor/src/client_ws.rs:ready_plan`, `register` ; `workers.rs:341-364` ;
`docs/journal.md` (L05, écart 2, correction 10). Décision de l'orchestrateur : acceptés.

### 4.3 Annuaire des clés des membres : épinglage TOFU par le superviseur (L05b, 2026-11-21, Q25)

Le worker n'a pas de disque ; le superviseur, qui relaie `GET /api/runtime/v1/e2ee/members/keys`
(04 §4.3), tient l'épinglage. **Aucun message de pipe nouveau** : le contrôle porte sur la réponse
relayée, avant que le worker la voie. Source : `crates/supervisor/src/member_pins.rs`,
`workers.rs:member_keys_gate`.

- **Identité épinglée** : `SHA-256` de la `SubjectPublicKeyInfo` DER (`rsaEncryption`), recalculée
  depuis `n` et `e` (zéros de tête sans effet ; vecteur WebCrypto `exportKey('spki')` en test). Est
  aussi gardée l'empreinte RFC 7638 (`SHA-256` du JWK canonique), la même que
  `computeKeyFingerprint` de l'app, pour l'affichage et la comparaison hors bande.
- **Stockage** : `<state_dir>/member-rsa-pins.json`, données publiques (empreintes, jamais la clé),
  `{ "v": 1, "orgs": { org: { userId: { fingerprint, thumbprint, firstSeen, previous[], pending? } } } }`,
  écriture atomique (`fsync` + `rename`) **une fois par étape de contrôle, hors du verrou d'état**
  (`spawn_blocking`, photos ordonnées : une plus ancienne n'écrase jamais une plus récente) ; la
  réponse n'est rendue au worker qu'après l'écriture (échec : refus fermé `member_pins_unavailable`
  et alerte `member_pins_not_saved`). Absent : vide ; illisible : le superviseur ne démarre pas (pas
  de remise à zéro silencieuse). **Bornes** (revue I3) : 2 000 épingles par org (au-delà, refus
  fermé `member_pins_limit` et alerte), 16 empreintes précédentes par membre, 100 clés en attente
  par org (au-delà, le refus reste fermé sans être mémorisé). Mesure : 2 000 premières vues dans une
  réponse en 0,12 s, verrou d'état tenu au plus 16 ms (`integration.rs::cles_rsa_charge_et_plafond`).
- **Règle**, pour chaque membre de la réponse dont la clé est lisible et dans les bornes (sinon le
  worker l'écarte, `skippedRecipients`) : première vue du couple (org, utilisateur) → épinglée ;
  même empreinte → acceptée ; empreinte différente → **rotation** acceptée seulement selon une
  règle stricte (corrigée après revue, I1) : la chaîne de transitions d'identité
  (`GET /users/:userId/sign-key`, au plus 8 vérifications par réponse), suivie depuis la plus
  ancienne clé de signature épinglée (`user-pins.json`), doit **reproduire exactement**
  l'historique épinglé (mêmes clés de signature, dans l'ordre : une branche signée par une clé
  retirée est refusée même si elle rejoint ensuite la clé courante), aboutir exactement à la clé RSA
  présentée, et cette clé doit être garantie par une clé **non retirée** : maillon signé par la
  clé de signature courante ou une successeure, ou bien chaîne qui s'arrête sur la clé courante
  avec la clé RSA que `pins.rs` a liée à cette clé quand elle a été acceptée
  (`UserPin.rsaFingerprint`) ; sinon **refus**. **Aucun retour arrière** (revue I2) : une clé
  déjà épinglée par le passé (`previous`, 16 dernières) ou égale à l'épinglée n'est jamais acceptée
  par rotation, et la clé épinglée, si la chaîne la contient, la précède.
- **Refus global** : la réponse entière est remplacée par `409 {"error":"member_key_changed"}`
  (ou `member_pins_limit`, `member_pins_unavailable` ; corps illisible : `502 member_keys_unreadable`,
  revue M3 ; variante non canonique du chemin : `relay_refused` sans appel à l'API, revue M1) ;
  `create_thread` rend `member_key_changed` (§9) sans créer ni sceller quoi que ce soit, y compris
  pour un salon d'espace (choix le plus sûr : un salon créé sans un membre serait surprenant, et un
  annuaire où une clé a été substituée n'est plus digne de confiance). La clé refusée est mise en
  attente (`pending`) ; alerte `member_rsa_key_changed` (vue d'ensemble du dashboard, journal sans
  clé, empreinte ni identifiant).
- **Acceptation manuelle** : la vue d'ensemble liste les clés refusées (empreintes épinglée et
  proposée au format de l'app) ; l'admin du runtime, après comparaison hors bande avec le membre,
  accepte **la clé affichée** (`POST /api/member-keys/accept { userId, fingerprint }`, session +
  origine + CSRF ; une autre empreinte → `409 no_pending_key`). Pas de commande en ligne : le
  fichier est tenu en mémoire par le superviseur en marche.
- **Limites** : la première vue vient de l'API (TOFU) ; un membre qui n'a jamais délégué au runtime
  n'a pas de clé de signature épinglée et `sign-key` ne le sert pas (04 §4.1) : sa rotation légitime
  n'est acceptée que par l'admin. La clé RSA du propriétaire n'est pas liée à son mandat (00 §6, Q25).

## 5. Métriques (sans contenu, P9)

```json
{ "type": "metrics", "turn": 3, "steps": 5, "llmCalls": 4, "toolCalls": 2, "toolErrors": 0,
  "promptTokens": 3120, "completionTokens": 410, "reasoningTokens": 0, "costEurMicro": 1840,
  "llmLatencyMs": { "p50": 820, "max": 2300 }, "turnDurationMs": 9100 }
```

CPU et RAM ne viennent pas du worker : le superviseur les lit dans le cgroup du worker
(`memory.current`, `memory.peak`, `cpu.stat`, L06) et les associe aux métriques. Aucun champ ne
contient de texte de la conversation, de nom de fichier, d'argument d'outil ni de nom de salon ; seul
le **nom de l'outil** est autorisé dans un compteur par outil. Le dashboard (L08) n'a accès qu'à ces
métriques.
**Écart L08** : le worker n'émet **aucun** compteur par outil (seulement les compteurs globaux ci-dessus) ;
la chronologie du dashboard ne nomme donc pas l'outil (11 §5, question ouverte : 00 §6, Q29 b).

## 6. Ce que reçoit le worker et ce qu'il ne peut pas faire

Reçoit : identité de sa conversation, `authId`, `leaseEpoch`, sa configuration LLM, ses plafonds, sa
politique d'outils, les clés de **sa** conversation et de l'org pour **son** utilisateur.

Ne peut pas (L06 le teste) : lire les clés ou la mémoire d'un autre worker ou du superviseur, lire le
disque hôte, joindre un hôte hors de la liste (API, fournisseurs LLM configurés, passerelle), signer
une requête lui-même, dépasser ses plafonds `memory.max` / `cpu.max` / `pids.max` (09 §2).

## 7. Journaux

Les trames `0x02` ne sont jamais journalisées, même en mode débogage ; les trames `0x01` ne sont
journalisées que par leur `type` et leur taille. `Debug` des types de clés masqué (comme
`SessionKey`, `Synco_AI_Gateway/src/crypto.rs:18-22`).

## 8. Cycle de vie (rappel, détail en 08 et L06)

1. Le superviseur prend le bail de la conversation (07 §4) **avant** de lancer le worker et lui
   transmet `leaseEpoch` ; le worker renouvelle le bail par `signed_request` toutes les 20 s.
2. Lancement : `init` → `ready` → clés → `start`.
3. Fin : le worker écrit l'historique, rend le bail, envoie `done`, quitte. Inactivité
   (`idleShutdownSecs`) ou attente d'un humain (`awaiting_*`) : il quitte aussi (P3 : le worker ne vit
   que lorsqu'il travaille).
4. Plantage (code ≠ 0, signal, canal fermé) : 08 §5.

## 9. Codes machine du worker (L07, L07b)

Résultats d'outil `{"error": code}` donnés au modèle (le code n'est pas un `lastErrorCode` de 08 §6) :

| Code | Cas |
|---|---|
| `tool_unavailable_in_runtime` | Outil que le worker ne peut pas exécuter dans son bac à sable : **`create_file`, `create_folder`, `list_documentation`, `read_documentation`, `search_documentation`**. Retirés de la liste d'outils donnée au modèle (`UNAVAILABLE_IN_RUNTIME`), refusés explicitement s'ils sont appelés quand même. `create_file` : le CDN est injoignable du worker ; `create_folder` : aucune route du canal ; documentation : embarquée dans `synco_app` |
| `tool_call_unverified` | Reprise : un appel **mutant** `accepted` qui ne correspond pas au `pendingToolCall` déchiffré est clos sans exécution (historique forgé ou illisible) |
| `invalid_tool_arguments` | Arguments de l'appel illisibles (dont `finish_reason: length`) : aucune exécution |
| `invalid_upload_ref` | Réponse `upload` dont `ref` n'est pas un identifiant (00 §3.2) |
| `too_many_recipients` | `create_thread` : plus de **300** destinataires de clé RSA (corps du canal ≤ 256 Kio, 04 §4.3) ; aucun salon créé pour cet élément (champ `max`) |
| `too_many_threads` | `create_thread` : plus de 10 salons par appel |
| `no_recipient_key` | `create_thread` : aucune clé de membre exploitable |
| `member_key_changed` | `create_thread` : le superviseur a refusé l'annuaire des membres, une clé RSA a changé sans preuve (§4.3, Q25) ; aucun salon créé, rien de scellé (champ `note`) |
| `unknown_outcome` | Issue inconnue d'un outil mutant (08 §5) |

Avertissements de `create_thread` (champ `warning` du résultat, le salon existe) : `key_envelope_unavailable`,
`key_envelope_not_posted`, `delegation_entry_not_posted` — le salon reste accepté en TOFU (03 §10.1).
Les membres dont la clé RSA publique est illisible ou **de moins de 2048 bits** sont écartés et
comptés dans `skippedRecipients` (jamais en silence). Le worker ne scelle la clé d'un salon **d'espace**
que pour le propriétaire (le canal ne donne pas les membres d'un espace, 04 §4.3).

Erreurs de l'interface LLM (`LlmError`, `crates/worker/src/provider/mod.rs`), codes de journal :

| Variante | Code | Nouvel essai | Effet |
|---|---|---|---|
| `Transport` | `llm_transport` | oui | |
| `Auth` | `llm_auth` | non | `failed` `provider_auth` |
| `RateLimited { retry_after_secs }` | `llm_rate_limited` | oui | (inclut `proxy_*rate_limited`, `proxy_runtime_token_budget`, `proxy_busy`) |
| `CallBudget` | `llm_call_budget` | non | fin du tour, `idle` `step_limit` |
| `TokenBudget` | `llm_token_budget` | non | `failed` `budget_exceeded` |
| `Timeout` | `llm_timeout` | oui | |
| `Rejected { status }` | `llm_rejected` | non | |
| `Provider { status }` | `llm_provider` | oui | |
| `BadStream` | `llm_bad_stream` | oui | flux illisible, erreur dans le flux, ou **flux coupé** (voir ci-dessous) |
| `TooLarge` (**ajouté par L07**) | `llm_too_large` | non | texte + raisonnement cumulés > **4 Mio** ou arguments d'outils cumulés > **1 Mio** dans une réponse ; `failed` `provider_error` |

**Adaptateurs** (L07b ; interface inchangée ; `adapter_for`) : `openai`, `gateway`, `custom` =
dialecte compatible OpenAI ; `mistral` (`provider/mistral.rs`) ; `gemini` (`provider/gemini.rs`).
Les flux de Mistral et Gemini sont écrits d'après la documentation et des retours publiés, **jamais
testés contre les vrais fournisseurs** (recette manuelle).

- **Gemini** par l'endpoint **compatible OpenAI** (`base_url` du runtime
  `https://generativelanguage.googleapis.com/v1beta/openai`) : l'API native est refusée par la liste
  blanche du mandataire (10 §4, `POST /chat/completions` seulement). Pas de `include_thoughts` (Google
  refuserait `reasoning_effort` combiné à `thinking_config`, d'après un retour tiers) : le
  raisonnement n'est lu que si le serveur le rend (`extra_content.google.thought`, `<thought>`) ;
  `reasoning_tokens` seulement si `completion_tokens_details.reasoning_tokens` est présent (non
  documenté), sinon absent ; `max_tokens` = `maxOutputTokensPerCall` ; pas de `parallel_tool_calls`.
- **Mistral** (`base_url` `https://api.mistral.ai/v1`) : les identifiants d'appel d'outil du worker
  (`call_<24 hex>`) sont **traduits** en 9 caractères alphanumériques **dans la requête seulement**
  (hachage FNV-1a en base 62, sans collision dans la requête) ; l'historique garde l'identifiant du
  worker. Pas de `stream_options` ; `parallel_tool_calls: false` quand des outils sont fournis ; `usage` attendu dans le dernier morceau (non garanti par la documentation lue : sans lui, la boucle estime les tokens).
- **Flux coupé** (fermé sans `finish_reason` ni `[DONE]`) : `BadStream` (donc nouvel essai) pour
  **Mistral et Gemini** ; pour `openai`, `custom` et `gateway`, fin silencieuse `stop` comme le TS
  (écart de comportement entre adaptateurs : **question ouverte**, voir 00 §6).
- **`reasoning_effort` limité aux modèles qui l'acceptent** : passerelle : toujours envoyé (champ de sa
  liste blanche) ; OpenAI : modèles à raisonnement (`o1`, `o3`, `o4`, `gpt-5`) ; `custom` : jamais ; Gemini : préfixes `gemini-2.5`, `gemini-3`, `gemini-4`
  (jamais `minimal`, `none`, `xhigh`) ; Mistral : `mistral-large-4*` seulement (`low|medium|high`).
  Les autres modèles Mistral n'acceptent que `high|none` : **aucun effort** n'est envoyé (la
  correspondance avec l'effort de l'org est une décision produit non prise, **question ouverte**).
