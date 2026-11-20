# 06 — Protocole superviseur ↔ worker (pipe)

Le superviseur lance **un process worker par conversation active** (P3, L06) et lui parle par un
**seul** canal : une paire de descripteurs hérités (`socketpair` `AF_UNIX`, `SOCK_STREAM`) sur le
descripteur 3 du worker. Aucun autre descripteur n'est hérité (en dehors de stdin/stdout/stderr
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
  kind    u8         0x01 = conv, 0x02 = thread, 0x03 = space, 0x10 = llm_credential (dépend de D1)
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

## 3. Superviseur → worker

| `type` | Champs | Moment |
|---|---|---|
| `init` | `sessionId`, `userId`, `orgId`, `runtimeId`, `authId`, `leaseEpoch`, `apiBaseUrl`, `llm` (§3.1), `limits` (§3.2), `toolPolicy` (D5 : `{ "<outil>": "auto" \| "ask" \| "deny" }`), `logLevel` | Première trame, suivie des trames de clés, puis `start` |
| `start` | — | Le worker peut commencer (toutes les clés initiales reçues) |
| `inbox` | `items` : éléments de boîte de réception tels que reçus (05 §6.2, champs encore chiffrés) | Message, décision ou annulation arrivés par WebSocket |
| `keys` | (trame `0x02`) | Clé ajoutée (synchro P11) ou retirée (révocation) |
| `shutdown` | `graceMs`, `reason` (`idle` \| `revoked` \| `unpaired` \| `sigterm` \| `limit`) | Arrêt demandé : terminer l'étape en cours si `graceMs > 0`, enregistrer, quitter |
| `net_response` | dépend de L06 | Réponse d'un accès réseau relayé par le superviseur, si L06 choisit ce modèle |
| `signed_request_response` | `id`, `status`, `headers`, `body`, `part?`, `last?`, `error?` | Réponse à `signed_request` (§4), en une ou plusieurs parties |
| `snapshot_request` | `requestId` | **Ajout L05** : un client reprend hors du tampon de rejeu (05 §3) ; le worker répond par `snapshot` (§4) |

### 3.1 Configuration LLM (`llm`)

`{ "provider": "openai" | "mistral" | "gemini" | "gateway" | "custom", "model": "…", "baseUrl": "…", "reasoningEffort": "low" | "medium" | "high", "pricing": { "inputPerMTok": <€>, "outputPerMTok": <€> } | null }`.
Les secrets (clé API du fournisseur) passent en trame `0x02` (`llm_credential`) ou pas du tout si le
superviseur relaie le réseau et les injecte lui-même — **dépend de D1 et de L06**. Pour `gateway`, le
worker obtient un ticket `sgt1` par `signed_request` vers `POST /api/runtime/v1/tickets/llm`.

### 3.2 Plafonds (`limits`)

`{ "maxStepsPerTurn", "maxTokensPerConversation", "maxTokensPerTurn", "maxTurnDurationSecs", "maxOutputTokensPerCall", "maxToolResultBytes", "idleShutdownSecs" }`
— valeurs de 09 §2, bornées par la politique de l'org (07 §6). **Révisé après L05, 2026-11-20** :
`maxTokensPerTurn` et `maxOutputTokensPerCall` (09 §2) font partie de `limits` (`WorkerLimits`,
`pipe.rs`), les sept champs sont tous obligatoires (désérialisation stricte).

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
| `net_request` | dépend de L06 | Accès réseau relayé |
| `log` | `level`, `code`, `fields` (sans contenu) | Journal structuré |
| `done` | `reason` (`idle` \| `awaiting` \| `failed` \| `cancelled` \| `shutdown`) | Le worker va quitter (code 0) |

Le superviseur limite le débit des `signed_request` (09 §2) et refuse un chemin hors liste
(journalisé comme incident de sécurité, worker tué).

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
