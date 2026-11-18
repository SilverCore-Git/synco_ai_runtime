# 04 — Canal interne runtime → API

Le runtime est chez le client : il joint synco_api **par Internet**, sur l'API publique (préfixe
`/api/runtime/v1`), et non sur un port privé comme le CDN (`cdnInternalServer.ts`). L'authentification
repose donc entièrement sur la signature Ed25519 de chaque requête par la clé `sig` du runtime,
enregistrée à l'appairage (01). Conventions : [00 §3](00-vue-ensemble.md).

## 1. Montage côté API

- Routeur dédié monté sur `/api/runtime/v1`, **hors** `authMiddleware` (pas de jeton Keycloak), avec
  son propre limiteur de débit par `runtimeId` (09 §4) et un corps brut lu tel quel (les octets
  signés), plafonné à 8 Mio (`PUT …/transcript`) et 256 Kio ailleurs.
- Le module IA (`features` contient `ai`, `activeModules.ai === true`) et l'absence de bannissement de
  l'org (`orgBanMiddleware`) sont vérifiés à chaque requête, comme pour les routes `/ai`.

## 2. Signature des requêtes

### 2.1 En-têtes

| En-tête | Valeur |
|---|---|
| `x-synco-runtime` | `runtimeId` |
| `x-synco-timestamp` | secondes Unix, `^\d{1,12}$` |
| `x-synco-nonce` | `b64u` de 16 octets aléatoires (22 caractères) |
| `x-synco-auth` | `authId` de l'autorisation de session (§3), **absent** pour les routes sans utilisateur |
| `x-synco-signature` | `b64u` de la signature Ed25519 (64 octets) |

### 2.2 Octets signés

```
"synco-rt-request-v1\0" ‖ utf8( METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" RUNTIME_ID "\n" AUTH "\n" b64u(SHA-256(CORPS)) )
```

- `METHOD` en majuscules ; `PATH` = chemin **et** chaîne de requête exactement tels qu'envoyés
  (`req.originalUrl`, encodage pourcent conservé), contrairement au CDN qui ignore la requête
  (`internalAuth.ts:7-10`) : certaines routes du runtime sont paginées ;
- `AUTH` = valeur de `x-synco-auth`, ou `-` si absent ;
- `CORPS` = octets exacts du corps (vide → SHA-256 de la chaîne vide).

### 2.3 Vérification (ordre)

1. En-têtes présents et bien formés → `401 rt_sig_missing`.
2. `|TIMESTAMP − maintenant| ≤ 60 s` (comme `MAX_CLOCK_DRIFT_SECS`, `internalAuth.ts:15`) →
   `401 rt_clock_skew`.
3. `AiRuntime` trouvé par `runtimeId` → sinon `404 rt_unknown` ; statut `active` → sinon
   `401 rt_revoked`.
4. Signature Ed25519 valide avec `AiRuntime.sigPublicKey` → `401 rt_sig_invalid`.
5. Anti-rejeu : `(runtimeId, NONCE)` absent du cache, puis inséré avec une durée de vie de 120 s
   (≥ 2 × fenêtre) → sinon `401 rt_replay`. Cache LRU borné en mémoire (100 000 entrées) : même
   limite que les quotas de `ws.ts` (un déploiement multi-instance devra partager ce cache).
6. Si `x-synco-auth` est présent : vérifications de §3.2.

Exemple (requête `POST /api/runtime/v1/conversations/0f0e…0100/status`, corps
`{"baseRev":12,"status":"running"}`, graine `sig` = `0x11` × 32) :

```
POST
/api/runtime/v1/conversations/0f0e0d0c-0b0a-4908-8706-050403020100/status
1795000400
WlpaWlpaWlpaWlpaWlpaWg
7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f
9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a
UvOjs3du6XMq1sU_UIFE_rVWfOC6WjzKx__91hqbcfw
→ x-synco-signature: sPPFa6e54n7Vdg4HZSV8SZiqRkb8L3_xoihfgyqKKUG5-JGBySBhgBnbVRwHtBuy6RDvmgYWi2w76Nm7QPbhBg
```

(Ed25519 est déterministe : valeur reproductible. Fichier : [exemples/exemples.json](exemples/exemples.json), clé `request`.)

## 3. Autorisation de session

### 3.1 Forme

Créée par l'API à la **bascule** d'une conversation vers le runtime (§5, `switch-to-runtime`), une par
conversation active. Enregistrement `AiSessionAuthorization` (07 §3) :

| Champ | Sens |
|---|---|
| `id` (`authId`) | UUID v4 tiré par l'API. **Pas un secret** : l'authentification est la signature du runtime ; l'`authId` lie explicitement la requête à un contexte (utilisateur, org, conversation) au lieu de le déduire du chemin. |
| `userId`, `orgId`, `sessionId`, `runtimeId` | Contexte |
| `delegationId` | Délégation active de (utilisateur, runtime) au moment de la création ; mise à jour quand la délégation est remplacée |
| `expiresAt` | = `expiresAt` de la délégation active, mis à jour à chaque renouvellement |
| `revokedAt`, `revokedReason` | Révocation |

Le runtime apprend l'`authId` par le flux de notifications (`conversation.authorized`, §6) ou par
`GET /api/runtime/v1/conversations?state=pending`.

### 3.2 Vérifications à chaque requête portant `x-synco-auth` (second verrou, mesure 6)

1. Autorisation trouvée, `runtimeId` = signataire → sinon `403 auth_invalid`.
2. Non révoquée → `403 auth_revoked` ; `expiresAt > maintenant` → `403 auth_expired`.
3. Délégation `delegationId` au statut `active`, `expiresAt > maintenant` → `403 delegation_expired` /
   `delegation_revoked`.
4. L'utilisateur est **toujours** membre de l'org (`getPermission(userId, { orgId })`), org non bannie,
   politique runtime de l'org l'autorise (07 §6) → `403 auth_invalid`.
5. Conversation : propriétaire = `userId`, org = `orgId`, régime `runtime`, `runtimeId` = signataire ;
   si la route porte un `:sessionId`, il doit être celui de l'autorisation → `403 out_of_scope`.

Toute route qui renvoie un contenu chiffré ou agit au nom d'un utilisateur **exige** `x-synco-auth`.
Ces contrôles sont faits **avant** toute lecture de données.

## 4. Liste fermée des routes du runtime

Préfixe `/api/runtime/v1`. Toute route absente de cette liste n'existe pas pour le runtime ; en
ajouter une (L14/L15) = modifier ce document. Colonne « Auth » : **S** = signature seule ;
**S+A** = signature + autorisation de session (§3.2).

### 4.1 Runtime (sans utilisateur)

| Méthode et chemin | Auth | Rôle | Lot |
|---|---|---|---|
| `POST /register` | S | Corps `{ url, software: { version } }`. Appairage terminé ? → `{ orgId, certificate }`, sinon `404 rt_unknown` (01 §7). Met à jour `lastSeenAt`, version. | L02 |
| `POST /unpair` | S | Désappairage demandé par l'opérateur (01 §9) | L02 |
| `GET /stream` | S | Mise à niveau WebSocket du flux de notifications (§6) | L02 |
| `GET /llm-policy` | S | Politique IA de l'org pour le runtime : fournisseurs et modèles autorisés, `reasoningEffort`, `toolPolicy` (D5), plafonds de l'org (D4/D6). **Aucun secret** (dépend de D1) | L02 |
| `GET /llm-credentials` | S | **Seulement si D1 = B ou C** : clés API des fournisseurs de l'org | L02 |
| `GET /delegations` | S | Délégations `active` de l'org pour ce runtime : `{ delegationId, userId, scope, iat, exp, wrap, mandateSignature }[]` | L03 |
| `GET /delegations/:delegationId/entries?after=<curseur>&limit=<≤500>` | S | Entrées `{ id, kind, ref, version, ciphertext }` | L03 |
| `POST /delegations/:delegationId/status` | S | `{ "status": "ok" \| "unusable" }`, sans cause (03 §12) | L03 |
| `GET /users/:userId/sign-key` | S | `{ publicSignKey, transitions }` d'un utilisateur ayant une délégation (active ou non) vers ce runtime ; sinon `404` | L03 |
| `GET /conversations?state=pending` | S | Conversations de l'org en régime runtime sur ce runtime qui demandent un worker : `queued`, `running` à bail expiré, `awaiting_key` dont la clé est désormais déléguée. `{ sessionId, userId, authId, status }[]` | L03 |
| `POST /metrics` | S | État du runtime sans contenu (version, workers actifs, file d'attente) pour l'écran de Synco ; ≤ 1 / min | L02 |

### 4.2 Au nom d'un utilisateur (conversation)

`:sessionId` est toujours la conversation de l'autorisation.

| Méthode et chemin | Auth | Rôle | Lot |
|---|---|---|---|
| `GET /conversations/:sessionId` | S+A | `{ id, title, messages, rev, status, pendingToolCall, encryptionScheme, leaseEpoch }` (champs chiffrés `gcm1:`) | L03 |
| `POST /conversations/:sessionId/lease` | S+A | Prendre ou renouveler le bail (07 §4) → `{ leaseEpoch, expiresAt }` ou `409 lease_conflict` | L03 |
| `DELETE /conversations/:sessionId/lease` | S+A | Rendre le bail (`leaseEpoch` dans le corps) | L03 |
| `PUT /conversations/:sessionId/transcript` | S+A | `{ leaseEpoch, baseRev, messages, title?, status, pendingToolCall, consumedInbox: [id] }` → `{ rev }` ou `409 rev_conflict` / `lease_conflict` (07 §4) | L03 |
| `POST /conversations/:sessionId/status` | S+A | `{ leaseEpoch, status, error? }` (changement d'état sans réécrire l'historique ; `error` = code) | L03 |
| `GET /conversations/:sessionId/inbox?after=<curseur>` | S+A | Éléments non consommés (messages, décisions, annulations) déposés par le client via l'API ou par le runtime (05 §6) | L03 |
| `POST /conversations/:sessionId/inbox` | S+A | Le runtime rend durable un élément reçu par WebSocket **avant** d'en accuser réception au client (idempotent par `id`) | L03 |
| `GET /conversations/:sessionId/tools` | S+A | Manifeste des outils (même contenu que `GET /api/orgs/:orgId/ai/tools`, `aiChat.ts:216-226`) | L03 |
| `POST /conversations/:sessionId/tools/:name/execute` | S+A | Outil `server` (§5) | L03 |
| `POST /conversations/:sessionId/push` | S+A | `{ type }` ∈ `AI_TURN_DONE`, `AI_AWAITING_CONFIRMATION`, `AI_AWAITING_KEY`, `AI_AWAITING_USER`, `AI_FAILED` ; titre et corps construits par l'API, **sans contenu** ; ≤ 1 / 30 s par conversation | L03 |
| `POST /tickets/llm` | S+A | Ticket `sgt1` pour l'utilisateur de l'autorisation, `rt` renseigné (02 §4) | L02 |

### 4.3 Données E2EE de l'org (dans le périmètre de la délégation)

Toutes **S+A**. En plus de §3.2, chaque route vérifie : la ressource appartient à l'org de
l'autorisation ; l'utilisateur y a accès **maintenant** (`getPermission`, mêmes services que les routes
HTTP de l'utilisateur) ; la délégation active contient l'entrée de la clé nécessaire (sinon
`403 key_not_delegated`, pour ne pas servir de chiffré inutilisable). Jamais de DM, de support, ni
d'autre org : ces routes n'existent pas.

| Méthode et chemin | Équivalent utilisateur | Rôle | Lot |
|---|---|---|---|
| `GET /e2ee/threads/:threadId/messages?before=&limit=` | `GET /api/messages/threads/:threadId` | Messages chiffrés d'un salon | L03 |
| `GET /e2ee/search-index/workspace/:workspaceId` | `GET /api/search-index/workspace/:workspaceId` (`searchIndex.ts:20`) | Index chiffrés, **sans** `threadKeys` (le runtime les a par la délégation) | L03 |
| `GET /e2ee/members/keys` | annuaire des membres | Clés publiques RSA et de signature des membres de l'org, pour sceller une nouvelle clé ; le runtime les épingle en TOFU comme `resolveRecipientKey` | L03 |
| `POST /e2ee/threads` | `POST /api/threads/org/:orgId`, `/api/threads/space/:spaceId` (`threads.ts`) | Créer un salon : mêmes champs que `createThreadSchema` (`validators/index.ts:125-144`) + `spaceId?` ; `creatorId` = `rt1:<delegationId>` posé par l'API (03 §10) | L03 |
| `POST /delegations/:delegationId/entries` | — | Le runtime ajoute l'entrée d'une clé qu'il a créée (03 §10) | L03 |
| `POST /e2ee/cdn/uploads` | `POST /api/cdn/transfers/uploads` (`cdnTransferRoutes.ts:66`) | Ouvrir un envoi CDN pour l'utilisateur (outil `create_file`) | L03 |

Extensions prévues (à spécifier ici par L14/L15 avant d'être codées) : lecture de fichiers (ticket
`down`), envoi de message dans un salon, documentation.

## 5. Outils `server` exécutés pour le runtime

`POST /conversations/:sessionId/tools/:name/execute` reprend exactement la logique de
`POST /api/orgs/:orgId/ai/tools/:name/execute` (`aiChat.ts:254-292`) : module IA actif,
`getPermission(userId, { orgId })`, outil de catégorie `server` avec `execute`, puis
`spec.execute({ orgId, userId, args })`. `userId` et `orgId` viennent **de l'autorisation**, jamais du
corps. Le résultat est renvoyé en clair au runtime (comme aujourd'hui à la passerelle) ; c'est le
worker qui le chiffre avant de l'enregistrer.

Route de bascule (côté utilisateur, L03), rappelée ici car elle crée l'autorisation :

- `POST /api/orgs/:orgId/ai/sessions/:sessionId/switch-to-runtime` — corps
  `{ runtimeId, delegationId, baseRev, messages, title, convKey: { encryptedKey, commitment, signature }, convEntry: { kind: "conv", ref, version, ciphertext } }` :
  propriétaire seulement, délégation active du même utilisateur vers ce runtime, `encryptionScheme`
  devient `conv-gcm1-v1` (transition autorisée depuis `null`, `gateway-aes-gcm-v1` ou
  `conv-gcm1-v1`), crée l'autorisation, journalise (`AiChatSessionEvent`), notifie le runtime.
- `POST /api/orgs/:orgId/ai/sessions/:sessionId/switch-to-local` : révoque l'autorisation, supprime
  l'entrée `conv` de la délégation, rend le bail, régime `client`, notifie le runtime
  (`conversation.revoked`).

## 6. Flux de notifications (WebSocket sortant)

`GET /api/runtime/v1/stream` avec en-tête `Upgrade: websocket`, signé comme une requête `GET` de
corps vide (§2). Serveur : bibliothèque `ws` (déjà résolue dans `synco_api`, version 8.21.3 via
`overrides` de `package.json`) sur le serveur HTTP de l'API. Une seule connexion par runtime ; une
nouvelle connexion ferme la précédente.

- **API → runtime** : trames texte JSON `{ "v": 1, "type": "<type>", ... }`, sans contenu chiffré :

| `type` | Champs | Effet attendu du runtime |
|---|---|---|
| `hello` | `orgId`, `serverTime` | Contrôle d'horloge (écart > 30 s → alerte dashboard) |
| `conversation.authorized` | `sessionId`, `userId`, `authId` | Mémoriser l'autorisation |
| `conversation.wake` | `sessionId`, `authId`, `reason` (`inbox` \| `decision` \| `keys`) | Lancer ou réveiller le worker |
| `conversation.revoked` | `sessionId`, `reason` | Arrêter le worker, oublier `CK`, fermer les WebSocket clients (`4403`) |
| `delegation.updated` | `userId`, `delegationId` | Recharger la délégation (03 §9) |
| `delegation.entries_added` | `delegationId`, `after` | Lire les nouvelles entrées |
| `delegation.entries_removed` | `delegationId`, `entries: [{kind, ref, version}]` | Effacer ces clés |
| `delegation.revoked` | `userId`, `delegationId`, `reason` | Effacer `DK` et les clés ; arrêter les workers de l'utilisateur |
| `user.revoked` | `userId`, `until` | Liste de révocation des tickets (02 §8) |
| `runtime.unpaired` | — | 01 §9 |
| `ping` | — | Répondre `pong` |

- **Runtime → API** : uniquement `{ "v": 1, "type": "pong" }` et `{ "v": 1, "type": "presence", "workers": <n> }` (≤ 1 / 30 s).
- Présence : le runtime est « en ligne » tant que la connexion est ouverte (`AiRuntime.lastSeenAt`
  mis à jour), exposée aux membres (`GET /api/orgs/:orgId/ai/runtime` → `online: boolean`).
- Ping toutes les 25 s ; sans `pong` en 60 s, l'API ferme. Reconnexion du runtime : backoff
  exponentiel 1 s → 60 s avec gigue ; après reconnexion il relit `GET /delegations` et
  `GET /conversations?state=pending` (les notifications ne sont pas rejouées : elles ne sont que des
  « réveils »).

## 7. Journaux

Ni l'API ni le runtime ne journalisent : corps des requêtes du canal, `wrap`, `mandateSignature`,
entrées, valeurs `gcm1:`, arguments ou résultats d'outils, tickets. Seuls : méthode, gabarit de route
(`/conversations/:sessionId/transcript`), `runtimeId`, code de résultat, durée, taille.

## 8. Codes d'erreur

| Code | HTTP | Sens |
|---|---|---|
| `rt_sig_missing` | 401 | En-têtes de signature absents ou mal formés |
| `rt_clock_skew` | 401 | Horodatage hors fenêtre de ±60 s |
| `rt_unknown` | 404 | Runtime inconnu (non appairé) |
| `rt_revoked` | 401 | Runtime désappairé |
| `rt_sig_invalid` | 401 | Signature invalide |
| `rt_replay` | 401 | Nonce déjà vu |
| `rt_rate_limited` | 429 | Débit dépassé |
| `auth_invalid` | 403 | Autorisation inconnue, d'un autre runtime, ou utilisateur plus autorisé |
| `auth_revoked` / `auth_expired` | 403 | Autorisation révoquée / expirée |
| `delegation_expired` / `delegation_revoked` | 403 | Délégation plus active |
| `out_of_scope` | 403 | Ressource hors de l'autorisation (autre conversation, autre org) |
| `key_not_delegated` | 403 | La clé nécessaire n'est pas dans la délégation |
| `forbidden` | 403 | Permission de l'utilisateur refusée par le service métier |
| `lease_conflict` | 409 | Bail détenu par un autre worker, ou `leaseEpoch` périmé |
| `rev_conflict` | 409 | `baseRev` ≠ révision courante |
| `invalid_body` | 400 | Corps invalide |
| `ai_disabled` | 403 | Module IA désactivé ou org bannie |
