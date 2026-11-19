# 03 — Délégation des clés au runtime

Couvre P5, P11 et les mesures 5 (délégation liée à son contexte) et 6 (expiration à double verrou).
Conventions : [00 §3](00-vue-ensemble.md).

## 1. Principe et menace traitée

Une enveloppe ECDH vers la clé publique `kex` du runtime **ne dit pas qui l'a produite** : n'importe
qui, synco_api compris, peut chiffrer vers une clé publique. Si le runtime acceptait de telles
enveloppes, une API malveillante pourrait lui « déléguer » une clé qu'elle connaît (fausse clé de
salon, fausse clé de conversation) ; le runtime chiffrerait ensuite avec elle du contenu produit à
partir de vraies données, que l'API lirait.

La délégation a donc trois couches :

| Couche | Produite par | Garantit |
|---|---|---|
| **Mandat** | le client, signé par la clé de signature d'identité de l'utilisateur (ECDSA P-256, FC4) | L'utilisateur a bien délégué, à **ce** runtime (empreinte), pour **cette** org, ce périmètre, jusqu'à cette date. Engage l'empreinte de l'enveloppe de tête. |
| **Enveloppe de tête** | le client | Transmet au seul runtime la clé de délégation `DK` (32 octets aléatoires propres à la délégation). AAD : utilisateur, org, runtime, délégation, périmètre, émission, expiration (mesure 5). |
| **Entrées** | le client (ou le runtime, §10) | Chaque clé de l'org, chiffrée sous `DK`, liée par AAD à la délégation et à son contexte. Sans `DK`, impossible d'en fabriquer une qui s'ouvre. |

L'API stocke ces trois couches **sans pouvoir les vérifier ni les fabriquer** (§12). Le contrôle est
fait par le runtime (mandat, AAD) et, en amont, par le client (certificat, épinglage, défi : 01 §6.3).

## 2. Ce qui est délégué, et ce qui ne l'est jamais

| `kind` | `ref` | `version` | Clé | Source côté client |
|---|---|---|---|---|
| `thread` | `threadId` | `1` | Clé AES-256 du salon (`ThreadKey`, `schema.prisma:659`, non versionnée) | `decryptThreadKeyWithRsa` (`crypto.ts:305`) |
| `space` | `workspaceId` | version de la `WorkspaceKey` (`schema.prisma:696`) | Clé AES-256 de l'espace, **toutes** les versions détenues (les fichiers anciens restent chiffrés sous les anciennes) | `workspaceCrypto.ts` |
| `conv` | `sessionId` | `1` | Clé de conversation `CK` (§6) | §6.2 |

Valeurs **réservées, refusées en v1** par l'API et par le runtime : `org` (`OrgKey`, `schema.prisma:682`,
aucun usage dans `synco_app/src`), `ai` (`AiSessionKey` partagée par l'org, cf. 00 §6 Q1).

**Jamais délégués** (aucun `kind` n'existe ; l'API et le runtime refusent toute valeur hors liste) :
AK, clés privées d'identité (RSA, ECDSA), clés d'appareil et DK d'appareil, clé de récupération,
secrets PIN, clés de DM (`DMConversationKey`, `dmCrypto.ts`), clés de tickets de support
(`support:<id>`), clés d'une autre org.

Seules les clés que l'utilisateur **détient lui-même** sont déléguées : l'API vérifie au dépôt qu'il
possède la ligne correspondante (`ThreadKey` / `WorkspaceKey` à son nom dans l'org, conversation dont il
est propriétaire).

## 3. Enveloppe de tête

Entrées : `userId`, `orgId`, `runtimeId`, `delegationId` (UUID v4 tiré par le client), `scope`
(v1 : toujours `org`), `iat`, `exp` (secondes), `kex` du runtime (`JWK-EC`, celle du certificat
vérifié), `DK` (32 octets aléatoires).

```
(epk_priv, epk) = paire ECDH P-256 éphémère (une par délégation)
ctx    = "synco-rt-delegation-v1|" userId "|" orgId "|" runtimeId "|" delegationId "|" scope "|" iat "|" exp "|" kex "|" epk
shared = ECDH(epk_priv, kex)                                  (coordonnée x, 32 octets)
KEK    = HKDF-SHA256(ikm = shared, salt = utf8("synco-rt-delegation-v1"), info = utf8(ctx), L = 32)
iv     = 12 octets aléatoires
blob   = iv ‖ AES-256-GCM(KEK, iv, DK, aad = utf8(ctx))           (ciphertext ‖ tag 16 octets)
wrap   = "srd1." b64u(utf8(epk)) "." b64u(blob)
```

Calqué sur `createDeviceEnvelope` (`e2eeV4.ts:151-167`) : ECDH éphémère, HKDF-SHA256 dont l'`info`
contient le contexte et les deux clés publiques, AES-GCM avec l'AAD de contexte. Différences voulues :
préfixe de version `srd1`, `b64u`, ordre RFC 7638 des JWK, et `exp`/`scope` dans le contexte.

Ouverture (runtime) : découper en exactement trois parties, préfixe `srd1`, `epk` = `JWK-EC`
canonique valide (point sur la courbe), `blob` ≥ 12 + 32 + 16 octets ; recalculer `ctx` à partir des
champs **de l'enregistrement de délégation** et de **sa propre** `kex` ; échec GCM →
`delegation_unusable`.

## 4. Mandat

```
mandateBytes = "synco-rt-mandate-v1|" userId "|" orgId "|" runtimeId "|" delegationId "|" scope "|" iat "|" exp "|" fprHex "|" b64u(SHA-256(utf8(wrap)))
signature    = ECDSA-P256-SHA256(clé de signature d'identité de l'utilisateur, utf8(mandateBytes))   (P1363, b64)
```

`fprHex` est l'empreinte du runtime (01 §2.1) **calculée par le client** à partir des clés vérifiées.

Vérification par le runtime (L05), avant toute ouverture :

1. `runtimeId` = le sien, `orgId` = son org, `scope` connu, `iat ≤ maintenant + 300`,
   `maintenant < exp`, `exp − iat ≤` durée maximale de sa configuration (09 §1) ; `fprHex` = sa propre
   empreinte. La crate exige aussi `iat < exp` et des champs conformes à 00 §3.2
   (`DelegationContext::validate`, `crates/synco-e2ee/src/delegation.rs:73-80`, `check_time`, `:84-89`).
2. Clé de signature de l'utilisateur : le runtime tient un **épinglage TOFU** par utilisateur (fichier
   d'état, données publiques) :
   - première vue : `GET /api/runtime/v1/users/:userId/sign-key` (04 §4) → épinglée ;
   - ensuite : la clé servie doit être l'épinglée, ou l'aboutissement d'une chaîne de transitions
     d'identité valide partant de l'épinglée (même algorithme que `identityChainPath`,
     `e2eeV4.ts:530-544`, porté dans `synco-e2ee`) ; sinon refus et alerte dans le dashboard.
3. Signature valide → sinon `delegation_unusable`.

Limite assumée (00 §6 Q3) : au tout premier contact, la clé de l'utilisateur vient de l'API.

**Chemin imposé côté runtime (révisé après la vague B, 2026-11-19).** Le mandat est vérifié sur
l'enveloppe de tête **réellement ouverte** : le hash engagé est recalculé à partir de `wrap`, jamais
lu d'une valeur servie (`verify_mandate`, `crates/synco-e2ee/src/delegation.rs:243-252`). Le runtime
n'emploie qu'**un** chemin, `accept_delegation` (`:294-310`), qui enchaîne dans l'ordre les étapes 1
et 3 ci-dessus (la clé de l'étape 2 est fournie par l'appelant depuis son épinglage) puis
l'ouverture de §3 ; tout refus y est `delegation_unusable`. La variante
`verify_mandate_offline_from_wrap_hash` (`:254-268`), qui prend un `wrapHash` servi, est **réservée**
à la vérification hors ligne des clés `rt1` par un client (§10 étape 3) et ne conditionne jamais
l'ouverture d'une enveloppe : une API malveillante peut garder le mandat authentique et son hash,
et servir une autre enveloppe scellée vers `kex` avec une `DK` qu'elle connaît.

## 5. Entrées

```
aad   = "synco-rt-entry-v1|" delegationId "|" userId "|" orgId "|" runtimeId "|" kind "|" ref "|" version
iv    = 12 octets aléatoires
entry = "sre1." b64u(iv ‖ AES-256-GCM(DK, iv, clé (32 octets), aad = utf8(aad)))
```

Une entrée est transportée avec ses métadonnées en clair `{ kind, ref, version, ciphertext }` ;
l'AAD est **recalculée** par le runtime à partir de ces métadonnées et de la délégation. Contrôles :
`kind` ∈ §2, `ref` conforme (00 §3.2), `version` entier ≥ 1, clair de exactement 32 octets, sinon
l'entrée est ignorée et comptée comme `entry_unusable` (métrique sans détail).

`exp` n'est pas dans l'AAD des entrées : elles ne s'ouvrent qu'avec `DK`, que seule l'enveloppe de
tête (qui porte `exp`) livre, et le runtime efface `DK` et toutes les entrées à `exp` (00 §6 Q4).

## 6. Clé de conversation `CK`

### 6.1 Pourquoi une clé par conversation

`AiSessionKey` (contexte `ai:<orgId>`, `AiSessionKeyService.ts:106`) est **commune à toute l'org** :
tout membre qui la détient peut lire toute conversation `gateway` qu'on lui servirait. La déléguer
donnerait au runtime ce pouvoir sur les conversations de tous les membres. Chaque conversation en mode
runtime a donc sa propre clé `CK`, et le runtime ne reçoit que les `CK` des conversations basculées.

### 6.2 Création et stockage

À la bascule (ou à la création d'une conversation directement en mode runtime), le client :

1. tire `CK` (32 octets) ;
2. la scelle pour lui-même en RSA-OAEP-SHA256 avec sa clé publique d'identité, exactement comme
   `wrapAiSessionKeyForMember` (`crypto.ts:912-933`) → `encryptedKey` (`b64`) ;
3. signe l'enveloppe FC4 : `signKeyEnvelope(CK, "aiconv:<sessionId>", 1)` (`keyEnvelope.ts:33-46`) →
   `commitment`, `signature` ; le contexte `aiconv:<sessionId>` s'ajoute au type `KeyContext`
   (`keyPinning.ts:22`) ;
4. dépose le tout avec la bascule (§6.4) : modèle `AiConversationKey` (07 §3).

Lecture : `GET /api/orgs/:orgId/ai/sessions/:sessionId/key` (propriétaire seulement) →
`{ encryptedKey, version, creatorId, commitment, signature }` ; RSA-OAEP →
`verifyKeyEnvelopeIfPresent(…, "aiconv:<sessionId>", 1, …)` → `pinOrCheckKey(…)`, comme
`ensureAiSessionKey` (`AiSessionKeyService.ts:96-109`).

Tant qu'une conversation est en régime `runtime`, seul le runtime écrit son historique : la route
existante `PATCH /api/orgs/:orgId/ai/sessions/:sessionId` (`aiSessions.ts:136`) refuse alors
`messages`, `status` et `pendingToolCall` (`409 runtime_owned`) ; le titre reste modifiable (chiffré).

Précisions (révisé après la vague B, 2026-11-19) :

- Le `PATCH` historique écrit par `updateMany` **conditionné** à l'état lu (schéma inchangé ;
  régime non `runtime` dès qu'il touche `messages`, `status` ou `pendingToolCall`) et incrémente
  `rev` sur toute écriture d'état ; le perdant d'une course (bascule concurrente) reçoit
  `409 runtime_owned` si la conversation est passée en régime `runtime`, sinon
  `409 session_conflict` (`synco_api/src/services/aiRuntime/conversationLegacyPatch.ts:21-57`,
  appelé par `aiSessions.ts:187`).
- Une conversation `conv-gcm1-v1` refuse le clair (`messages` non chiffrés, `title` hors `gcm1:`) au
  `POST` comme au `PATCH`, quel que soit son régime (`checkConvContent`,
  `conversationState.ts:140-152` ; `400`).
- `POST /ai/chat` et `POST /ai/chat/:id/tool-result` (régime `server`) répondent `409 runtime_owned`
  pour une conversation en régime `runtime` **ou** `conv-gcm1-v1` (l'API ne peut pas la lire ;
  `serverRegimeRefusal`, `conversationState.ts:131-138`, `aiChat.ts:144`, `:202`).
- `DELETE /api/orgs/:orgId/ai/sessions/:sessionId` d'une conversation en régime `runtime` la fait
  d'abord sortir du régime (raison `session_deleted`, 08 §3) : autorisation révoquée, bail clos,
  runtime notifié (`aiSessions.ts:221`).
- La `CK` est déposée avec `creatorId` = l'utilisateur, posé par l'API (jamais lu du corps) ;
  `commitment` et `signature` FC4 sont facultatifs au dépôt (`switchToRuntimeSchema`,
  `conversationLifecycle.ts:156-176`, `:244-249`, `:290-302`). Au retour au runtime d'une conversation qui a
  déjà une `CK`, `convKey` peut être omis (la clé existante est conservée) ; sinon il est
  obligatoire (`400 invalid_body`).

### 6.3 Format des champs chiffrés (inchangé)

Le format est **exactement** celui de la passerelle (`Synco_AI_Gateway/src/crypto.rs`) et de
`encryptAiField`/`decryptAiField` (`synco_app/src/assets/utils/crypto.ts:952-1003`), seule la clé
change :

```
valeur = "gcm1:" b64(nonce(12) ‖ ciphertext ‖ tag(16))
aad    = utf8(sessionId ":" messageId ":" fieldName)          ← séparateur ":" (crypto.rs:64-66), pas "|"
```

| Champ JSON (camelCase, `StoredMessage`) | `messageId` dans l'AAD | `fieldName` dans l'AAD | Clair |
|---|---|---|---|
| `content` | `id` du message | `content` | texte |
| `thinking` | `id` du message | `thinking` | texte |
| `toolResult` | `id` du message | `tool_result` | JSON sérialisé |
| `toolCalls[i].arguments` | `id` du message | `tool_call_arguments:<toolCalls[i].id>` | JSON sérialisé |
| `pendingToolCall.args` | `__pending__` | `pending_tool_call_args` | JSON sérialisé |
| `title` (session) | `__session_title__` | `title` | texte (≤ 60 caractères) |

Références : `synco_client.rs:118-190`, `AIService.ts:494-497`, `:594-602`, `:651`, `:897-906`.
Restent en clair (nécessaires à l'API et à l'affichage) : `id`, `role`, `toolCallId`, `createdAt`,
`usage`, `toolCalls[i].{id,name,category,mutating,status}`, `pendingToolCall.{id,name,category,mutating,interactive}`.

Nouvelle exigence pour les écritures (lecture tolérante de l'existant) : `sessionId`, `messageId` et
`toolCallId` conformes à 00 §3.2 (ni `:` ni `|`), pour qu'aucune AAD ne soit ambiguë.

`encryptionScheme` (`AiChatSession`, `schema.prisma:1529`) :

| Valeur | Clé | Origine |
|---|---|---|
| `null` | — | clair (`server`) ou blob RSA `isE2EE` (`client`, `AIService.ts:917-927`) |
| `gateway-aes-gcm-v1` | `AiSessionKey` de l'org | passerelle (`synco_client.rs`, `setEncryptedSessionTitle`) |
| `conv-gcm1-v1` | `CK` de la conversation | **nouveau** : mode runtime, et suite locale d'une conversation passée par le runtime |

Une fois `conv-gcm1-v1`, une conversation ne revient jamais à un autre schéma ; elle ne peut plus être
pilotée par le régime `server` (l'API ne peut pas la lire). Détection à la lecture (L11) :
`encryptionScheme === "conv-gcm1-v1"` → `CK` ; sinon champs `gcm1:` → `AiSessionKey` (détection
existante `hasEncryptedGatewayFields`, `AIService.ts:594`) ; sinon formats historiques.

### 6.4 Bascule local → runtime : réécriture de l'historique

Le client, avant d'appeler la route de bascule (04 §5) :

| Schéma de départ | Lecture | Conversion |
|---|---|---|
| `null`, tableau `StoredMessage[]` en clair (`server`) | tel quel | chiffrer les champs du §6.3 sous `CK` |
| `null`, blob `isE2EE` (`client`) | déchiffrement RSA existant | convertir le format d'affichage en `StoredMessage[]` (à valider par L11), puis chiffrer |
| `gateway-aes-gcm-v1` | `decryptGatewaySessionMessages` (`AIService.ts:617`) avec `AiSessionKey` | rechiffrer champ par champ sous `CK` |
| `conv-gcm1-v1` (retour au runtime après un passage en local) | `CK` existante | aucune ; `CK` est conservée |

La route de bascule reçoit dans **une seule requête** : l'historique réécrit, le titre chiffré, la
`CK` scellée (§6.2) et l'entrée `conv` de la délégation active ; elle applique tout ou rien (07 §4).

## 7. Cycle de vie côté client (L10)

### 7.1 Création

L'utilisateur active son mode runtime (paramètres, ou première bascule). Le client :

1. vérifie le certificat, l'épingle, le défi (01 §6.3) ;
2. ouvre localement les clés du §2 qu'il détient dans l'org, tire `DK`, `delegationId`, produit
   l'enveloppe de tête, les entrées et le mandat ;
3. dépose : `POST /api/orgs/:orgId/ai/runtime/delegations`

```json
{
  "delegationId": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "runtimeId": "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f",
  "scope": "org", "iat": 1795000000, "exp": 1795604800,
  "wrap": "srd1.…", "mandateSignature": "<b64>",
  "entries": [ { "kind": "thread", "ref": "cm3threadexample000000001", "version": 1, "ciphertext": "sre1.…" } ]
}
```

L'API vérifie : membre de l'org, module IA actif, runtime actif de l'org, politique de l'org autorise
ce membre (07 §6), `|iat − maintenant| ≤ 300`, `exp − iat ≤` maximum de l'org (D4, 09 §1), entrées
conformes et détenues (§2), nombre ≤ 09 §4. Elle remplace atomiquement la délégation active
précédente de (utilisateur, runtime) (statut `superseded`) et notifie le runtime
(`delegation.updated`, 04 §6). Le client garde `DK` **en mémoire** (clé AES non extractable, effacée
au verrouillage via `registerKeyCache`, `keyCaches.ts:15`) pour ajouter des entrées pendant la
session de l'app.

Comportement réel (révisé après la vague B, 2026-11-19 ; `depositDelegation`,
`synco_api/src/services/aiRuntime/delegationService.ts:120-206`) :

- `1 h ≤ exp − iat ≤ maxDelegationDays` de l'org → sinon `400 delegation_invalid` ; un
  `delegationId` déjà utilisé → `400 delegation_invalid` ; au plus 10 dépôts par heure et par
  utilisateur → `429 rate_limited` (`aiRuntimeDelegations.ts:65`).
- Dans la transaction : appartenance revérifiée (`403 forbidden` sinon) ; délégations précédentes
  `superseded` **et leurs entrées supprimées** ; les autorisations de session actives de
  l'utilisateur sur ce runtime suivent la nouvelle délégation (`delegationId`, `expiresAt`).
- Après : `delegation.updated` au runtime, puis réveil des conversations `awaiting_key` dont la clé
  attendue figure dans les nouvelles entrées (08 §2).
- Réponse `201 DelegationView` = `{ delegationId, runtimeId, scope, iat, exp, status, runtimeStatus,
  entryCount }`. `GET …/delegations/current` → `{ "delegation": DelegationView | null }`.

### 7.2 Synchro des clés manquantes (P11)

`GET /api/orgs/:orgId/ai/runtime/delegations/current/missing` → `[{ kind, ref, version }]` : clés du
§2 que l'utilisateur détient dans l'org et qui n'ont pas d'entrée dans sa délégation active.

- **À l'ouverture de l'app** (déverrouillée), en tâche de fond, sans bloquer le démarrage :
  - pas de délégation active alors que le mode runtime est activé → création (§7.1) ;
  - durée restante < 50 % de la durée → **renouvellement** = nouvelle délégation complète (§7.1),
    qui inclut d'office les clés manquantes ;
  - sinon, si des clés manquent : `DK` en mémoire → ajout d'entrées
    (`POST /api/orgs/:orgId/ai/runtime/delegations/:delegationId/entries`, mêmes contrôles) ;
    `DK` absente (nouvelle session de l'app) → nouvelle délégation complète.
- **En temps réel**, tant que l'app est ouverte : sur les évènements socket de création de clé
  (`thread:created`, émis par `synco_api/src/routes/threads.ts`, création ou rotation de clé
  d'espace, nouvelle conversation runtime), ajout de l'entrée (regroupé, au plus une requête toutes
  les 5 s ; plafonds et backoff 09 §4).
- Jamais de boucle : un échec est retenté avec backoff exponentiel (30 s → 30 min), au plus 5 fois par
  session.

Formes réelles (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/aiRuntimeDelegations.ts`) :
`GET …/current/missing` → `200 [{ kind, ref, version }]` (au plus 5 000), ou `404 not_found` s'il n'y a
pas de délégation active (en créer une) ; `POST …/:delegationId/entries` corps `{ entries }` (1 à 500)
→ `201 { added }`, doublons exacts `(kind, ref, version)` ignorés, au plus 3 requêtes par 15 s et par
utilisateur (`429 rate_limited`), délégation d'un autre ou absente → `404 not_found`, inactive →
`403 delegation_expired` / `delegation_revoked`. Un ajout par le client notifie
`delegation.entries_added` (`after` = dernier curseur **avant** l'ajout) ; un ajout par le runtime
(§10) ne notifie pas (`delegationService.ts:264-282`).

### 7.3 Révocation par l'utilisateur

`DELETE /api/orgs/:orgId/ai/runtime/delegations/current` → délégation `revoked`
(`user_revoked`), autorisations associées révoquées, conversations runtime de l'utilisateur
repassées en local (08 §3), notification `delegation.revoked` au runtime. Le client efface `DK`.
Réponse : `{ "revoked": [<delegationId>…] }` (révisé après la vague B, 2026-11-19).

## 8. Expiration et révocation (mesure 6, double verrou)

| Verrou | Où | Effet |
|---|---|---|
| `exp` dans l'AAD de l'enveloppe de tête et dans le mandat | runtime | Le runtime refuse d'ouvrir après `exp` et efface `DK` et les clés de la délégation à `exp` (minuterie), même sans nouvelle de l'API. |
| `AiRuntimeDelegation.expiresAt`, `status` | API | Toute requête du runtime pour cet utilisateur exige une délégation `active` et non expirée : sinon `403 delegation_expired` / `delegation_revoked`, **avant** de servir le moindre contenu chiffré (04 §3). |

Causes de révocation : utilisateur (§7.3), admin (révocation d'un membre ou de tous :
`DELETE /api/orgs/:orgId/ai/runtime/delegations/:delegationId`), désappairage (01 §9), départ de
l'org (`revokeOrgMembership`, `synco_api/src/services/membershipRevocation.ts:75`, à compléter par L03),
remplacement par une nouvelle délégation (`superseded`).

### 8.1 Causes et raisons réelles (révisé après la vague B, 2026-11-19)

| Cause | Déclencheur | `status` / `revokedReason` (= `delegation.revoked.reason`) |
|---|---|---|
| Utilisateur | `DELETE …/delegations/current` | `revoked` / `user_revoked` |
| Admin, une délégation | `DELETE …/delegations/:delegationId` (propriétaire ou `ORG_AI`) → `{ revoked: boolean }`, `404 not_found` | `revoked` / `admin_revoked` |
| Admin, **toutes** les délégations actives de l'org | `DELETE /api/orgs/:orgId/ai/runtime/delegations` (propriétaire ou `ORG_AI`) → `{ revoked: [<delegationId>…] }` (`aiRuntimeDelegations.ts:75-85`) | `revoked` / `admin_revoked` |
| Désappairage | 01 §9 | `revoked` / `runtime_unpaired` |
| Départ de l'org | `revokeOrgMembership`, et filet de maintenance (`sweepOrphanDelegations`) | `revoked` / `member_left` |
| Org bannie | changement d'état IA (ci-dessous) | `revoked` / `org_banned` |
| Module IA coupé (`features` sans `ai` ou `activeModules.ai !== true`) | idem | `revoked` / `ai_disabled` |
| Mode runtime désactivé (`aiConfig.runtime` absent ou `enabled: false`) | idem | `revoked` / `runtime_disabled` |
| Membre retiré des membres autorisés (`members: "list"`) | idem, ses délégations seulement | `revoked` / `member_not_allowed` |
| Expiration | maintenance (07 §9) | `expired` / `revokedReason = null` ; `delegation.revoked.reason = "expired"` |
| Remplacement | nouveau dépôt (§7.1) | `superseded` / `superseded` (pas de `delegation.revoked` : `delegation.updated`) |

Effets communs (`revokeDelegations`, `delegationService.ts:366-439`) : statut changé par `updateMany`
conditionné (`status = active`), `activeKey = null` ; chaque conversation autorisée par la
délégation sort du régime runtime (08 §3) ; autorisations closes ; **toutes les entrées de la
délégation supprimées** (une délégation remplacée, révoquée ou expirée ne garde aucune entrée) ;
`delegation.revoked` au runtime. Raison posée sur les autorisations (`AiSessionAuthorization.revokedReason`
et `conversation.revoked.reason`) : `delegation_revoked` (utilisateur, admin, org bannie, IA ou
runtime coupés, membre non autorisé), `delegation_expired`, `runtime_unpaired`, `member_left` ; plus,
hors délégation, `switched_to_local` et `session_deleted` (`conversationLifecycle.ts:26-32`,
`delegationService.ts:349-358`).

**Révocation automatique sur changement d'état IA de l'org** (`enforceOrgRuntimePolicy`,
`delegationService.ts:497-519`, idempotente) : appelée par `onOrgAiStateChanged(orgId)`
(`synco_api/src/services/aiRuntime/runtimePolicyEnforcement.ts`), qui invalide d'abord le cache de
5 s de l'état IA lu par le second verrou (04 §3.2). Points d'appel : `PATCH /api/orgs/:orgId` quand
`activeModules` est envoyé (`synco_api/src/routes/orgs.ts:304`) ; `PATCH /api/admin/organizations/:id`
quand `features` change ; bannissement et levée (`synco_api/src/routes/admin.ts:677`, `:735`, `:783`) —
la levée n'est qu'une invalidation de cache, rien n'est restauré. Filet : `sweepPolicyViolations` à
chaque passe de maintenance (07 §9). L'ordre de priorité est `org_banned` > `ai_disabled` >
`runtime_disabled` > `member_not_allowed`. Non traités en v1 (00 §6 Q14, Q17) : baisse de
`maxDelegationDays` sous la durée d'une délégation existante (elle court jusqu'à son `exp`),
bannissement d'un **utilisateur**.

Perte d'accès à un salon ou un espace (`revokeSpaceMembership`, `membershipRevocation.ts:25`) :
l'API supprime les entrées concernées et notifie `delegation.entries_removed` ; de toute façon elle
refuse de servir au runtime le contenu d'un salon auquel l'utilisateur n'a plus accès (04 §5).
Ce que le runtime a déjà vu reste vu (risque assumé, `03_securite.md §2`).

## 9. Côté runtime (L05) : conservation et cloisonnement

- Récupération : `GET /api/runtime/v1/delegations` (actives de son org) et
  `GET /api/runtime/v1/delegations/:delegationId/entries?after=<curseur>` ; au démarrage, puis sur
  `delegation.updated` / `delegation.entries_added`.
- Ordre : mandat (§4) → enveloppe de tête (§3) → entrées (§5).
- **En mémoire uniquement**, dans des types effacés à la libération (`zeroize`) ; jamais sur disque ni
  dans un journal. Effacement à `exp`, à la révocation, au remplacement, au désappairage.
- **Cloisonnement par utilisateur** : une clé reçue dans la délégation de l'utilisateur A ne sert
  **jamais** à une conversation de B, même si B a la même clé de salon dans sa propre délégation. Le
  worker d'une conversation ne reçoit que les clés de la délégation de son propriétaire (06 §3).
- Échec d'ouverture : alerte dans le dashboard ; l'API reçoit seulement
  `POST /api/runtime/v1/delegations/:delegationId/status { "status": "unusable" }`, **sans la cause**
  (§12).
- Formes réelles (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/runtimeInternal/delegations.ts`) :
  `GET /delegations` → tableau `[{ delegationId, userId, scope, iat, exp, wrap, mandateSignature }]`
  (actives **et** non expirées, ordre de création) ; `GET /delegations/:delegationId/entries` →
  `{ "entries": [{ id, kind, ref, version, ciphertext }], "next": <id> | null }` (`limit` 1 à 500,
  500 par défaut ; `next` non nul quand la page est pleine ; curseur inconnu → `400 invalid_body` ;
  délégation absente, d'un autre runtime ou inactive → `404 not_found`) ; `POST …/status` →
  `204`, `404 not_found`.

## 10. Clés créées par le runtime (signature FC4)

Un outil exécuté par le worker peut créer une clé (`create_thread` : nouvelle `ThreadKey` scellée en
RSA-OAEP pour chaque membre, comme `createThreadHelper`, `OrgAI.vue:495-528`). Les clients vérifient
l'origine d'une clé avec la clé de signature d'identité de son **créateur**
(`verifyKeyEnvelopeIfPresent`, `keyEnvelope.ts:124-146`), que le runtime n'a pas (P5).

Format :

```
creatorId  = "rt1:" delegationId                     (posé par l'API à partir de l'autorisation de session, jamais lu du corps)
commitment = keyCommitment(clé, ctx, version)         (inchangé, keyPinning.ts:42-51)
octets     = "synco-key-envelope-rt-v1|" ctx "|" version "|" commitment "|" delegationId
signature  = ECDSA-P256-SHA256(csk_priv, utf8(octets))   (P1363, b64)
```

Vérification par un client à jour (L10), pour `creatorId` commençant par `rt1:` :

1. `GET /api/orgs/:orgId/ai/runtime/delegations/:delegationId/mandate` (tout membre de l'org) →
   `{ delegationId, userId, orgId, runtimeId, scope, iat, exp, wrapHash, signature, certificate }`
   (`wrapHash` = `b64u(SHA-256(utf8(wrap)))`, l'enveloppe elle-même n'est pas servie).
2. Certificat vérifié comme en 01 §6.3 étapes 1–3 (pas de défi : il s'agit d'une vérification hors
   ligne) ; `fprHex` recalculée depuis les clés du certificat.
3. Mandat vérifié avec la clé de signature de `userId` (`verifyWithSignKeys`, résultat `trusted`), en
   reconstruisant `mandateBytes` avec `fprHex` et `wrapHash`.
4. `ctx` appartient à `orgId` (salon ou espace de cette org).
5. Signature de l'enveloppe vérifiée avec `csk` du certificat ; commitment vérifié.
6. Puis `pinOrCheckKey` comme d'habitude.

Un mandat expiré ou révoqué **depuis** reste valable pour vérifier une clé créée **pendant** sa
validité (aucune date n'est signée dans l'enveloppe ; après expiration, l'API refuse de toute façon
au runtime d'écrire une clé, 04 §3). Affichage : « créé par Synco AI pour <nom de l'utilisateur> ».

Clients **actuels** : `lookupCreatorSignKey("rt1:…")` ne trouve aucun membre (`keyTrust.ts:348-352`),
l'enveloppe est ignorée avec un avertissement et la clé est acceptée en TOFU (`keyEnvelope.ts:132-137`) :
compatible, sans vérification (00 §6 Q5).

Le runtime ajoute aussi la clé créée à la délégation de l'utilisateur (il détient `DK`) :
`POST /api/runtime/v1/delegations/:delegationId/entries` ; l'API n'accepte de lui que des entrées
dont la clé porte `creatorId = "rt1:<cette délégation>"` ou la `CK` d'une conversation de
l'utilisateur.

Règles réelles (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/runtimeInternal/delegations.ts:126-173`) :
route **S+A** ; `:delegationId` = délégation de l'autorisation, sinon `403 out_of_scope` ; corps
`{ entries }` (1 à 500) ; par entrée : `thread` → salon de l'org de l'autorisation
(`out_of_scope`), auquel l'utilisateur a accès **maintenant**, et `ThreadKey` de l'utilisateur dont
`creatorId = rt1:<cette délégation>` (sinon `403 forbidden`) ; `conv` → uniquement la `CK` de **la**
conversation de l'autorisation (`out_of_scope` sinon, `forbidden` si la clé n'existe pas) ; `space`
ou tout autre `kind` → `403 forbidden`. Succès `201 { added }`.

Mandat servi (`GET …/delegations/:delegationId/mandate`, tout membre ; `getMandate`,
`delegationService.ts:543-566`) : exactement la forme de l'étape 1 ci-dessus, `certificate` étant
celui du runtime de la délégation (`null` si la ligne n'existe plus) ; `404 not_found`.

**Question ouverte (00 §6 Q11)** : l'enveloppe `rt1` signe `ctx = thread:<threadId>`, or l'id du
salon est tiré par l'API **à la création** (`POST /e2ee/threads`, 04 §4.3) : le runtime ne peut pas
le signer d'avance. Aujourd'hui, la route accepte `commitment` et `signature` (ensemble ou absents)
mais le runtime ne peut pas les produire pour le bon `ctx` ; le salon créé par le runtime est donc
accepté en **TOFU** par les clients, comme les salons créés par l'IA dans l'app aujourd'hui
(`CreateNewThread.vue`, `OrgAI.vue` n'envoient pas de `commitment`).

## 11. Salon créé par un autre membre en l'absence de l'utilisateur

Le membre B crée le salon T pendant que A est hors ligne : A a une `ThreadKey` scellée pour lui (RSA),
mais sa délégation n'a pas T, et ni B, ni l'API, ni le runtime ne peuvent l'y ajouter (il faut la clé
privée RSA de A pour ouvrir la `ThreadKey`, et `DK` de A pour écrire l'entrée).

- Si la conversation de A a besoin de T (outil de lecture ou d'écriture sur T) : le worker répond à
  l'appel d'outil par un résultat `{"error":"key_unavailable","kind":"thread","ref":"<T>"}` si le
  modèle peut s'en passer ; si l'utilisateur a explicitement demandé T, la conversation passe en
  `awaiting_key` (08), avec une notification push « Ouvrez Synco pour donner accès à de nouveaux
  salons à Synco AI ».
- À la prochaine ouverture de Synco par A, la synchro P11 (§7.2) ajoute T ; le runtime reçoit
  `delegation.entries_added` et relance la conversation (`awaiting_key` → `queued`).
- Le runtime ne copie **jamais** la clé de T depuis la délégation de B (§9).

Si T a été créé par le runtime pour B (§10), le cas est identique pour A.

## 12. Ce que l'API peut et ne peut pas faire

L'API stocke `wrap`, `mandateSignature` et les `ciphertext` comme des valeurs **opaques** : elle n'a
ni la clé privée `kex`, ni la clé privée de signature de l'utilisateur, ni `DK`. Elle ne peut donc ni
vérifier qu'une délégation est valide, ni en fabriquer une qui le soit :

| Tentative de l'API | Bloquée par |
|---|---|
| Fabriquer une délégation (enveloppe vers `kex` d'une `DK` qu'elle connaît) | Mandat : signature de l'utilisateur absente (§4) |
| Ajouter une entrée (fausse clé) à une délégation réelle | AAD + `DK` inconnue (§5) |
| Rejouer une délégation vers un autre runtime | `runtimeId` et `kex` dans `ctx`, `fprHex` dans le mandat |
| …vers une autre org, un autre utilisateur, un autre périmètre | `ctx` et mandat |
| Prolonger une délégation | `exp` dans `ctx` et dans le mandat |
| Déplacer une entrée d'une délégation à une autre | `delegationId` dans l'AAD de l'entrée ; `DK` différente |
| Substituer la clé du runtime pour recevoir des délégations | Certificat, épinglage TOFU et défi côté client (01 §6.3) |

Son acceptation d'un dépôt n'est **jamais** une garantie de validité, et le runtime ne lui rend pas
d'oracle : un rejet est signalé par le statut générique `unusable` (§9), sans cause. Ce que l'API
garde comme pouvoir : refuser de servir (déni de service), et le contrôle d'accès du second verrou (§8).

## 13. Exemple complet

Valeurs de démonstration (non normatives) : [exemples/exemples.json](exemples/exemples.json), clé
`delegation`. `DK` = `0x88` × 32, `epk_priv` = `0x99` × 32, `iv` = `0xaa` × 12 ; `ThreadKey` = `0xbb` × 32,
`iv` d'entrée = `0xcc` × 12 ; `iat` = 1795000000, `exp` = `iat` + 7 jours.

```
ctx  = synco-rt-delegation-v1|66666666-7777-4888-9999-aaaaaaaaaaaa|cm3orgexample0000000000001|7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f|a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d|org|1795000000|1795604800|{"crv":"P-256","kty":"EC","x":"1lqTl3yqPRsIGFL_V6eeRl8WYFdzBLrq1QXdOkhYnPM","y":"UBheiVNy32Ih6joTdVfkc_3bZ1XwW9UHw8Uz_OnJEoU"}|{"crv":"P-256","kty":"EC","x":"3cJ11iMBtzQ0-6-d7zxCxP1Yz59pEcHf8zVXZ0ug2UY","y":"IzRpRFb-uA8-ZZVcyqDuXs8pjShHQkpgg7AS5oFqKac"}
KEK  = 4dd1d7892a2e12cd4df4d7c7be87af3505a38ca39d8c94a7a31016745727e8ad
wrap = srd1.eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjNjSjExaU1CdHpRMC02LWQ3enhDeFAxWXo1OXBFY0hmOHpWWFowdWcyVVkiLCJ5IjoiSXpScFJGYi11QTgtWlpWY3lxRHVYczhwalNoSFFrcGdnN0FTNW9GcUthYyJ9.qqqqqqqqqqqqqqqqzDr7_Z6KQv9PsHxFxSeZg6mHTfkMLim3ongsZxyfPQJG_ZsPjHxpnoKtZFmNynO8
mandateBytes = synco-rt-mandate-v1|66666666-7777-4888-9999-aaaaaaaaaaaa|cm3orgexample0000000000001|7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f|a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d|org|1795000000|1795604800|f605b872881487a9b37f903d997ff879b94c5718856a5e729587b0e39f8faf2b|AhmVSSsEBVdTz0jXtoGJN5FPPNe6C60IuU-L8SVONBk
entry aad = synco-rt-entry-v1|a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d|66666666-7777-4888-9999-aaaaaaaaaaaa|cm3orgexample0000000000001|7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f|thread|cm3threadexample000000001|1
entry     = sre1.zMzMzMzMzMzMzMzMct41NxlNMdx0P1wYKg4xPQP0ww2YrjkRT_thUzsofrcl7XtxD5j8XMqpb3Xd21OX
```

Champ de conversation (`CK` = `0xdd` × 32, nonce `0xee` × 12, clair « Bonjour depuis le runtime. ») :

```
aad    = 0f0e0d0c-0b0a-4908-8706-050403020100:3c2b1a09-8f7e-4d6c-9b5a-493827161504:content
valeur = gcm1:7u7u7u7u7u7u7u7uKvSAEGi4hwHvKh4YX23/vX8rHCEAG0FLuXQ7RghH2/+UqVU04hUCcbW8
```

Les signatures ECDSA (mandat, `rt1`) ne sont pas déterministes : les valeurs du fichier d'exemples se
vérifient mais ne se reproduisent pas à l'octet près.

## 14. Codes d'erreur

| Code | Où | Sens |
|---|---|---|
| `delegation_invalid` | API 400 | Forme, durée, horloge ou nombre d'entrées invalide |
| `delegation_entry_forbidden` | API 403 | `kind` hors liste, ou clé non détenue par l'utilisateur, ou hors de l'org |
| `delegation_not_allowed` | API 403 | La politique de l'org n'autorise pas ce membre (07 §6) |
| `runtime_unavailable` | API 409 | Pas de runtime actif dans l'org |
| `delegation_expired` / `delegation_revoked` | API 403 (canal interne) | Second verrou (§8) |
| `delegation_unusable` | runtime (interne) | Mandat, enveloppe ou entrée refusés ; la cause n'est jamais transmise |
| `entry_unusable` | runtime (interne) | Entrée refusée (`kind` hors liste, AAD, clair ≠ 32 octets) ; comptée, jamais transmise |
| `rate_limited` | API 429 | Dépôt (10 / h) ou ajout d'entrées (3 / 15 s) trop fréquent (révisé après la vague B) |
| `not_found` | API 404 | Délégation absente ou d'un autre ; pas de délégation active (`…/missing`) |
| `forbidden` | API 403 | Non membre, appartenance perdue pendant le dépôt, non admin (révocations admin) |
| `ai_disabled` | API 403 | Module IA coupé ou org bannie |
