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
   empreinte.
2. Clé de signature de l'utilisateur : le runtime tient un **épinglage TOFU** par utilisateur (fichier
   d'état, données publiques) :
   - première vue : `GET /api/runtime/v1/users/:userId/sign-key` (04 §4) → épinglée ;
   - ensuite : la clé servie doit être l'épinglée, ou l'aboutissement d'une chaîne de transitions
     d'identité valide partant de l'épinglée (même algorithme que `identityChainPath`,
     `e2eeV4.ts:530-544`, porté dans `synco-e2ee`) ; sinon refus et alerte dans le dashboard.
3. Signature valide → sinon `delegation_unusable`.

Limite assumée (00 §6 Q3) : au tout premier contact, la clé de l'utilisateur vient de l'API.

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

### 7.3 Révocation par l'utilisateur

`DELETE /api/orgs/:orgId/ai/runtime/delegations/current` → délégation `revoked`
(`user_revoked`), autorisations associées révoquées, conversations runtime de l'utilisateur
repassées en local (08 §3), notification `delegation.revoked` au runtime. Le client efface `DK`.

## 8. Expiration et révocation (mesure 6, double verrou)

| Verrou | Où | Effet |
|---|---|---|
| `exp` dans l'AAD de l'enveloppe de tête et dans le mandat | runtime | Le runtime refuse d'ouvrir après `exp` et efface `DK` et les clés de la délégation à `exp` (minuterie), même sans nouvelle de l'API. |
| `AiRuntimeDelegation.expiresAt`, `status` | API | Toute requête du runtime pour cet utilisateur exige une délégation `active` et non expirée : sinon `403 delegation_expired` / `delegation_revoked`, **avant** de servir le moindre contenu chiffré (04 §3). |

Causes de révocation : utilisateur (§7.3), admin (révocation d'un membre ou de tous :
`DELETE /api/orgs/:orgId/ai/runtime/delegations/:delegationId`), désappairage (01 §9), départ de
l'org (`revokeOrgMembership`, `synco_api/src/services/membershipRevocation.ts:75`, à compléter par L03),
remplacement par une nouvelle délégation (`superseded`).

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
