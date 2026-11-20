# 07 — Modèle de données (synco_api, Prisma)

Ajouts et extensions de `synco_api/prisma/schema.prisma`, appliqués par `prisma db push` (pas de
migration). Règle maison : **aucun SQL brut** (`$executeRaw`, `$queryRaw`) ; les exclusivités (bail,
« une seule ligne active ») se font par contrainte d'unicité et `updateMany` conditionné. Les colonnes
sensibles portent `/// @encrypted` (`prisma-field-encryption`), comme l'existant, même quand leur
contenu est déjà chiffré de bout en bout (double couche, comme `ThreadKey.encryptedKey`).

Les noms de champs ci-dessous sont normatifs pour L02/L03 ; l'ordre et les commentaires sont libres.

## 1. Vue d'ensemble

```
Organization 1──* AiRuntime 1──* AiRuntimeDelegation 1──* AiRuntimeDelegationEntry
                       │                │
                       │                └──* AiSessionAuthorization *──1 AiChatSession 1──1 AiConversationKey
                       │                                                     │
                       └─────────────────────────────────────────────────────┤──* AiChatInboxItem
                                                                             └──* AiChatSessionEvent
```

## 2. `AiRuntime`

```prisma
// Runtime Synco AI auto-hébergé par le client et appairé à une org (docs/plan/01 du dépôt
// synco_ai_runtime). v1 : au plus un runtime actif par org (activeOrgId unique).
model AiRuntime {
  id              String   @id // runtimeId : UUID v4 tiré par le runtime
  orgId           String
  organization    Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)
  /// = orgId tant que le runtime est actif, null une fois révoqué : unicité « un actif par org »
  /// sans index partiel (PostgreSQL admet plusieurs NULL dans un index unique).
  activeOrgId     String?  @unique

  url             String   // URL canonique (01 §3)
  sigPublicKey    String   // Ed25519, b64u 32 octets
  kexPublicKey    String   @db.Text // JWK-EC canonique
  cskPublicKey    String   @db.Text // JWK-EC canonique
  fingerprint     String   // fprHex (01 §2.1)
  certificate     Json     // forme de 01 §6.2 (aucun secret)
  certSerial      Int      @default(1)

  status          String   @default("active") // 'active' | 'revoked'
  pairedById      String
  pairedAt        DateTime @default(now())
  registeredAt    DateTime? // premier POST /api/runtime/v1/register réussi
  lastSeenAt      DateTime? // flux de notifications (04 §6)
  softwareVersion String?
  revokedAt       DateTime?
  revokedById     String?   // null si désappairé par l'opérateur du runtime

  delegations     AiRuntimeDelegation[]
  authorizations  AiSessionAuthorization[]

  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt

  @@index([orgId])
  @@map("ai_runtimes")
}
```

Clés publiques non chiffrées en base : publiques par nature, comparées telles quelles.

## 3. Délégations, entrées, autorisations, clé de conversation

```prisma
// Délégation d'un utilisateur vers un runtime (docs/plan/03). Le contenu (wrap, signature,
// entrées) est opaque pour l'API : elle ne peut ni le vérifier ni le fabriquer.
model AiRuntimeDelegation {
  id               String   @id // delegationId : UUID v4 tiré par le client
  runtimeId        String
  runtime          AiRuntime @relation(fields: [runtimeId], references: [id], onDelete: Cascade)
  orgId            String
  userId           String
  user             User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  scope            String   // v1 : 'org'
  issuedAt         DateTime // iat
  expiresAt        DateTime // exp
  wrap             String   @db.Text /// @encrypted  // enveloppe de tête "srd1.…"
  mandateSignature String   @db.Text // ECDSA b64 (public par nature : servie aux membres, 03 §10)
  wrapHash         String   // b64u(SHA-256(wrap)), servi avec le mandat sans exposer wrap

  status           String   @default("active") // 'active' | 'superseded' | 'revoked' | 'expired'
  /// = "<userId>:<runtimeId>" tant que la délégation est active, sinon null.
  activeKey        String?  @unique
  revokedAt        DateTime?
  revokedReason    String?  // 'user_revoked' | 'admin_revoked' | 'runtime_unpaired' | 'member_left' | 'superseded' (+ 'org_banned' | 'ai_disabled' | 'runtime_disabled' | 'member_not_allowed' | 'user_banned', ci-dessous)
  runtimeStatus    String?  // 'ok' | 'unusable' (04 §4.1, sans cause)

  entries          AiRuntimeDelegationEntry[]
  authorizations   AiSessionAuthorization[]

  createdAt        DateTime @default(now())
  updatedAt        DateTime @updatedAt

  @@index([runtimeId, status])
  @@index([userId, orgId])
  @@map("ai_runtime_delegations")
}

model AiRuntimeDelegationEntry {
  id           String   @id @default(cuid()) // aussi curseur de pagination (ordre de createdAt, id)
  delegationId String
  delegation   AiRuntimeDelegation @relation(fields: [delegationId], references: [id], onDelete: Cascade)
  kind         String   // 'thread' | 'space' | 'conv' (03 §2)
  ref          String
  version      Int
  ciphertext   String   @db.Text /// @encrypted  // "sre1.…"
  writtenBy    String   // 'client' | 'runtime'
  createdAt    DateTime @default(now())

  @@unique([delegationId, kind, ref, version])
  @@index([delegationId, createdAt])
  @@map("ai_runtime_delegation_entries")
}

// Autorisation de session (docs/plan/04 §3) : le runtime agit pour CET utilisateur sur CETTE conversation.
model AiSessionAuthorization {
  id            String   @id @default(uuid()) // authId
  sessionId     String
  session       AiChatSession @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  /// = sessionId tant que l'autorisation est active : une seule active par conversation.
  activeSessionId String? @unique
  userId        String
  orgId         String
  runtimeId     String
  runtime       AiRuntime @relation(fields: [runtimeId], references: [id], onDelete: Cascade)
  delegationId  String
  delegation    AiRuntimeDelegation @relation(fields: [delegationId], references: [id], onDelete: Cascade)
  expiresAt     DateTime // = expiresAt de la délégation active, mis à jour au renouvellement
  revokedAt     DateTime?
  revokedReason String?  // 'switched_to_local' | 'delegation_revoked' | 'runtime_unpaired' | 'member_left'
  createdAt     DateTime @default(now())

  @@index([runtimeId])
  @@index([userId, orgId])
  @@map("ai_session_authorizations")
}

// Clé de conversation CK (docs/plan/03 §6), scellée pour le propriétaire. Même forme que
// AiSessionKey, contexte FC4 "aiconv:<sessionId>".
model AiConversationKey {
  id           String   @id @default(uuid())
  sessionId    String
  session      AiChatSession @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  userId       String
  version      Int      @default(1)
  encryptedKey String   @db.Text /// @encrypted  // RSA-OAEP-SHA256, b64
  creatorId    String?  // FC4 §2 — voir ThreadKey
  commitment   String?  @db.Text
  signature    String?  @db.Text
  createdAt    DateTime @default(now())

  @@unique([sessionId, userId, version])
  @@map("ai_conversation_keys")
}
```

`AiRuntimeDelegation.mandateSignature` et `wrapHash` ne sont pas chiffrés en base : ils sont servis à
tout membre de l'org pour vérifier les clés créées par le runtime (03 §10).

Valeurs réelles (révisé après la vague B, 2026-11-19, et après L03c, 2026-11-20 ; le schéma appliqué,
`synco_api/prisma/schema.prisma:1634` et suivants, est identique aux modèles ci-dessus, seuls les
commentaires d'énumération sont complétés ici) :

- `AiRuntimeDelegation.revokedReason` : `user_revoked`, `admin_revoked`, `runtime_unpaired`,
  `member_left`, `superseded`, **`org_banned`, `ai_disabled`, `runtime_disabled`,
  `member_not_allowed`** (03 §8.1), **`user_banned`** (utilisateur banni de la plateforme, Q17 = C ;
  révisé après L03c, 2026-11-20 : colonne `String`, aucune migration ;
  `SYNCOAI_REFONTE_FEATURE.md` §13.1) ; `null` pour une délégation `expired`
  (`synco_api/src/services/aiRuntime/delegationService.ts:345-347`, `:396-406`).
- `AiSessionAuthorization.revokedReason` : `switched_to_local`, `delegation_revoked`,
  **`delegation_expired`**, `runtime_unpaired`, `member_left`, **`session_deleted`**
  (`synco_api/src/services/aiRuntime/conversationLifecycle.ts:26-32`).
- Une délégation `superseded`, `revoked` ou `expired` n'a **plus aucune entrée** : elles sont
  supprimées au changement de statut (03 §8.1) ; le désappairage supprime toutes les entrées du
  runtime (01 §9).
- `AiConversationKey.creatorId` = l'utilisateur, posé par l'API à la bascule ; `commitment` et
  `signature` facultatifs (03 §6.2).

## 4. Extension de `AiChatSession` et bail

```prisma
model AiChatSession {
  // … champs existants inchangés (schema.prisma:1529-1562) …

  /// Régime explicite des conversations écrites après la refonte : 'client' | 'server' | 'runtime'.
  /// null = conversation antérieure : régime déduit comme aujourd'hui (AIService.ts:694-698).
  regime          String?
  /// Statuts : historiques 'idle' | 'awaiting_confirmation' | 'awaiting_client_tool' (régime server)
  /// + mode runtime 'queued' | 'running' | 'awaiting_key' | 'awaiting_user' | 'failed' | 'cancelled'
  /// (docs/plan/08). Le champ existant `status` est conservé (String).
  runtimeId       String?  // runtime qui pilote la conversation (régime 'runtime')
  rev             Int      @default(0) // révision de l'historique, +1 à chaque écriture du runtime
  leaseHolder     String?  // runtimeId détenteur du bail
  leaseEpoch      Int      @default(0) // jeton de clôture : +1 à chaque prise de bail
  leaseExpiresAt  DateTime?
  lastErrorCode   String?  // code de 08 §6, jamais de texte
  awaitingKey     String?  // "<kind>:<ref>" tant que status = 'awaiting_key' (08 §2)
  statusChangedAt DateTime?

  convKeys        AiConversationKey[]
  authorizations  AiSessionAuthorization[]
  inbox           AiChatInboxItem[]
  events          AiChatSessionEvent[]

  @@index([runtimeId, status])
}
```

`encryptionScheme` (existant) prend la nouvelle valeur `conv-gcm1-v1` (03 §6.3). Transitions
autorisées : `null → *`, `gateway-aes-gcm-v1 → conv-gcm1-v1` (par la route de bascule uniquement) ;
toutes les autres sont refusées (garde existante `aiSessions.ts:153-158` à étendre).

### 4.1 Prendre le bail (superviseur, avant de lancer un worker)

```ts
const now = new Date();
const taken = await prisma.aiChatSession.updateMany({
    where: {
        id: sessionId, regime: 'runtime', runtimeId,
        OR: [{ leaseExpiresAt: null }, { leaseExpiresAt: { lt: now } }],
    },
    data: { leaseHolder: runtimeId, leaseExpiresAt: new Date(now.getTime() + LEASE_MS), leaseEpoch: { increment: 1 } },
});
if (taken.count !== 1) return conflict('lease_conflict');
const { leaseEpoch } = await prisma.aiChatSession.findUniqueOrThrow({ where: { id: sessionId }, select: { leaseEpoch: true } });
```

`UPDATE … WHERE` est atomique par ligne (la condition est réévaluée après le verrou de ligne) : deux
prises concurrentes ne peuvent pas réussir toutes les deux. `LEASE_MS` : 09 §2.

### 4.2 Renouveler, rendre

```ts
// renouveler (toutes les 20 s)
prisma.aiChatSession.updateMany({
    where: { id: sessionId, leaseHolder: runtimeId, leaseEpoch, leaseExpiresAt: { gt: now } },
    data: { leaseExpiresAt: new Date(now.getTime() + LEASE_MS) },
});
// rendre
prisma.aiChatSession.updateMany({
    where: { id: sessionId, leaseHolder: runtimeId, leaseEpoch },
    data: { leaseHolder: null, leaseExpiresAt: null },
});
```

### 4.3 Écrire l'historique (jeton de clôture + révision)

```ts
await prisma.$transaction(async (tx) => {
    const w = await tx.aiChatSession.updateMany({
        where: { id: sessionId, leaseHolder: runtimeId, leaseEpoch, leaseExpiresAt: { gt: now }, rev: baseRev },
        data: { messages: JSON.stringify(messages), rev: { increment: 1 }, status, pendingToolCall, statusChangedAt: now },
    });
    if (w.count !== 1) throw new LeaseOrRevConflict(); // annule la transaction → 409
    await tx.aiChatInboxItem.updateMany({ where: { sessionId, id: { in: consumedInbox }, consumedAt: null }, data: { consumedAt: now } });
});
```

Un worker dont le bail a expiré (ou qui a été remplacé : `leaseEpoch` plus grand) ne peut plus rien
écrire : c'est l'invariant « deux workers n'écrivent jamais la même conversation ».

### 4.4 Réalisation (révisé après la vague B, 2026-11-19)

`synco_api/src/services/aiRuntime/conversationLease.ts:128-166`, `:275-350` :

- prise et renouvellement passent par la **même** route (`POST …/lease`) : corps vide = prise,
  `{ leaseEpoch }` = renouvellement ; le renouvellement exige en plus `regime = 'runtime'` et
  `runtimeId` ; la prise journalise `lease_taken` (code = nouvel `leaseEpoch`) ;
- l'écriture d'historique ou de statut exige le bail courant (`leaseHolder`, `leaseEpoch`,
  `leaseExpiresAt > maintenant`) ; un conflit est ensuite classé : bail toujours détenu →
  `rev_conflict`, sinon `lease_conflict` ;
- les actions d'outils pour le runtime (`tools/:name/execute`, `POST /e2ee/threads`,
  `POST /e2ee/cdn/uploads`) exigent elles aussi le bail courant (04 §5) ;
- `leaseEpoch` est incrémenté à chaque prise, à la **bascule** vers le runtime et à chaque sortie
  du régime runtime par `exitRuntimeRegime` ; le désappairage (01 §9) clôt le bail sans l'incrémenter ;
- le `PATCH` historique (03 §6.2) est lui aussi un `updateMany` conditionné et incrémente `rev`.

## 5. Boîte de réception et journal

```prisma
// Messages et décisions destinés au worker (docs/plan/05 §6.2), durables.
model AiChatInboxItem {
  id         String   // id de l'élément (05 §6.2), unique par conversation
  sessionId  String
  session    AiChatSession @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  kind       String   // 'message' | 'confirm' | 'answer' | 'upload' | 'cancel'
  payload    String   @db.Text /// @encrypted  // JSON de la trame sans v/t ; champs sensibles déjà en gcm1:
  source     String   // 'ws' (déposé par le runtime) | 'api' (déposé par le client)
  createdAt  DateTime @default(now())
  consumedAt DateTime?

  @@id([sessionId, id])
  @@index([sessionId, consumedAt, createdAt])
  @@map("ai_chat_inbox_items")
}

// Journal des transitions d'une conversation (bascules, statuts, baux), SANS contenu.
model AiChatSessionEvent {
  id        String   @id @default(cuid())
  sessionId String
  session   AiChatSession @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  type      String   // 'switch_to_runtime' | 'switch_to_local' | 'status' | 'lease_taken' | 'lease_lost' | 'tool_unknown_outcome' (les deux derniers écrits par le worker, `events`, 04 §4.2 ; Q15 = A)
  actor     String   // 'user' | 'runtime' | 'api'
  fromState String?
  toState   String?
  code      String?  // code d'erreur ou raison
  createdAt DateTime @default(now())

  @@index([sessionId, createdAt])
  @@map("ai_chat_session_events")
}
```

Dépôt idempotent : `createMany({ data: [...], skipDuplicates: true })` sur la clé `(sessionId, id)`.

Précisions (révisé après la vague B, 2026-11-19) : `payload` = trame sans `v` ni `t` ; le plafond de
100 éléments non consommés est vérifié avant l'insertion (`429 inbox_full`) ; un doublon ne change
ni l'état ni le réveil (`conversationLifecycle.ts:398-460`). Journal : l'API écrit `switch_to_runtime`,
`switch_to_local` (code = raison de sortie), `status` (code = `lastErrorCode` ou `null`, acteur `user`,
`runtime` ou `api`) et `lease_taken`. **Révisé après L03c, 2026-11-20 (Q15 = A)** : le worker
écrit `tool_unknown_outcome` et `lease_lost` lui-même par le champ facultatif `events: [{ type, code? }]`
de `PUT …/transcript` et `POST …/status` (04 §4.2) : lignes `actor = "runtime"`, `fromState` /
`toState` nuls, `code` = nom d'outil ou epoch (`^[a-z0-9_]{1,64}$`), écrites seulement si l'écriture
qui les porte réussit (dans sa transaction). Un worker qui a perdu le bail ne peut pas écrire son
propre `lease_lost` : c'est le worker suivant qui le constate. Aucune rétention : les lignes ne
disparaissent qu'avec la conversation (`onDelete: Cascade`). Source :
`synco_api/src/services/aiRuntime/conversationLease.ts:186-228`, `SYNCOAI_REFONTE_FEATURE.md` §13.6.

## 6. Politique runtime de l'org

Dans `Organization.activeModules.aiConfig` (JSON lisible par les membres, édité avec `ORG_AI`,
`orgs.ts:244`), une sous-clé `runtime` — **aucun secret** :

```json
{
  "runtime": {
    "enabled": true,
    "members": "all",
    "memberIds": [],
    "maxDelegationDays": 7,
    "toolPolicy": { "create_task": "ask", "delete_task": "deny" },
    "limits": { "maxStepsPerTurn": 25, "maxTokensPerConversation": 2000000,
                "confirmationTimeoutSecs": 604800, "keyTimeoutSecs": 604800 }
  }
}
```

| Champ | Sens | Dépend de |
|---|---|---|
| `enabled` | Le mode runtime est proposé aux membres | — |
| `members` / `memberIds` | `all`, ou liste des membres autorisés à basculer (sélecteur cherchable côté app) | — |
| `maxDelegationDays` | Durée maximale d'une délégation | D4 (09 §1) |
| `toolPolicy` | Politique par outil en l'absence de l'utilisateur | D5 |
| `limits` | Plafonds de l'org, bornés par ceux du runtime ; contient aussi `confirmationTimeoutSecs` (`awaiting_confirmation` et `awaiting_user` → `failed` `confirmation_timeout`) et `keyTimeoutSecs` (`awaiting_key` → `failed` `key_timeout`) : entiers ≥ 1, défaut **604 800** (7 j), **abaissables seulement**, ancien format sans ces champs = 7 j (Q14 a = A ; révisé après L03c, 2026-11-20) | D6 (09 §2), 09 §3 |

Lecture tolérante (règle des formats rétrocompatibles) : `runtime` absent = mode runtime désactivé ;
champs absents = valeurs par défaut de 09. Normalisé par `normalizeAiConfig` (`orgAiConfig.ts:81`), qui conserve ces deux champs de `limits` ; la maintenance lit les délais de chaque org (politique illisible → défaut) et `GET /llm-policy` les renvoie dans `runtime.limits` (04 §4.1). Un délai de 1 s est admis (question ouverte : minimum, 00 §6 Q19).

## 7. Notifications

Ajouts à `enum NotificationType` (`schema.prisma:1189`) : `AI_TURN_DONE`, `AI_AWAITING_CONFIRMATION`,
`AI_AWAITING_KEY`, `AI_AWAITING_USER`, `AI_FAILED`. Titre et corps construits par l'API à partir du
type et du **titre** de la conversation… qui est chiffré : le corps reste générique (« Synco AI a
terminé », « Synco AI attend votre confirmation »), `data` = `{ orgId, sessionId }` pour ouvrir la
conversation. Aucun contenu.

## 8. Relations à ajouter sur les modèles existants

- `Organization` : `aiRuntimes AiRuntime[]`.
- `User` : `aiRuntimeDelegations AiRuntimeDelegation[]`.
- Suppression en cascade : org supprimée → runtimes, délégations, autorisations ; utilisateur
  supprimé → ses délégations (et leurs entrées) ; conversation supprimée → clé, autorisations, boîte,
  journal.

## 9. Nettoyage

Tâche périodique (L03, comme `cdnMaintenance.ts`) : délégations `active` expirées → `expired`
(`activeKey = null`) et autorisations associées révoquées ; éléments de boîte consommés de plus de
7 jours supprimés ; journaux de conversation conservés tant que la conversation existe.

Passes réelles (révisé après la vague B, 2026-11-19 ; `runAiRuntimeMaintenance`,
`synco_api/src/services/aiRuntime/runtimeMaintenance.ts:68-87`), toutes les **60 s**, idempotentes
(plusieurs instances peuvent la lancer), dans cet ordre :

1. `expireDelegations` : délégations actives dont `expiresAt ≤ maintenant` → `expired`, avec les
   effets de 03 §8.1 (entrées supprimées, conversations repassées en local, `delegation.revoked`
   `reason: "expired"`) ;
2. `sweepOrphanDelegations` : délégations actives d'un utilisateur qui n'est plus membre →
   `member_left` (filet de `revokeOrgMembership`) ;
3. `sweepPolicyViolations` : délégations que l'état IA de l'org ne permet plus (03 §8.1 : org
   bannie, module IA ou mode runtime coupé, membre non autorisé) ; puis `sweepBannedUserDelegations`
   (délégation active d'un utilisateur dont `bannedAt` est posé → `user_banned`, révisé après L03c,
   Q17 = C) ;
4. `sweepOrphanAuthorizations` : autorisations actives dont la délégation n'est plus active ou a
   expiré (révocation interrompue, course bascule / révocation) → conversations repassées en local ;
5. `failTimedOutWaits` : `awaiting_confirmation` / `awaiting_user` depuis plus de
   `limits.confirmationTimeoutSecs` → `failed` `confirmation_timeout` ; `awaiting_key` depuis plus de
   `limits.keyTimeoutSecs` → `failed` `key_timeout` (comparaison stricte sur `statusChangedAt`), journal
   et push `AI_FAILED` ; défaut 7 jours, abaissable par l'org (§6 ; révisé après L03c, Q14 a = A) ;
6. `purgeConsumedInbox` : éléments consommés depuis plus de 7 jours supprimés.
