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
  revokedReason    String?  // 'user_revoked' | 'admin_revoked' | 'runtime_unpaired' | 'member_left' | 'superseded'
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
  type      String   // 'switch_to_runtime' | 'switch_to_local' | 'status' | 'lease_taken' | 'lease_lost' | 'tool_unknown_outcome'
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
    "limits": { "maxStepsPerTurn": 25, "maxTokensPerConversation": 2000000 }
  }
}
```

| Champ | Sens | Dépend de |
|---|---|---|
| `enabled` | Le mode runtime est proposé aux membres | — |
| `members` / `memberIds` | `all`, ou liste des membres autorisés à basculer (sélecteur cherchable côté app) | — |
| `maxDelegationDays` | Durée maximale d'une délégation | D4 (09 §1) |
| `toolPolicy` | Politique par outil en l'absence de l'utilisateur | D5 |
| `limits` | Plafonds de l'org, bornés par ceux du runtime | D6 (09 §2) |

Lecture tolérante (règle des formats rétrocompatibles) : `runtime` absent = mode runtime désactivé ;
champs absents = valeurs par défaut de 09. Normalisé par `normalizeAiConfig` (`orgAiConfig.ts:81`).

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
