# 12 — Plan d'action, mode autonome et politiques d'org (figé par L00f, 2026-11-21)

Source : conception C1 (`.claude/prompts/syncoai_refonte/conception/C1_plan_action.md`), validée par
l'utilisateur, et ses décisions PC34 à PC43 (00 §5). Ce document fige ce dont **L01c** (mandat v2,
fonctions pures), **L03g** (API : plans, verrou, conditions `auto`), **L03h** (API : politiques) et
**L08d** (runtime) ont besoin pour travailler en parallèle. Les points que ni C1 ni les PC ne
tranchent sont au §15 (questions **QP1** à **QP5**) ; le texte qui en dépend est marqué
« provisoire ».

Conventions : 00 §3. Colonne « Auth » : **S** et **S+A** comme en 04 §4 ; **U** = route utilisateur
(Keycloak, `authMiddleware`, membre de l'org, `banMiddleware`), montée sous `/api/orgs/:orgId/ai`
comme les routes de 03 §7 ; **U-prop** = U et propriétaire de la conversation ; **U-admin** = U et
propriétaire de l'org ou permission `ORG_AI`. Erreurs : `{ "error": "<code>" }`, codes au §14.

## 1. Principe

```
 worker ──(1) propose_actions── POST …/plans : transcript chiffré (CK) + ligne AiActionPlan (métadonnées)
   │                                     │ awaiting_confirmation + push AI_AWAITING_CONFIRMATION
   ▼ s'arrête                            ▼
                        appareil de l'utilisateur (déverrouillé)
                        (2) déchiffre, valide (§5), affiche (C1 §3) ; l'utilisateur coche et accepte
                        (3) decision → (4) claim → (5) exécute chaque action d'appareil par les routes
                            normales, progress par action → (6) entrées de délégation (03 §7.2)
                        (7) dépose plan_result (chiffré CK) dans la boîte
 worker ◀──(8) conversation.wake : exécute les actions d'agent acceptées (§8.2), ferme propose_actions
```

Le plan **généralise** `awaiting_confirmation` (C1 §2.1) : même état, même notification, même délai
`confirmationTimeoutSecs`, même `pendingToolCall`, même boîte de réception. Les outils mutants dont la
politique effective est `ask` passent **tous** par le plan (PC38).

## 2. Ce qui passe par le plan

- **Politique effective d'un outil** (D5, règle du worker `crates/worker/src/tools/mod.rs:110-120`, que
  l'API applique désormais aussi) : `toolPolicy[name]` de l'org si présent, sinon `ask` pour un outil
  `mutating`, `auto` sinon ; un outil `interactive` reste hors plan (`awaiting_user`).
- **Mode plan** (délégation du propriétaire en `plan`, défaut) : le modèle ne voit plus aucun outil
  mutant dont la politique effective est `ask` ni aucun outil d'appareil (`create_thread`,
  `create_folder`, `create_file`) ; il les demande par l'outil interne **`propose_actions`**. Les outils
  `auto` et les lectures restent appelés directement ; `deny` n'est jamais proposé.
- **Mode autonome** (délégation `auto`, §10) : `create_thread` dont la politique effective est `auto`
  est exécuté directement par le runtime (L07 inchangé, signature `rt1`) ; tout le reste de la liste
  ci-dessus passe encore par le plan (C1 §6 : « les actions `ask` passent toujours par le plan »).
- Hors plan : lectures, outils `auto`, outils interactifs (`ask_question`, `request_image_upload`).

## 3. Format du plan

### 3.1 Appel du modèle

Le modèle appelle `propose_actions` avec `{ "summary": "<texte>", "actions": [ … ] }`, chaque action
ayant la forme du §3.2 (`n` compris). Le worker valide (§5), ajoute les champs d'en-tête et écrit le
plan. Un appel invalide n'écrit rien : le worker rend au modèle le résultat
`{"error":"plan_invalid","detail":"<règle>"}` (texte court, sans valeur reçue) et continue le tour.

### 3.2 Clair (interne, chiffré sous `CK`)

```json
{ "v": 1, "planId": "<UUID v4 tiré par le worker>", "sessionId": "<conversation>", "toolCallId": "call_7",
  "createdAt": 1795000000, "expiresAt": 1795604800, "summary": "<texte du modèle, affiché comme tel>",
  "actions": [
    { "n": 1, "kind": "thread.create", "args": { "name": "budget", "type": "text", "spaceId": "cm…" } },
    { "n": 5, "kind": "server.call", "tool": "create_task", "args": { "title": "…" }, "after": [1],
      "argsRefs": { "description": "$1.id" } } ] }
```

| Champ | Règle |
|---|---|
| `v` | `1` |
| `planId`, `sessionId`, `toolCallId` | identifiants 00 §3.2 ; `sessionId` = la conversation ; `toolCallId` = l'appel `propose_actions` |
| `createdAt`, `expiresAt` | secondes Unix ; `createdAt < expiresAt ≤ createdAt + confirmationTimeoutSecs` de l'org (09 §3, borné [1 h, 7 j]) |
| `summary` | chaîne ; affichée **à part**, en citation, jamais comme intitulé d'action (C1 §3) |
| `actions` | 1 à 20 objets ; `n` = position (1, 2, 3… sans trou) |
| `kind` | liste fermée du §4 |
| `tool` | présent **si et seulement si** `kind = server.call` |
| `args` | objet strict selon le `kind` (§4) ; aucun champ inconnu |
| `after` | facultatif ; entiers distincts, chacun `< n` |
| `argsRefs` | facultatif ; `{ "<champ de args>": "$<m>.<champ exporté>" }`, `m ∈ after`, champ exporté par le `kind` de `m` (§4), champ cible présent dans le schéma de l'action et **absent** de `args` |

### 3.3 Sérialisation et chiffrement

- **JSON canonique** (C1 §2.3) = **RFC 8785 (JCS)** restreint aux entiers sûrs (`|x| ≤ 2⁵³ − 1`, aucun
  nombre décimal) : clés triées par unités UTF-16, aucune espace, chaînes échappées comme
  `JSON.stringify`. C'est aussi la forme compacte de `serde_json::to_string` (clés triées) pour ces
  valeurs : le vecteur le vérifie. Sert au clair du plan, au clair de `plan_result` et aux condensats.
- **Taille** : `utf8(JCS(plan)) ≤ 65 536` octets.
- **Chiffrement** : format `gcm1:` de 03 §6.3 sous la `CK` de la conversation, avec
  `aad = utf8(sessionId ":" planId ":plan")` (`messageId` = `planId`, `fieldName` = `plan`).
- **Liaison** : aucune signature en plus (C1 §2.3) : seuls les appareils du propriétaire et le runtime
  de sa délégation détiennent `CK` ; l'AAD lie le plan à sa conversation et à son `planId`.

### 3.4 Où il est stocké

`pendingToolCall` de la conversation (07 §4) :

```json
{ "id": "call_7", "name": "propose_actions", "category": "client", "mutating": true,
  "interactive": false, "planId": "<planId>", "args": "gcm1:…" }
```

Pour `name = "propose_actions"`, et seulement pour lui, `args` est le plan chiffré avec l'AAD du §3.3
(au lieu de `__pending__` / `pending_tool_call_args`), et `planId` est en clair. L'appel du modèle
(`toolCalls[i].arguments`, AAD `tool_call_arguments:<id>`) reste écrit comme aujourd'hui. Un
`pendingToolCall` d'un autre nom se confirme comme avant (`confirm`, C1 §7).

## 4. Types d'action v1 (liste fermée)

| `kind` | `args` (strict) | Exécutant, mode plan | Exécutant, mode autonome | Champs exportés | Clé ajoutée à la délégation |
|---|---|---|---|---|---|
| `thread.create` | `name` (1 à 255), `type` ∈ `text`, `voice`, `spaceId?` (id) — paramètres de l'outil `create_thread`, un salon par action | **appareil** (§8.1) | si la politique effective de `create_thread` est `ask` : **runtime** (`POST /e2ee/threads` + `rt1`, §8.2) ; si `auto` : hors plan | `id`, `spaceId` | `thread:<id>` |
| `folder.create` | `spaceId` (id), `name` (1 à 255), `parentFolderId?` (id) | appareil | appareil | `id`, `spaceId` | aucune |
| `file.create_text` | `spaceId` (id), `name` (1 à 255, extension de `textFileFormats.ts`), `content?` (chaîne), `folderId?` (id) | appareil | appareil | `id`, `spaceId` | aucune |
| `server.call` | `tool` : outil du manifeste de catégorie `server`, `mutating` ; `args` : schéma de l'outil (`parameters`) | **agent**, sans signature (§8.2) | agent | `id` (= `data.id` du résultat, s'il est un identifiant) | aucune |

- `thread.create` : l'appareil reprend `createThreadHelper` / `CreateNewThread.vue` : route
  `POST /api/threads/space/:spaceId` (ou `/api/threads/org/:orgId` sans `spaceId`), `type` `voice` →
  `vocal` (vocabulaire de `createThreadSchema`), catégorie = première catégorie visible de la cible
  (règle de L03d, 04 §4.3), clé du salon scellée pour les membres avec épinglage FC1, puis enveloppe FC4
  du créateur par `POST /api/threads/:threadId/key-envelope` (§12.1).
- `folder.create` : `createFolderRequest` (`POST /api/spaces/:spaceId/folders`). `file.create_text` :
  `createTextFile` (envoi CDN chiffré, PC6, PC41). Le bac à sable du worker ne change pas.
- **Actions sensibles** (C1 §3, règle 3 : non précochées, cochées une par une) : niveau de risque fourni
  par L14. En attendant L14 : toute action `server.call` dont l'outil supprime (`delete_*`) ou envoie
  hors de Synco (`create_email_report`) — provisoire, QP5.
- Un nouveau `kind` demande un lot dédié et la mise à jour du §5 ; les catalogues L14 et L15 ajoutent
  des `server.call` sans changer ce document.

## 5. Validation

Faite par le **worker** avant d'écrire, et **refaite par l'appareil** avant d'afficher ; tout échec
rend le plan entier invalide (code `plan_invalid`). Règles (vecteurs `action-plan.json`,
`validationCases`) :

1. Champs du §3.2, rien d'autre ; `v = 1` ; identifiants conformes ; `sessionId` = la conversation.
2. `createdAt < expiresAt`, écart ≤ délai de l'org (et ≤ 604 800).
3. 1 à 20 actions, `n` consécutifs depuis 1 ; clair canonique ≤ 64 Kio.
4. `kind` dans la liste ; `tool` présent seulement pour `server.call`, outil `server` et `mutating` du
   manifeste (`GET …/tools`) ; `args` stricts (champs connus, requis présents dans `args` ou fournis par
   `argsRefs`, types et bornes).
5. `after` et `argsRefs` conformes au §3.2 (vers des actions **antérieures** seulement : aucun cycle).
6. **Provisoire (QP1)** : une action d'appareil ne dépend (`after`) d'aucune action d'agent.
7. Appareil seulement : chaque `spaceId`, `parentFolderId`, `folderId` est résolu dans l'annuaire
   local ; un identifiant inconnu bloque le plan (C1 §2.6).

Un plan invalide **à l'appareil** est refusé par la route de décision avec `reason: "plan_invalid"`
(§12.1) : le worker reçoit `{"error":"plan_rejected","reason":"plan_invalid"}`. L'API ne voit pas le
clair ; elle contrôle ce qu'elle reçoit (§12.2).

## 6. Dépendances et acceptation partielle (PC37)

- L'utilisateur peut décocher toute action. Les actions qui en dépendent (`after`, transitivement)
  sont décochées **en cascade**, et l'écran le montre avant validation (« décocher #budget retire
  aussi la tâche 5 »). Vecteurs : `cascadeCases`.
- Une action sensible n'est jamais précochée et le bouton principal reste grisé tant que chacune n'est
  pas cochée ou retirée ; il n'existe pas de « Tout accepter » qui les couvre (C1 §3).
- La décision envoie l'ensemble `accepted` ; les autres actions passent `skipped`.

## 7. États et expiration

### 7.1 Plan (`AiActionPlan.status`)

```
proposed ──decision accept──▶ accepted ──claim──▶ executing ──▶ done    (toutes les actions terminales, aucune en échec)
   │  └──decision reject────▶ rejected                │      └──▶ failed  (une action en échec ; la suite skipped)
   └──expiresAt──────────────▶ expired                └──claim expiré, action en cours──▶ interrupted
```

- `rejected` aussi quand un message de l'utilisateur arrive pendant l'attente (le worker clôt
  `propose_actions` avec `superseded_by_user_message`, 08 §2), et pour un plan invalide à l'appareil.
- `expired` : `proposed` ou `accepted` non réclamé à `expiresAt` ; la tâche de maintenance pose
  `expired` et la conversation suit la transition existante `failed` (`confirmation_timeout`).
- `interrupted` : le claim expire alors qu'une action est `executing` ; cette action passe
  `unknown_outcome`, les actions `pending` passent `skipped`, **rien n'est relancé** (C1 §2.6).
- États terminaux : `done`, `failed`, `rejected`, `expired`, `interrupted`.

### 7.2 Action (`actionStates[n-1]`)

`pending` → `executing` → `done` | `failed` ; `pending` → `skipped` (décochée, ou non exécutée après un
échec) ; `executing` → `unknown_outcome` (claim expiré, ou appel d'agent interrompu). **Une action
n'entre qu'une fois en `executing`** : écriture par `updateMany` conditionné à l'état lu ; une seconde
tentative reçoit `409 action_state_conflict` (C1 §2.6).

### 7.3 Échec, plafond

- L'exécution **s'arrête** à la première action en échec ; les suivantes, dans l'ordre d'exécution
  (§8), passent `skipped`. **Aucune annulation automatique.** Vecteurs : `failureCases`.
- L'agent reçoit le bilan action par action et peut proposer un **nouveau** plan ; au plus **3 plans
  consécutifs par tour**, au-delà le tour échoue : `failed`, code `plan_limit` (08 §6).

### 7.4 Délais

| Délai | Valeur |
|---|---|
| Expiration du plan | `expiresAt` = `createdAt` + `confirmationTimeoutSecs` de l'org (défaut 7 j, borné [1 h, 7 j]) |
| Claim | 5 min ; prolongé de 5 min par chaque `progress` ou nouveau `claim` du même appareil |

## 8. Exécution

### 8.1 Par l'appareil

Préalables (C1 §2.6) : app déverrouillée, délégation active avec `DK` en mémoire (sinon
renouvellement, 03 §7.1), plan revalidé (§5). Puis :

1. `POST …/decision` (§12.1).
2. `POST …/claim` ; un autre appareil reçoit `409 plan_claimed` et affiche « en cours sur votre autre
   appareil ». **Provisoire (QP1)** : l'appareil réclame et dépose `plan_result` même si aucune action
   d'appareil n'est acceptée.
3. Pour chaque action d'appareil acceptée, dans l'ordre de `n` : `progress { n, state: "executing" }`,
   appel de la **route normale** de l'utilisateur avec l'en-tête `X-Synco-Plan: <planId>/<n>` (audit
   seulement : l'API le journalise sans rien changer aux droits), puis `progress { n, state: "done" | "failed" }`.
   Arrêt au premier échec (§7.3). En mode autonome, `thread.create` est laissé `pending` pour le
   runtime (§4).
4. **Clés** : après les actions et **avant** le résultat, ajout des entrées des salons créés
   (`POST …/delegations/:delegationId/entries`, 03 §7.2) ; le runtime reçoit `delegation.entries_added`.
5. **Résultat** : élément `plan_result` (§9) ; s'il arrive avant la clé, `awaiting_key` prend le relais.

Plan `interrupted` (claim perdu) : l'appareil du propriétaire qui le trouve (à l'ouverture de la
conversation) dépose `plan_result` à partir des états de la ligne, sans claim.

### 8.2 Par l'agent

**Provisoire (QP1)** : le worker exécute les actions d'agent **après** `plan_result` : les `server.call`
acceptées, et en mode autonome les `thread.create` laissées `pending`, dans l'ordre de `n`, en
résolvant `argsRefs` depuis `plan_result.outcomes[].output`. Chaque appel porte
`plan: { planId, n }` (§12.2) ; l'API passe l'action `executing` puis `done` / `failed` dans la même
requête. Un appel interrompu (transport coupé après envoi) donne `unknown_outcome`, jamais relancé
(08 §5). Arrêt au premier échec.

### 8.3 Verrou serveur des actions `ask` (PC38)

Un appel du runtime à `POST /conversations/:sessionId/tools/:name/execute` pour un outil dont la
politique effective est `ask`, ou à `POST /e2ee/threads` quand celle de `create_thread` est `ask`, doit
porter `plan: { planId, n }`. L'API vérifie, sinon **`403 action_not_accepted`** :

1. la ligne `AiActionPlan` existe, de cette conversation et de l'utilisateur de l'autorisation ;
2. son statut est `accepted` ou `executing`, et la décision a été écrite par la route **utilisateur**
   de décision (seule à poser `accepted`) ;
3. l'action `n` est acceptée et `pending` (sinon `409 action_state_conflict`) ;
4. `server.call` : `serverDigests[n]` = SHA-256 de `JCS({ tool: name, args })` des arguments **reçus**
   (provisoire pour une action à `argsRefs` : QP2) ; `thread.create` : aucune empreinte (C1 :
   `serverDigests` ne couvre que `server.call`), l'action doit seulement être acceptée.

Un outil `auto` n'exige rien (un `plan` fourni est alors contrôlé de la même façon) ; `deny` reste
refusé avant tout (`tool_denied_by_policy`).

## 9. Éléments de boîte de réception

Ajoutés à 05 §6.2 (les éléments existants restent valides, C1 §7) :

| `t` | Déposé par | `id` | Charge | Transition (08 §2) |
|---|---|---|---|---|
| `plan_decision` | **l'API seule**, par la route de décision (`source = "api"`) ; refusé sur `POST …/inbox` et du runtime (`400 invalid_body`) | `decision:<planId>` | `{ planId, decision: "accept" \| "reject", accepted: [n…], reason? }` (métadonnées, en clair) | `reject` : `awaiting_confirmation` → `queued` ; `accept` : aucune (on attend `plan_result`) |
| `plan_result` | l'appareil, par `POST …/sessions/:sessionId/inbox` ou par WebSocket (le runtime le rend durable) | `plan:<planId>` | `{ planId, value: "gcm1:…" }` ; clair = `JCS({ v: 1, planId, outcomes: [{ n, state, output? }] })`, AAD `sessionId:planId:plan_result` | `awaiting_confirmation` → `queued` |

- `output` = champs exportés de l'action (§4), identifiants seulement ; `state` ∈ états du §7.2
  (`pending` pour une action d'agent pas encore exécutée).
- Dépôt de `plan_result` : la ligne existe pour cette conversation, statut ∈ `executing`, `done`,
  `failed`, `interrupted` (sinon `409 plan_not_executing`). Doublon : `200`, rien n'est rejoué.
- Réveil : `conversation.wake` `reason: "decision"` pour les deux.
- Le worker rejette un `plan_result` qui ne correspond pas au `pendingToolCall` déchiffré (autre
  `planId`, AAD fausse) : `tool_call_unverified` (06 §9).
- Un `confirm` visant `propose_actions` est consommé et ignoré (`stale_decision`).

## 10. Mode autonome

### 10.1 Consentement

Le mode vit dans le **mandat v2** signé par l'utilisateur (03 §4.1) : `mode = plan | auto`. Activer ou
désactiver = déposer une nouvelle délégation (nouvel identifiant), l'ancienne passe `superseded`.
Conditions de dépôt `auto` : §11.3. Le runtime se fie au mandat **vérifié**, jamais au champ servi.

### 10.2 Enveloppes `rt1` côté client (vecteurs `mandate-v2.json`, `rt1Policy`)

Un client à jour vérifie le mandat servi par `GET …/delegations/:delegationId/mandate` (03 §10) :

| Mandat vérifié | Enveloppe `rt1` valide | Résultat |
|---|---|---|
| v2, `mode = auto` | oui | vérifiée : « Créé par Synco AI (mode autonome) pour Alice » |
| v2, `mode = plan` | oui | **refusée**, comme une enveloppe fausse |
| v1 (hors production, PC32) | oui | TOFU avec avertissement |
| illisible, ou enveloppe fausse | — | refusée |

### 10.3 Superviseur (L08d)

- `created_key` et `repose` : refus si le mandat **courant vérifié** du propriétaire n'est pas v2 `auto`
  (code `autonomy_required`, 06 §9).
- Configuration `autonomy.allowed` (défaut `true`) : à `false`, le runtime traite tout mandat `auto`
  comme `plan` (aucune signature `rt1`) et le signale au dashboard ; c'est la seule protection que l'API
  ne peut pas contourner (C1 §4.5).
- Lecture des mandats : 03 §4.1 (v1 → `plan`).

### 10.4 Conditions `auto` côté API

| Route | Condition ajoutée | Refus |
|---|---|---|
| `POST /e2ee/threads` (créateur `rt1:`) | délégation de l'autorisation `mode = auto` ; `isFeatureAllowed(autonomous_mode)` ; verrou du §8.3 si `create_thread` est `ask` | `403 autonomy_required`, `403 feature_not_allowed`, `403 action_not_accepted` |
| `POST /e2ee/threads/:threadId/key-envelope` | délégation de l'autorisation `mode = auto` ; politique | `403 autonomy_required`, `403 feature_not_allowed` |
| `POST /e2ee/threads/:threadId/key-envelope/repose` | délégation `delegationId` du corps `mode = auto` ; politique | idem |
| `GET /e2ee/threads/envelope-resets` (L03f) | ne liste que les délégants dont la délégation active vers ce runtime est `auto` et autorisée | (filtre) |
| `POST …/ai/runtime/threads/:threadId/key-envelope/reset` (utilisateur) | `repose_unavailable` aussi si le délégant n'a pas de délégation active `auto` autorisée | `409 repose_unavailable` |
| Second verrou (04 §3.2) | délégation `auto` : `isFeatureAllowed(autonomous_mode)` | `403 feature_not_allowed` |

Les contrôles s'insèrent **après** ceux qui existent (forme du corps, porte d'outil, bail) et avant
toute écriture. **Limite documentée** : un salon créé en mode autonome puis cassé après le retour en mode
plan ne se répare qu'en réactivant le mode autonome (C1 §4.3).

### 10.5 Traçabilité

Salons : `creatorId = rt1:<delegationId>`, inchangé. Actions `server.call` exécutées par le runtime :
`AiChatSessionEvent` `actor: "runtime"`, `type: "plan_action"`, `code` = `<planId>.<n>` (07 §5).
Actions de l'appareil : actions de l'utilisateur ; seul marquage, l'en-tête `X-Synco-Plan`.

## 11. Politiques d'org des fonctionnalités IA (PC36, PC39, PC42)

### 11.1 Liste fermée

| `feature` | Statut v1 | Défaut sans ligne en base | « Activé » signifie |
|---|---|---|---|
| `autonomous_mode` | actif | `none` (PC39), administrateurs compris | `AiFeatureOptIn` présent avec la `warningVersion` courante |
| `runtime_mode` | actif | lu de `aiConfig.runtime.members` / `memberIds` (`all` → `all`, `list` → `list` avec ces membres) ; illisible → `list` vide (règle existante, `runtimePolicy.ts:34`) | délégation active (dépôt, 03 §7.1) |
| `tool_auto_accept` | actif | `all` | réglage local de l'app (`autoAcceptTools`) ; **jamais** pour une action sensible (§4) |
| `subagents`, `agent_memory`, `runtime_transcription`, `rich_push` | **réservées** (PC42) | — | — |

Une fonctionnalité réservée n'a ni écran ni écriture : `PUT` → `409 feature_reserved`. Une valeur
hors liste → `404 not_found`. `mode` ∈ `all`, `none`, `list`.

### 11.2 `isFeatureAllowed(orgId, userId, feature)`

Fonction unique côté serveur ; rend `{ allowed, enabled }` ; « autorisé et activé » = les deux. `list` :
autorisé si une ligne `AiFeaturePolicyMember` existe. Points d'appel pour `autonomous_mode` : dépôt
d'une délégation `auto`, routes du §10.4, second verrou. Pour `runtime_mode` : là où l'API appelle
aujourd'hui `isRuntimeAllowedForUser` (dépôt, bascule, second verrou, `sweepPolicyViolations`). Le
runtime ne lit aucune politique (il applique le mandat et `autonomy.allowed`). L'app masque ou grise,
seul le serveur fait foi.

### 11.3 Activation par l'utilisateur

1. L'app montre l'avertissement (C1 §5.4 : trois phrases, case « J'ai compris » non précochée).
2. `PUT /ai/feature-policies/me/autonomous_mode/opt-in { warningVersion }` (§12.3).
3. Dépôt d'une délégation v2 `mode = auto` : l'API exige `isFeatureAllowed` (allowed **et** enabled),
   sinon `403 feature_not_allowed`.
4. Désactivation : dépôt d'une délégation v2 `plan` (l'ancienne `superseded`), puis
   `DELETE …/me/autonomous_mode/opt-in`. Le `DELETE` applique de toute façon le §11.4 aux délégations
   `auto` qui resteraient.
5. Badge « Autonome » tant que la délégation active est `auto`. Si `warningVersion` courante > celle
   enregistrée, l'app redemande l'acceptation (le serveur répond `enabled: false`).

### 11.4 Retrait (PC40)

Dès que `isFeatureAllowed(autonomous_mode)` devient faux pour un utilisateur (passage à `none`, retrait
de la liste, `DELETE` de l'opt-in), dans **la même transaction** que l'écriture qui le provoque :

1. ses `AiFeatureOptIn` de la fonctionnalité sont supprimés (sauf `DELETE` lui-même) ;
2. ses délégations actives `mode = auto` passent `revoked`, raison **`autonomy_withdrawn`**, entrées
   supprimées ; le runtime reçoit `delegation.revoked` (`reason: "autonomy_withdrawn"`) ;
3. ses conversations en régime runtime **restent sur le runtime, en pause**, puis reprennent **en mode
   plan** au prochain dépôt d'une délégation par son app (PC40 ; mécanique provisoire : QP3) ;
4. ce qui a été fait reste fait ; les plans `proposed` sont **sans effet** (leur exécutant serait
   désormais l'appareil) ;
5. notification `AI_AUTONOMY_WITHDRAWN` : « Votre organisation a désactivé le mode autonome » (pas pour
   un `DELETE` fait par l'utilisateur lui-même) ;
6. ligne `AiFeaturePolicyEvent`.

L'écran admin annonce le nombre de personnes concernées **avant** d'enregistrer (`enabledCount` et
`enabled` par membre, §12.3). Retrait de `runtime_mode` : révocation existante `member_not_allowed`
(03 §8.1), inchangée. Retrait de `tool_auto_accept` : l'app relit `GET …/me` et vide `autoAcceptTools`.

### 11.5 Reprise de `aiConfig.runtime.members`

Tant qu'aucune ligne `AiFeaturePolicy` `runtime_mode` n'existe, `members` / `memberIds` sont **lus**
comme cette politique. La première écriture par les routes du §12.3 crée la ligne (et ses membres) ;
ensuite la ligne fait foi et `members` / `memberIds` ne sont plus écrits (le `PUT` de la config IA les
conserve tels quels, sans effet). `prisma db push` suffit. L'écran « membres autorisés » du mode runtime
migre vers la carte `runtime_mode` (L11).

### 11.6 Journal (PC39 : exception visible et journalisée)

Chaque changement de mode, ajout ou retrait de membre, activation ou désactivation et révocation écrit
une ligne `AiFeaturePolicyEvent` (07 §10) ; un administrateur qui s'ajoute lui-même à la liste y figure
comme les autres. Lecture : `GET /ai/feature-policies/:feature/events` (U-admin).

## 12. Routes

### 12.1 Utilisateur : plans (montées sous `/api/orgs/:orgId/ai/sessions/:sessionId`)

| Méthode et chemin | Auth | Corps | Succès | Refus |
|---|---|---|---|---|
| `GET /plans/:planId` | U-prop | — | `200 PlanView` | `404 not_found` |
| `POST /plans/:planId/decision` | U-prop | `{ "decision": "accept", "accepted": [1,3,4,5] }` ou `{ "decision": "reject", "reason"?: "plan_invalid" }` | `200 PlanView` ; même décision rejouée : `200` | `400 invalid_body` (`accepted` vide, hors `1..actionCount`, doublon), `404 not_found`, `409 plan_not_pending` (déjà décidé autrement, expiré), `409 not_runtime` |
| `POST /plans/:planId/claim` | U-prop | `{ "deviceId": "<id>" }` | `200 { claimExpiresAt }` (prise ou prolongation) | `404`, `409 plan_claimed` (autre appareil, claim valide), `409 plan_not_claimable` (statut ≠ `accepted`, `executing`) |
| `POST /plans/:planId/progress` | U-prop | `{ "deviceId", "n", "state": "executing" \| "done" \| "failed" }` | `200 PlanView` (claim prolongé) | `400 invalid_body` (action d'agent, `n` hors plage), `404`, `409 plan_claim_lost`, `409 action_state_conflict` |
| `POST /inbox` (existante) | U-prop | `{ "t": "plan_result", "id": "plan:<planId>", "planId", "value": "gcm1:…" }` | `201` / `200` doublon (05 §6.2) | existants + `409 plan_not_executing`, `404 not_found` |

`PlanView` = `{ planId, sessionId, toolCallId, status, actionCount, createdAt, expiresAt, decidedAt,
claim: { deviceId, expiresAt } | null, actionStates: ["pending", …] }` (dates ISO 8601) ; **aucun
contenu** : le clair se lit dans `pendingToolCall` (§3.4). `deviceId` : identifiant 00 §3.2 tiré par
l'appareil, opaque pour l'API. Effets de la décision, dans une transaction : `updateMany` conditionné
à `status = proposed`, `decidedAt`, états `skipped`, dépôt de `decision:<planId>` ; `reject` passe la
conversation `queued` et réveille le runtime. `failed` en `progress` passe les actions `pending`
restantes en `skipped` et le plan en `failed`. Débit : compteur des routes utilisateur du mode runtime
(120 / min, 09 §4.1).

**Autres routes utilisateur**

| Méthode et chemin | Auth | Changement |
|---|---|---|
| `POST /api/orgs/:orgId/ai/runtime/delegations` | U | corps : `mandateVersion?` (`1` si absent, ou `2`), `mode?` et `ownerRsaSpkiHex?` (obligatoires si `2`, interdits si `1`) ; `mode = auto` → `isFeatureAllowed(autonomous_mode)` sinon `403 feature_not_allowed` ; forme invalide → `400 delegation_invalid` (03 §4.1) |
| `GET …/delegations/current`, `DelegationView` | U | ajoute `mandateVersion`, `mode` |
| `GET …/delegations/:delegationId/mandate` | U | ajoute `version`, `mode` (`plan` pour v1), `ownerRsaSpkiHex` (`null` pour v1) |
| `POST /api/threads/:threadId/key-envelope` | U (créateur) | **nouvelle** (C1 §2.6) : `{ "ctx": "thread:<threadId>", "version": 1, "commitment", "signature" }` (`b64` canoniques) ; seulement si l'appelant est le `creatorId` d'une `ThreadKey` du salon et que l'enveloppe est vide ; `200 { threadId, updated }`, même enveloppe : `updated: 0` ; `403 forbidden`, `404 not_found`, `409 envelope_exists`. Sert aussi aux humains (`OrgLayout.vue:349`) |

### 12.2 Canal du runtime (`/api/runtime/v1`, ajouts à 04 §4)

| Méthode et chemin | Auth | Corps | Succès | Refus |
|---|---|---|---|---|
| `POST /conversations/:sessionId/plans` | S+A, bail | `{ leaseEpoch, baseRev, messages, title?, pendingToolCall, consumedInbox, events?, plan: { planId, toolCallId, actionCount, createdAt, expiresAt, serverDigests: [{ n, sha256Hex }] } }` | `201 { rev, planId }` : transcript écrit **et** ligne créée dans une transaction, statut `awaiting_confirmation` | `400 invalid_body` (forme ; `pendingToolCall.name ≠ propose_actions` ; `planId` ou `toolCallId` ≠ ceux de `pendingToolCall` ; `actionCount` hors 1..20 ; `n` de `serverDigests` hors plage ou en double ; `expiresAt` hors `]maintenant, maintenant + confirmationTimeoutSecs + 300]`), `409 plan_exists`, `409 rev_conflict`, `409 lease_conflict` |
| `GET /conversations/:sessionId/plans/:planId` | S+A | — | `200 PlanView` | `404 not_found`, `403 out_of_scope` |
| `POST /conversations/:sessionId/tools/:name/execute` | S+A | `{ leaseEpoch, args?, plan?: { planId, n } }` | inchangé ; avec `plan`, l'état de l'action suit (§8.2) | + `403 action_not_accepted`, `409 action_state_conflict` |
| `POST /e2ee/threads` | S+A | + `plan?: { planId, n }` | inchangé | + `403 autonomy_required`, `403 feature_not_allowed`, `403 action_not_accepted`, `409 action_state_conflict` |
| `GET /delegations` | S | — | ajoute `mandateVersion`, `mode`, `ownerRsaSpkiHex` | — |
| Routes `rt1` et L03f | | | conditions du §10.4 | |

Flux (04 §6) : `delegation.revoked.reason` peut valoir `autonomy_withdrawn` ; `conversation.wake.reason`
`decision` couvre `plan_decision` et `plan_result`.

### 12.3 Politiques (montées sous `/api/orgs/:orgId/ai`)

| Méthode et chemin | Auth | Corps / requête | Succès | Refus |
|---|---|---|---|---|
| `GET /feature-policies` | U-admin | — | `200 { policies: [{ feature, mode, memberCount, enabledCount, updatedAt, updatedBy }] }` (fonctionnalités actives) | `403 forbidden` |
| `PUT /feature-policies/:feature` | U-admin | `{ mode }` | `200 { feature, mode, revoked: <n> }` ; applique §11.4 | `400 invalid_body`, `403 forbidden`, `404 not_found`, `409 feature_reserved` |
| `GET /feature-policies/:feature/members` | U-admin | `?after=<userId>&limit=1..100&q=<recherche>` | `200 { members: [{ userId, addedAt, enabled }], next }` | idem |
| `POST /feature-policies/:feature/members` | U-admin | `{ userIds: [1..100] }` (membres de l'org) | `200 { added }` | `400 invalid_body` (non-membre), idem |
| `POST /feature-policies/:feature/members/remove` | U-admin | `{ userIds: [1..100] }` | `200 { removed, revoked }` ; §11.4 | idem |
| `GET /feature-policies/:feature/events` | U-admin | `?before=<id>&limit=1..100` | `200 { events: [...], next }` | idem |
| `GET /feature-policies/me` | U | — | `200 { features: [{ feature, allowed, enabled, warningVersion }] }` | — |
| `PUT /feature-policies/me/:feature/opt-in` | U | `{ warningVersion }` (entier ≥ 1) | `200 { feature, enabled: true }` | `403 feature_not_allowed`, `404 not_found` (fonctionnalité sans opt-in en v1 : tout sauf `autonomous_mode`) |
| `DELETE /feature-policies/me/:feature/opt-in` | U | — | `200 { feature, enabled: false, revoked: [<delegationId>…] }` | `404 not_found` |

Ajouts et retraits sont idempotents. Liste `list` : au plus 1 000 membres (PC30). `q` cherche dans les
noms comme le sélecteur cherchable existant ; aucune rangée par membre côté app (C1 §5.5).

## 13. Données

Modèles en 07 §10 : `AiActionPlan`, `AiFeaturePolicy`, `AiFeaturePolicyMember`, `AiFeatureOptIn`,
`AiFeaturePolicyEvent` ; champs ajoutés à `AiRuntimeDelegation` (07 §3) ; `kind` de boîte (07 §5) ;
`AI_AUTONOMY_WITHDRAWN` (07 §7). **Aucun contenu en clair** : ni nom, ni argument, ni résumé.

## 14. Codes d'erreur

| Code | Où | Sens |
|---|---|---|
| `plan_invalid` | worker (résultat d'outil), appareil (`reason`), API `400` (forme) | Plan hors des règles du §5 |
| `plan_rejected` | résultat de `propose_actions` | Refus de l'utilisateur ou plan invalide à l'appareil (`reason`) |
| `plan_limit` | `lastErrorCode` (`failed`) | Plus de 3 plans consécutifs dans un tour |
| `plan_exists` | API 409 | `planId` déjà utilisé |
| `plan_not_pending` | API 409 | Décision sur un plan déjà décidé autrement ou expiré |
| `plan_claimed` / `plan_not_claimable` / `plan_claim_lost` | API 409 | Claim d'un autre appareil / statut ne permettant pas le claim / claim expiré ou repris |
| `plan_not_executing` | API 409 | `plan_result` sur un plan non exécuté |
| `action_state_conflict` | API 409 | Transition d'action invalide (dont seconde exécution) |
| `action_not_accepted` | API 403 | Verrou du §8.3 |
| `autonomy_required` | API 403, superviseur | Délégation ou mandat vérifié non `auto` |
| `feature_not_allowed` | API 403 | Politique d'org (ou opt-in absent) |
| `feature_reserved` | API 409 | Fonctionnalité réservée (§11.1) |
| `autonomy_withdrawn` | `revokedReason`, `delegation.revoked.reason` | Retrait du mode autonome (§11.4) |

## 15. Questions ouvertes (non tranchées par C1 ni par les PC)

**QP1 — Ordre d'exécution d'un plan mixte (appareil + agent).** C1 donne `server.call` à l'agent et
`thread.create` à l'appareil, et son exemple fait dépendre une tâche d'un salon, sans dire qui commence
ni comment l'agent apprend les résultats de l'appareil. **Recommandation** (texte marqué
« provisoire ») : phase appareil d'abord, toujours close par `plan_result` ; phase agent ensuite ; une
action d'appareil ne peut dépendre d'une action d'agent (sinon `plan_invalid`, l'agent fait deux plans).

**QP2 — `serverDigests` et `argsRefs`.** Le condensat de `{tool, args}` (C1) ne couvre pas les champs
remplis par `argsRefs` ; l'API verrait des arguments résolus différents. **Recommandation** : condensat
de `JCS({ tool, args, argsRefs })` (sans `argsRefs` s'il est absent, ce qui garde le vecteur actuel) ;
l'appel d'exécution porte `args` non résolu + `refs` résolues ; l'API vérifie le condensat, puis que
chaque valeur de `refs` égale la sortie enregistrée de l'action visée (`progress` porterait alors
`output`, identifiants seulement).

**QP3 — Mécanique de la pause au retrait (PC40).** **Recommandation** : autorisations de session non
révoquées (exemptées de `sweepOrphanAuthorizations` tant que la délégation révoquée a pour raison
`autonomy_withdrawn`) ; conversations `queued` ou `running` → `awaiting_key` avec
`awaitingKey = "delegation:<runtimeId>"` ; les autres états inchangés ; au dépôt suivant, les
autorisations suivent la nouvelle délégation (règle existante) et ces conversations repassent `queued` ;
`keyTimeoutSecs` s'applique (`key_timeout`).

**QP4 — Écart entre la clé RSA servie du propriétaire et `ownerRsaSpkiHex` du mandat v2 (PC27 b,
« prioritaire »).** **Recommandation** : le superviseur prend l'empreinte du mandat v2 vérifié comme
épingle du propriétaire (elle prime sur l'épingle TOFU) ; un écart donne `409 member_key_changed` et une
alerte, comme L05b ; mandat v1 : épinglage TOFU actuel.

**QP5 — Détails fixés par L00f par analogie, à ratifier.** JCS restreint aux entiers ; AAD
`sessionId:planId:plan_result` ; condensats en `hex` ; `plan_decision` en clair déposé par l'API ;
`expiresAt` contrôlé à ±300 s ; sens d'« activé » par fonctionnalité (§11.1) ; `DELETE` de l'opt-in
qui révoque ; actions sensibles avant L14 (§4) ; verrou appliqué aussi à `POST /e2ee/threads` ;
`AiFeaturePolicyEvent` sans purge en v1 ; noms des codes du §14. **Recommandation** : ratifier tels quels.

## 16. Répartition par lot

| Lot | Prend dans ce document |
|---|---|
| L01c | 03 §4.1 (octets, lecture v1/v2), §3.3 (JCS, AAD), fonctions pures TS et Rust, vecteurs `mandate-v2.json` et `action-plan.json` rejoués des deux côtés |
| L03g | §7, §8.3, §9, §10.4, §12.1, §12.2, 07 §3, §5, §10 (`AiActionPlan`) ; vecteurs : condensats, `validationCases` pour la forme vue par l'API |
| L03h | §11, §12.3, 07 §10 (politiques), 03 §8.1 (`autonomy_withdrawn`) |
| L08d | §2, §3, §5, §7.3, §8.2, §10.3 ; `propose_actions`, reprise sur `plan_result`, `created_key` / `repose` conditionnés |
| L10 à L13 | §4 à §8.1, §10.2, §11.3, écrans de C1 §3 et §5.5 |
