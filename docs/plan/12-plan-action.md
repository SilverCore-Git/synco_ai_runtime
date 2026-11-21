# 12 — Plan d'action, mode autonome et politiques d'org (figé par L00f, 2026-11-21)

Source : conception C1 (`.claude/prompts/syncoai_refonte/conception/C1_plan_action.md`), validée par
l'utilisateur, et ses décisions PC34 à PC43 (00 §5). Ce document fige ce dont **L01c** (mandat v2,
fonctions pures), **L03g** (API : plans, verrou, conditions `auto`), **L03h** (API : politiques) et
**L08d** (runtime) ont besoin pour travailler en parallèle. Les questions QP1 à QP5 que ni C1 ni les PC
ne tranchaient ont été tranchées par l'utilisateur le 2026-11-21 (**PC44 à PC48**, §15) : amendement
du même jour (ordre libre des phases, condensat et `refs`, pause au retrait, épingle du mandat v2,
rétention du journal), puis par **PC54 à PC58** (second amendement : échec limité aux dépendantes,
message pendant un plan et arrêt, durée de vie du lien objet ↔ plan, risque accepté du mode autonome,
graphe explicite et exécution parallèle).

Conventions : 00 §3. Colonne « Auth » : **S** et **S+A** comme en 04 §4 ; **U** = route utilisateur
(Keycloak, `authMiddleware`, membre de l'org, `banMiddleware`), montée sous `/api/orgs/:orgId/ai`
comme les routes de 03 §7 ; **U-prop** = U et propriétaire de la conversation ; **U-admin** = U et
propriétaire de l'org ou permission `ORG_AI`. Erreurs : `{ "error": "<code>" }`, codes au §14.

## 1. Principe

```
 worker ──(1) propose_actions── POST …/plans : transcript chiffré (CK) + ligne AiActionPlan (métadonnées :
   │                                          exécutant et after de chaque action) ; awaiting_confirmation + push
   ▼ s'arrête
               appareil de l'utilisateur (déverrouillé)
               (2) déchiffre, valide (§5), affiche (C1 §3) ; l'utilisateur coche et accepte
               (3) decision : chaque exécutant démarre les actions prêtes qui lui reviennent (§8.1)
 ┌──────── graphe explicite (after = needs), actions prêtes exécutées en parallèle (PC44, PC58) ─────────┐
 │ appareil, phase k : claim (un seul appareil) → actions prêtes en parallèle par les routes normales   │
 │                     → clés des salons → plan_result:k (boîte, chiffré CK) → réveil si l'agent a du   │
 │                     travail                                                                           │
 │ agent, phase k    : le worker exécute ses actions prêtes en parallèle (verrou §8.4)                   │
 │                     → plan_agent_result:k (chiffré CK) → awaiting_confirmation ; le worker s'arrête   │
 │ les deux peuvent avancer en même temps sur des branches indépendantes ; un échec n'annule que ses     │
 │ dépendantes (PC54)                                                                                    │
 └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
 worker : quand plus rien n'est en attente (ou arrêt, expiration), ferme propose_actions avec le bilan,
          puis traite les messages arrivés pendant le plan (PC55)
```

Le plan **généralise** `awaiting_confirmation` (C1 §2.1) : même état, même notification, même délai
`confirmationTimeoutSecs`, même `pendingToolCall`, même boîte de réception. Les outils mutants dont la
politique effective est `ask` passent **tous** par le plan (PC38). Quand l'agent n'a plus rien de prêt,
la conversation revient en `awaiting_confirmation` : l'app doit être ouverte pour exécuter les actions
d'appareil.

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

**Description de l'outil donnée au modèle (PC58)**, à reprendre telle quelle par L08d :

> Propose un plan d'actions que l'utilisateur validera. Déclare pour chaque action, dans `after`, toutes
> les actions dont elle a **réellement** besoin, et seulement celles-là : une action sans `after` démarre
> tout de suite, et les actions prêtes s'exécutent **en parallèle**. N'ajoute jamais de dépendance pour
> imposer un ordre d'affichage ou par prudence : chaque `after` superflu ralentit le plan. Quand une
> action utilise l'identifiant créé par une autre, mets cette autre dans `after` et l'identifiant dans
> `argsRefs` (`"$<n>.id"`). Regroupe les actions liées avec `groups` (par exemple une catégorie et ses
> salons) pour que l'utilisateur lise le plan facilement ; les groupes ne changent pas l'exécution.

### 3.2 Clair (interne, chiffré sous `CK`)

```json
{ "v": 1, "planId": "<UUID v4 tiré par le worker>", "sessionId": "<conversation>", "toolCallId": "call_7",
  "createdAt": 1795000000, "expiresAt": 1795604800, "summary": "<texte du modèle, affiché comme tel>",
  "groups": [ { "id": "finance", "label": "Catégorie Finance et ses salons" } ],
  "actions": [
    { "n": 1, "kind": "thread.create", "args": { "name": "budget", "type": "text", "spaceId": "cm…" },
      "group": "finance" },
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
| `groups` | facultatif (PC58) ; 1 à 20 objets `{ id, label }`, `id` = `[a-z0-9_-]{1,32}` distincts, `label` chaîne de 1 à 100 ; présentation seulement |
| `group` | facultatif ; `id` d'un élément de `groups` |
| `after` | facultatif ; entiers distincts, chacun `< n` ; équivalent de `needs` (§8.1) : toutes les actions requises, et seulement elles |
| `argsRefs` | facultatif ; `{ "<champ de args>": "$<m>.<champ exporté>" }`, `m ∈ after` (action d'appareil ou d'agent, PC44), champ exporté par le `kind` de `m` (§4), champ cible présent dans le schéma de l'action et **absent** de `args` |

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
| `category.create` | `name` (1 à 255), `spaceId?` (id) — ajouté par PC58 (cas « une catégorie et ses salons ») | appareil | appareil | `id`, `spaceId` | aucune |
| `thread.create` | `name` (1 à 255), `type` ∈ `text`, `voice`, `spaceId?` (id), `categoryId?` (id, PC58) — paramètres de l'outil `create_thread`, un salon par action | **appareil** (§8.2) | si la politique effective de `create_thread` est `ask` : **runtime** (`POST /e2ee/threads` + `rt1`, §8.3) ; si `auto` : hors plan | `id`, `spaceId` | `thread:<id>` |
| `folder.create` | `spaceId` (id), `name` (1 à 255), `parentFolderId?` (id) | appareil | appareil | `id`, `spaceId` | aucune |
| `file.create_text` | `spaceId` (id), `name` (1 à 255, extension de `textFileFormats.ts`), `content?` (chaîne), `folderId?` (id) | appareil | appareil | `id`, `spaceId` | aucune |
| `server.call` | `tool` : outil du manifeste de catégorie `server`, `mutating` ; `args` : schéma de l'outil (`parameters`) | **agent**, sans signature (§8.3) | agent | `id` (= `data.id` du résultat, s'il est un identifiant) | aucune |

- `thread.create` : l'appareil reprend `createThreadHelper` / `CreateNewThread.vue` : route
  `POST /api/threads/space/:spaceId` (ou `/api/threads/org/:orgId` sans `spaceId`), `type` `voice` →
  `vocal` (vocabulaire de `createThreadSchema`), catégorie = `categoryId` s'il est donné, sinon la
  première catégorie visible de la cible (règle de L03d, 04 §4.3), clé du salon scellée pour les membres avec épinglage FC1, puis enveloppe FC4
  du créateur par `POST /api/threads/:threadId/key-envelope` (§12.1).
- `category.create` : route existante `POST /api/categories/space/:spaceId` (ou `/api/categories/org/
  :orgId` sans `spaceId`), `index` = après la dernière catégorie de la cible.
- `folder.create` : `createFolderRequest` (`POST /api/spaces/:spaceId/folders`). `file.create_text` :
  `createTextFile` (envoi CDN chiffré, PC6, PC41). Le bac à sable du worker ne change pas.
- **Exécutant** : fixé à la création par le worker, selon ce tableau et le mode de son mandat vérifié ;
  l'API le stocke avec `after` (§12.2) et l'appareil les recontrôle (§5, règle 8).
- **Actions sensibles** (C1 §3, règle 3 : non précochées, cochées une par une) : niveau de risque fourni
  par L14. En attendant L14 : toute action `server.call` dont l'outil supprime (`delete_*`) ou envoie
  hors de Synco (`create_email_report`) (ratifié, PC48).
- Un nouveau `kind` demande un lot dédié et la mise à jour du §5 ; les catalogues L14 et L15 ajoutent
  des `server.call` sans changer ce document.

## 5. Validation

Faite par le **worker** avant d'écrire, et **refaite par l'appareil** avant d'afficher ; tout échec
rend le plan entier invalide (code `plan_invalid`). Règles (vecteurs `action-plan.json`,
`validationCases`) :

1. Champs du §3.2 (`groups` et `group` compris), rien d'autre ; chaque `group` existe dans `groups` ; `v = 1` ; identifiants conformes ; `sessionId` = la conversation.
2. `createdAt < expiresAt`, écart ≤ délai de l'org (et ≤ 604 800).
3. 1 à 20 actions, `n` consécutifs depuis 1 ; clair canonique ≤ 64 Kio.
4. `kind` dans la liste ; `tool` présent seulement pour `server.call`, outil `server` et `mutating` du
   manifeste (`GET …/tools`) ; `args` stricts (champs connus, requis présents dans `args` ou fournis par
   `argsRefs`, types et bornes).
5. `after` et `argsRefs` conformes au §3.2 (vers des actions **antérieures** seulement : aucun cycle).
6. Aucune contrainte d'exécutant sur `after` ni sur `argsRefs` (PC44) : une action d'appareil peut
   dépendre d'une action d'agent, et inversement (§8.1).
7. Appareil seulement : chaque `spaceId`, `categoryId`, `parentFolderId`, `folderId` écrit dans `args` est résolu dans
   l'annuaire local ; un identifiant inconnu bloque le plan (C1 §2.6). Une valeur venue d'`argsRefs`
   est contrôlée à l'exécution (§8.2, étape 3).
8. Appareil seulement : l'exécutant et l'`after` de chaque action servis par l'API (`PlanView.actions`,
   §12.1) égalent ceux du plan déchiffré (exécutant selon le §4 et le mode de sa délégation courante).

Un plan invalide **à l'appareil** est refusé par la route de décision avec `reason: "plan_invalid"`
(§12.1) : le worker reçoit `{"error":"plan_rejected","reason":"plan_invalid"}`. L'API ne voit pas le
clair ; elle contrôle ce qu'elle reçoit (§12.2).

## 6. Dépendances et acceptation partielle (PC37)

- L'utilisateur peut décocher toute action. Les actions qui en dépendent (`after`, transitivement)
  sont décochées **en cascade**, et l'écran le montre avant validation (« décocher #budget retire
  aussi la tâche 5 »). Vecteurs : `cascadeCases`.
- Une action sensible n'est jamais précochée et le bouton principal reste grisé tant que chacune n'est
  pas cochée ou retirée ; il n'existe pas de « Tout accepter » qui les couvre (C1 §3).
- La cascade ignore l'exécutant : décocher une action d'agent retire les actions d'appareil qui en
  dépendent, et inversement (`cascadeCases`, plan mixte).
- La décision envoie l'ensemble `accepted` ; les autres actions passent `skipped`.

## 7. États et expiration

### 7.1 Plan (`AiActionPlan.status`)

```
proposed ──decision accept──▶ accepted ──1re action démarrée──▶ executing ──▶ done         (aucune action en échec ni d'issue inconnue)
   │  └──decision reject────▶ rejected                              │   ├──▶ failed       (au moins une action en échec)
   └──expiresAt──────────────▶ expired ◀──────── expiresAt ─────────┤   ├──▶ interrupted  (aucun échec, au moins un unknown_outcome)
                                          stopped ◀── « Arrêter le plan » (PC55) ──┘
```

- `accepted` → `executing` dès qu'une action démarre (claim et `progress executing` de l'appareil, ou
  premier appel d'exécution du runtime).
- **Fin normale** : quand il ne reste aucune action `pending` ni `executing`, le statut est calculé :
  `failed` si une action est `failed`, sinon `interrupted` si une action est `unknown_outcome`, sinon
  `done`. Un échec ne termine donc pas le plan : les actions indépendantes continuent (PC54, §7.3).
- `rejected` : refus de l'utilisateur, plan invalide à l'appareil, ou message de l'utilisateur reçu
  **avant la décision** (le worker clôt `propose_actions` avec `superseded_by_user_message`, 08 §2).
  Après l'acceptation, un message **n'arrête pas** le plan (PC55, §8.6).
- `stopped` (PC55, §8.6) : l'utilisateur arrête un plan `accepted` ou `executing` ; les actions `pending`
  passent `skipped`, celles qui sont `executing` vont à leur terme.
- `expired` : l'expiration vaut pour **le plan entier** : **aucune action ne démarre après
  `expiresAt`**. À `expiresAt`, les actions `pending` passent `skipped` ; celles qui sont `executing` vont
  à leur terme ; le plan est `expired` quand il n'en reste plus. Plan jamais décidé (`proposed`) : la
  conversation suit la transition existante `failed` (`confirmation_timeout`, C1). Plan accepté : la
  conversation passe `queued` (si elle attendait) et le worker ferme `propose_actions` avec le bilan.
- États terminaux : `done`, `failed`, `interrupted`, `rejected`, `stopped`, `expired`. À la clôture, les
  liens objet ↔ action sont purgés (PC56, §8.5).

### 7.2 Action (`AiActionPlanAction.state`)

`pending` → `executing` → `done` | `failed` ; `pending` → `skipped` (décochée, dépendante d'une action
qui n'a pas abouti, plan arrêté ou expiré) ; `executing` → `unknown_outcome` (claim expiré, ou appel
d'agent interrompu). **Une action n'entre qu'une fois en `executing`** : une ligne par action,
`updateMany` conditionné à l'état lu ; une seconde tentative reçoit `409 action_state_conflict`
(C1 §2.6). Elle n'y entre que si elle est **prête** (§8.1) et que son exécutant est l'appelant (sinon
`409 plan_phase_mismatch`).

### 7.3 Échec (PC54), plafond

- Une action `failed` ou `unknown_outcome` fait passer `skipped` ses **seules dépendantes transitives**
  (par `after`, qui contient toutes les cibles d'`argsRefs`, §3.2), quel que soit leur exécutant. Les
  actions indépendantes continuent, sur l'appareil comme chez l'agent. **Aucune annulation
  automatique.** C'est la même règle que la cascade de décision (PC37, §6). Vecteurs : `failureCases`,
  `runCases`, `categoryPlan`.
- L'agent reçoit le bilan action par action et peut proposer un **nouveau** plan ; au plus **3 plans
  consécutifs par tour**, au-delà le tour échoue : `failed`, code `plan_limit` (08 §6).

### 7.4 Délais

| Délai | Valeur |
|---|---|
| Expiration du plan | `expiresAt` = `createdAt` + `confirmationTimeoutSecs` de l'org (défaut 7 j, borné [1 h, 7 j]), pour le plan entier |
| Attente de l'appareil | jusqu'à `expiresAt`, sans autre délai ; un push quand des actions d'appareil deviennent prêtes et qu'aucun appareil ne les tient, aucune relance |
| Claim | 5 min, pour **une** phase d'appareil ; prolongé de 5 min par chaque `progress` ou nouveau `claim` du même appareil ; libéré au dépôt de `plan_result:<k>` |

## 8. Exécution

### 8.1 Graphe, niveaux et actions prêtes (PC44, PC58)

Le plan est un **graphe explicite**, comme les jobs de GitHub Actions : `after` est l'équivalent de
`needs` (nom gardé, déjà figé) et liste **toutes** les actions dont une action a besoin, et elles
seules. `groups` / `group` (§3.2) ne servent qu'à la présentation.

- **Niveau** : `niveau(a) = 1` si `after` est vide, sinon `1 + max(niveau(m), m ∈ after)`. Il sert à la
  présentation (colonnes, §17) et décrit le parallélisme maximal ; il ne contraint pas l'exécution.
- **Action prête** : acceptée, `pending`, et toutes les actions de son `after` sont `done`. Si l'une
  d'elles finit `failed`, `unknown_outcome` ou `skipped`, l'action passe `skipped` (§7.3).
- **Ordre libre et parallèle** : chaque exécutant démarre, dès qu'il le peut, **toute** action prête qui
  lui revient, en parallèle dans la limite de sa concurrence (§8.7), la plus petite `n` d'abord. Aucun
  exécutant n'attend une branche de l'autre sans rapport avec ses actions.

**Ajustement de PC44 (signalé).** Le premier amendement calculait d'avance des phases strictement
alternées (phases impaires d'appareil, paires d'agent). Ce calcul sérialisait des branches
indépendantes : dans un plan `[agent A, appareil B]` sans dépendance, A attendait la fin de B. Les phases
sont désormais **dynamiques** : une **phase d'appareil** est une séance d'exécution de l'appareil (un
claim, un `plan_result:<k>`), une **phase d'agent** est une reprise du worker (une
`plan_agent_result:<k>` si le plan n'est pas fini). Une phase d'appareil et une phase d'agent peuvent se
**chevaucher** ; chaque exécutant numérote les siennes de 1 en 1. Le reste de PC44 tient : une action
d'appareil peut dépendre d'une action d'agent, chaque phase d'appareil se clôt par un résultat partiel,
l'agent signale qu'il a fini sa part, l'app doit être ouverte pour exécuter, un seul appareil par phase.

L'API connaît le graphe sans contenu : pour chaque action, `executor` et `after` (§12.2). Elle calcule
seule ce qui est prêt et refuse tout démarrage d'une action non prête.

À la décision `accept` : s'il existe une action d'agent prête, la conversation passe `queued` et le
runtime est réveillé ; s'il existe une action d'appareil prête, l'appareil qui vient de décider la
démarre. Les deux à la fois si besoin.

### 8.2 Phase d'appareil

Préalables (C1 §2.6) : app **ouverte** et déverrouillée, délégation active avec `DK` en mémoire (sinon
renouvellement, 03 §7.1), plan revalidé (§5). **Sans appareil, les actions d'appareil attendent**
jusqu'à `expiresAt` (§7.1) ; l'agent, lui, avance sur ses branches. Phase `k` (= nombre de phases
d'appareil déjà closes + 1) :

1. Avant la première phase : `POST …/decision` (§12.1).
2. `POST …/claim { deviceId, phase: k }` : une phase est réservée par **un seul appareil** ; un autre
   reçoit `409 plan_claimed` et affiche « en cours sur votre autre appareil ». Le claim n'est accordé que
   s'il existe une action d'appareil prête ; il ne dépend pas de l'état de la conversation (l'agent peut
   travailler en même temps).
3. **Références** : chaque `argsRefs` est résolu depuis les résultats de phase déchiffrés
   (`plan_result:<j>`, `plan_agent_result:<j>`, §9) et doit **égaler** la sortie enregistrée par l'API
   (`PlanView.actions[m-1].output`, §8.5). Un écart : l'action passe `failed` sans appel, avec une
   alerte (« résultat incohérent »), et ses dépendantes `skipped` (§7.3).
4. Exécution parallèle (§8.7) : pour chaque action prête, `progress { n, state: "executing" }`, appel de
   la **route normale** de l'utilisateur avec l'en-tête `X-Synco-Plan: <planId>/<n>` (aucun effet sur
   les droits, §8.5), puis `progress { n, state: "done" | "failed" }`. L'appareil relit `PlanView` (push,
   `ai:session-status` ou après chaque action) : une action devenue prête, y compris grâce à l'agent,
   rejoint la phase en cours.
5. **Clés** : avant le résultat, ajout des entrées des salons créés (`POST …/delegations/:delegationId/
   entries`, 03 §7.2) ; le runtime reçoit `delegation.entries_added`.
6. **Fin de phase** quand aucune action d'appareil n'est prête ni `executing` : élément `plan_result:<k>`
   (§9), qui libère le claim. L'API le refuse (`409 plan_phase_mismatch`) s'il reste une action
   d'appareil prête ou en cours : l'appareil relit et continue. Si des actions d'agent sont devenues
   prêtes et que la conversation attendait, elle passe `queued` et le runtime est réveillé ; si le plan
   est fini, elle passe `queued` pour la clôture. Si le résultat arrive avant la clé, `awaiting_key` prend
   le relais.

Claim perdu : les actions `executing` de l'appareil passent `unknown_outcome` (dépendantes `skipped`),
le claim est libéré ; les autres actions d'appareil prêtes restent disponibles pour une nouvelle phase.
L'appareil qui avait perdu le claim dépose quand même `plan_result:<k>` de ce qu'il a fait (sans claim,
accepté pour cette phase).

### 8.3 Phase d'agent

Le worker reprend sur `conversation.wake` (décision avec une action d'agent prête, `plan_result` qui en
a rendu une prête, fin du plan, arrêt ou expiration) :

1. Il déchiffre les résultats de phase reçus et les recontrôle (AAD, `planId`, `phase` ; sinon
   `tool_call_unverified`, 06 §9).
2. Il exécute **en parallèle** (§8.7) les actions d'agent prêtes : `server.call` par
   `POST …/tools/:name/execute`, et en mode autonome `thread.create` (politique `ask`) par
   `POST /e2ee/threads` avec `rt1`. Chaque appel porte `plan: { planId, n }` et, pour une action à
   `argsRefs`, `args` **non résolus**, `argsRefs` et `refs` (§8.4). L'API passe l'action `executing`
   puis `done` / `failed` dans la même requête et **enregistre sa sortie** (§8.5). Un appel interrompu
   (transport coupé après envoi) donne `unknown_outcome`, jamais relancé (08 §5). Entre deux appels, il
   relit la boîte : un `plan_result` arrivé entre-temps peut rendre d'autres actions prêtes.
3. Fin de la phase, quand aucune action d'agent n'est prête ni `executing` :
   - plan terminé (aucune action `pending` ni `executing`, ou plan `stopped` / `expired`) : il ferme
     `propose_actions` par un `tool_result` portant l'état et la sortie de chaque action (ordre de `n`),
     puis le tour continue (`running`) et traite les messages arrivés pendant le plan (§8.6) ;
   - sinon : `POST …/plans/:planId/agent-result` (§12.2) avec `plan_agent_result:<k>` (§9). Dans une
     transaction, l'API enregistre la valeur, repasse la conversation `awaiting_confirmation` (même
     `pendingToolCall`) et, si des actions d'appareil sont prêtes sans claim, envoie le push
     `AI_AWAITING_CONFIRMATION` (« Votre plan continue : à poursuivre sur votre appareil », sans
     contenu) et `ai:session-status`. Le worker s'arrête. L'API refuse (`409 plan_phase_mismatch`) s'il
     reste une action d'agent prête : le worker relit et continue (pas de réveil perdu).

Le signal vers l'appareil n'est **pas** un élément de boîte (la boîte va de l'utilisateur vers le
runtime) : `plan_agent_result:<k>` est rangé avec le plan et servi par `PlanView`.

### 8.4 Verrou serveur des actions `ask` (PC38, PC47)

Un appel du runtime à `POST /conversations/:sessionId/tools/:name/execute` pour un outil dont la
politique effective est `ask`, ou à `POST /e2ee/threads` quand celle de `create_thread` est `ask`, doit
porter `plan: { planId, n }`. L'API vérifie, sinon **`403 action_not_accepted`** :

1. la ligne `AiActionPlan` existe, de cette conversation et de l'utilisateur de l'autorisation ;
2. son statut est `accepted` ou `executing`, la décision a été écrite par la route **utilisateur** de
   décision, et `expiresAt` n'est pas passé (sinon `409 plan_not_executing`) ;
3. l'action `n` est acceptée, `pending` (sinon `409 action_state_conflict`), d'exécutant `agent` et
   **prête** (sinon `409 plan_phase_mismatch`) ;
4. `server.call` (PC47) :
   - `serverDigests[n]` = SHA-256 (`hex`) de `JCS({ tool: name, args, argsRefs })` calculé sur l'appel
     **reçu** : `args` non résolus et `argsRefs` tels que dans le plan ; `argsRefs` est **omis** de
     l'objet s'il est absent (le condensat d'une action sans référence est celui de C1) ;
   - `refs` a exactement les clés d'`argsRefs` ; pour chaque champ `f` avec `argsRefs[f] = "$m.x"`,
     l'action `m` est `done` et `refs[f]` = la sortie `x` **enregistrée par l'API** (§8.5), qu'`m` soit
     une action d'agent ou d'appareil ;
   - les arguments exécutés sont `args` ∪ `refs`, validés par le schéma de l'outil comme aujourd'hui ;
5. `thread.create` : aucune empreinte (C1 : `serverDigests` ne couvre que `server.call`), l'action doit
   seulement être acceptée et prête ; ses `refs` ne sont pas recontrôlées (risque accepté, PC57, §10.6).

Un `refs` mal formé (valeur non chaîne, clé dans `args`) est `400 invalid_body`. Un outil `auto`
n'exige rien (un `plan` fourni est alors contrôlé de la même façon) ; `deny` reste refusé avant tout
(`tool_denied_by_policy`). Vecteurs : `serverDigests`, `executeCases`.

### 8.5 Sorties connues de l'API, lien objet ↔ action (PC47, PC56)

L'API ne lit **rien de chiffré** : elle connaît la sortie de chaque action parce qu'elle a **créé
l'objet elle-même** et l'enregistre à ce moment-là dans `AiActionPlanAction.output` (champs exportés du
§4, identifiants seulement) :

- **action d'agent** : à l'exécution (§8.4), depuis sa propre réponse (`data.id` d'un `server.call`
  quand c'est un identifiant ; `id` et `spaceId` du salon créé par `POST /e2ee/threads`) ;
- **action d'appareil** : la route normale qui crée l'objet (catégorie : `POST /api/categories/space/
  :spaceId` ou `/api/categories/org/:orgId` ; salon : `POST /api/threads/space/:spaceId` ou
  `/api/threads/org/:orgId` ; dossier : `POST /api/spaces/:spaceId/folders` ; fichier texte : la route
  qui enregistre le fichier envoyé au CDN, `POST /api/cdn/transfers/uploads` et sa finalisation), quand
  elle reçoit `X-Synco-Plan: <planId>/<n>` et que l'action `n` est `executing`, d'exécutant `device`,
  dans un plan de cet utilisateur sous claim valide, enregistre `{ id, spaceId }` de l'objet qu'elle
  vient de créer. **Une seule fois** (`updateMany` conditionné à une sortie vide) ; une seconde création
  sous le même en-tête aboutit normalement (l'en-tête ne change pas les droits) mais n'est pas
  enregistrée : elle est journalisée **sans** identifiant d'objet (`AiChatSessionEvent`
  `type: "plan_duplicate_create"`, `code: "<planId>.<n>"`).
- `progress { state: "done" }` d'une action d'appareil exige une sortie enregistrée, sinon
  `409 action_output_missing`.

Double contrôle : le worker résout `refs` depuis `plan_result:<k>`, authentifié par `CK`, et l'API les
compare à ce qu'elle a enregistré ; l'appareil fait de même pour les sorties d'agent (§8.2, étape 3).
Une API qui fausserait une sortie ne fait qu'arrêter la branche concernée.

**Durée de vie du lien (PC56).** Le lien « objet créé ← plan / action » (la colonne `output`, seul
endroit où il est écrit) n'existe que **le temps du plan** : il est effacé (`output = null`) dans la
transaction qui passe le plan à un état terminal (`done`, `failed`, `interrupted`, `rejected`,
`stopped`, `expired`), et une passe de maintenance bornée rattrape les plans clos dont un lien
subsisterait (07 §9). Après la clôture, les sorties ne vivent plus que dans les résultats de phase
chiffrés et dans le `tool_result` du transcript (chiffré). Le lien figure au catalogue RGPD (07 §11).

### 8.6 Message pendant un plan, arrêt du plan (PC55)

- **Avant la décision** (`proposed`) : règle existante, le message remplace le plan (`rejected`,
  `superseded_by_user_message`).
- **Après l'acceptation** (`accepted`, `executing`) : le message **n'arrête pas** le plan. Il est déposé
  dans la boîte comme d'habitude, mais la conversation **ne change pas d'état** (elle reste
  `awaiting_confirmation`, ou `running` si l'agent travaille) et le worker ne le lit pas avant d'avoir
  fermé `propose_actions`. Il est traité **après le plan**, au tour qui suit la clôture, et non à la
  phase d'agent suivante : l'appel `propose_actions` doit être clos par son `tool_result` avant tout
  nouveau message de l'utilisateur dans le transcript, et le modèle reçoit ainsi le bilan avant la
  question. L'app l'annonce sous le message (« sera traité à la fin du plan ; Arrêter le plan pour le
  traiter maintenant »).
- **Arrêter le plan** : route `POST …/plans/:planId/stop` (U-prop, §12.1), seule façon d'arrêter un plan
  accepté. Dans une transaction : plan `stopped`, actions `pending` → `skipped`, claim libéré, dépôt de
  l'élément `plan_decision` `{ decision: "stop" }` (`id = stop:<planId>`, API seule) ; la conversation
  qui attendait passe `queued` et le runtime est réveillé. Les actions `executing` vont à leur terme et
  peuvent encore rapporter `done` / `failed` ; aucune ne démarre plus (`409 plan_not_executing`). Le
  worker ferme `propose_actions` avec le bilan (`"stopped": true`), puis traite les messages en attente.
  Rejeu sur un plan déjà `stopped` : `200` ; sur un autre état terminal : `409 plan_not_executing`.

### 8.7 Concurrence, ordre des rapports, idempotence, limites de débit (PC58)

| | Appareil | Agent (worker) |
|---|---|---|
| Concurrence par défaut | **4** actions en cours au plus par plan | **4** (`plan.concurrency` de la configuration du runtime) |
| Maximum | **8** (constante de l'app, non réglable par l'utilisateur) | **8** (valeur hors [1, 8] refusée au démarrage) |

- **Choix** : parmi les actions prêtes, la plus petite `n` d'abord ; une place libérée est reprise
  aussitôt (pas d'attente par niveau entier).
- **Ordre des rapports** : chaque action rapporte `executing` avant son appel et `done` / `failed` après,
  dans l'ordre où elle se termine ; l'API n'exige aucun ordre entre actions (une ligne par action).
  `plan_result`, `plan_agent_result` et le `tool_result` final listent les actions dans l'ordre de `n`.
- **Idempotence** : `progress` qui répète l'état déjà enregistré par le même appareil → `200` sans effet
  (rejeu après coupure) ; toute autre transition invalide → `409 action_state_conflict`. Une action
  n'entre qu'une fois en `executing` (§7.2) ; sa sortie n'est enregistrée qu'une fois (§8.5). Le statut
  du plan est recalculé dans la transaction de chaque transition d'action (`updateMany` conditionné),
  si bien que deux fins simultanées ne perdent rien.
- **Limites de débit (`429`)** : un `429` (`rate_limited`, `rt_rate_limited`, limite des routes
  utilisateur) signifie que rien n'a été exécuté. L'exécutant **réessaie le même appel** au plus
  **3 fois** (4 essais) : délai `Retry-After` s'il est fourni (plafonné à 30 s), sinon 1 s, 2 s puis 4 s,
  ± 20 % ; et il **réduit sa concurrence de moitié** (au moins 1) pour le reste de la phase. Au-delà :
  action `failed` (code `rate_limited` dans le bilan), dépendantes `skipped` (§7.3). Un `429` sur
  `progress` se réessaie de même (l'appel est idempotent). Un transport coupé **après** envoi n'est
  jamais réessayé : `unknown_outcome`.

## 9. Résultats de phase et éléments de boîte de réception

Ajoutés à 05 §6.2 (les éléments existants restent valides, C1 §7). Clair de chaque résultat de phase
= `JCS({ v: 1, planId, phase: k, outcomes: [{ n, state, output? }] })`, `outcomes` = les actions
traitées pendant cette phase (dans l'ordre de `n`), `output` = champs exportés (§4), identifiants
seulement. `k` est compté **par exécutant** (§8.1).

| `t` / valeur | Déposé par | `id` | Charge | Transition (08 §2) |
|---|---|---|---|---|
| `plan_decision` (boîte) | **l'API seule**, par la route de décision ou d'arrêt (`source = "api"`) ; refusé sur `POST …/inbox` et du runtime (`400 invalid_body`) | `decision:<planId>`, `stop:<planId>` | `{ planId, decision: "accept" \| "reject" \| "stop", accepted?: [n…], reason? }` (métadonnées, en clair) | `reject`, `stop` : `awaiting_confirmation` → `queued` ; `accept` : `queued` s'il existe une action d'agent prête, sinon aucune |
| `plan_result` (boîte), un par phase d'appareil | l'appareil, par `POST …/sessions/:sessionId/inbox` ou par WebSocket (le runtime le rend durable) | `plan:<planId>:<k>` | `{ planId, phase: k, value: "gcm1:…" }`, AAD `sessionId:planId:plan_result:<k>` | `awaiting_confirmation` → `queued` si une action d'agent est devenue prête ou si le plan est fini ; sinon inchangé |
| `plan_agent_result` (**pas** un élément de boîte), un par phase d'agent qui ne finit pas le plan | le worker, par `POST …/plans/:planId/agent-result` (§12.2) ; rangé avec le plan, servi par `PlanView` | — | `{ phase: k, value: "gcm1:…" }`, AAD `sessionId:planId:plan_agent_result:<k>` | `running` → `awaiting_confirmation` |

- `state` ∈ états du §7.2. Le numéro de phase est dans l'AAD et dans le clair : un résultat ne se rejoue
  ni sur une autre phase, ni sur un autre plan, ni comme résultat de l'autre exécutant (vecteurs
  `encryptionCases`).
- Dépôt de `plan_result:<k>` : la ligne existe pour cette conversation ; statut ∈ `executing`, ou un
  état terminal atteint pendant la phase (sinon `409 plan_not_executing`) ; `k` = la phase réclamée, et
  plus aucune action d'appareil prête ni `executing` (sinon `409 plan_phase_mismatch`). Doublon : `200`,
  rien n'est rejoué.
- Réveil : `conversation.wake` `reason: "decision"` pour `plan_decision` et `plan_result`.
- Le worker rejette un résultat de phase qui ne correspond pas au `pendingToolCall` déchiffré (autre
  `planId`, autre phase, AAD fausse) : `tool_call_unverified` (06 §9).
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
- **Épingle du propriétaire (PC46)** : pour un mandat v2 vérifié, `ownerRsaSpkiHex` **est** l'épingle de
  la clé RSA du propriétaire et prime sur l'épingle TOFU de `member-rsa-pins.json` (06 §4.3) ; une clé
  servie différente donne `409 member_key_changed` et l'alerte du dashboard, comme L05b. Mandat v1 :
  épinglage TOFU actuel.

### 10.4 Conditions `auto` côté API

| Route | Condition ajoutée | Refus |
|---|---|---|
| `POST /e2ee/threads` (créateur `rt1:`) | délégation de l'autorisation `mode = auto` ; `isFeatureAllowed(autonomous_mode)` ; verrou du §8.4 si `create_thread` est `ask` | `403 autonomy_required`, `403 feature_not_allowed`, `403 action_not_accepted` |
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

### 10.6 Risque accepté : références du `thread.create` autonome (PC57)

En mode autonome, `thread.create` est exécuté par le runtime sans condensat (C1 : `serverDigests` ne
couvre que `server.call`). Quand il porte des `argsRefs` (par exemple `spaceId` ou `categoryId` venu
d'une action précédente), le worker les résout depuis les résultats de phase authentifiés par `CK`, mais
l'API **ne les recontrôle pas** contre ses sorties enregistrées (§8.4, point 5). Un runtime fautif
pourrait donc créer le salon dans un autre espace ou une autre catégorie **où le délégant a déjà le
droit de créer** : les droits de la route et le verrou « action acceptée et prête » s'appliquent
toujours, le mandat `auto` doit être en vigueur, et la création reste tracée (`creatorId = rt1:…`,
`plan_action`). **Accepté par l'utilisateur (PC57)** ; à revoir si `thread.create` entre un jour dans
`serverDigests`. Repris dans la liste des risques (§15).

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
   plan** au prochain dépôt d'une délégation par son app (PC40). Mécanique (PC45) : les autorisations de
   session ne sont **pas** révoquées (exemptées de `sweepOrphanAuthorizations` tant que la délégation
   révoquée a pour raison `autonomy_withdrawn`) ; les conversations `queued` ou `running` passent
   `awaiting_key` avec `awaitingKey = "delegation:<runtimeId>"`, les autres états sont inchangés ; au
   dépôt suivant, les autorisations suivent la nouvelle délégation (règle existante) et ces
   conversations repassent `queued` ; au-delà de `keyTimeoutSecs`, `failed` `key_timeout` ;
4. ce qui a été fait reste fait ; les plans `proposed` sont **sans effet** (leur exécutant serait
   désormais l'appareil), et une action d'agent `thread.create` restante d'un plan en cours échoue
   (`autonomy_required`, arrêt du §7.3) ;
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
**Rétention (PC48, RGPD)** : 1 an, puis purge bornée côté API (07 §9), comme `AiThreadEnvelopeEvent`
(PC29).

## 12. Routes

### 12.1 Utilisateur : plans (montées sous `/api/orgs/:orgId/ai/sessions/:sessionId`)

| Méthode et chemin | Auth | Corps | Succès | Refus |
|---|---|---|---|---|
| `GET /plans/:planId` | U-prop | — | `200 PlanView` | `404 not_found` |
| `POST /plans/:planId/decision` | U-prop | `{ "decision": "accept", "accepted": [1,3,4,5] }` ou `{ "decision": "reject", "reason"?: "plan_invalid" }` | `200 PlanView` ; même décision rejouée : `200` | `400 invalid_body` (`accepted` vide, hors `1..actionCount`, doublon), `404 not_found`, `409 plan_not_pending` (déjà décidé autrement, expiré), `409 not_runtime` |
| `POST /plans/:planId/claim` | U-prop | `{ "deviceId": "<id>", "phase": <k> }` | `200 { phase, claimExpiresAt }` (prise ou prolongation) | `404`, `409 plan_claimed` (autre appareil, claim valide), `409 plan_phase_mismatch` (`k` ≠ phases d'appareil closes + 1, ou aucune action d'appareil prête), `409 plan_not_claimable` (statut ∉ `accepted`, `executing`, ou `expiresAt` passé) |
| `POST /plans/:planId/progress` | U-prop | `{ "deviceId", "n", "state": "executing" \| "done" \| "failed" }` | `200 PlanView` (claim prolongé) ; même état rejoué : `200` (§8.7) | `400 invalid_body` (action d'agent, `n` hors plage), `404`, `409 plan_claim_lost`, `409 plan_phase_mismatch` (action non prête), `409 plan_not_executing` (`executing` après `expiresAt` ou arrêt), `409 action_state_conflict`, `409 action_output_missing` (`done` sans sortie enregistrée, §8.5) |
| `POST /plans/:planId/stop` | U-prop | `{}` | `200 PlanView` (plan `stopped`, §8.6) ; rejeu : `200` | `404`, `409 plan_not_executing` (statut ∉ `accepted`, `executing`, `stopped`) ; un plan `proposed` se refuse par `decision` |
| `POST /inbox` (existante) | U-prop | `{ "t": "plan_result", "id": "plan:<planId>:<k>", "planId", "phase": <k>, "value": "gcm1:…" }` | `201` / `200` doublon (05 §6.2) | existants + `409 plan_not_executing`, `409 plan_phase_mismatch`, `404 not_found` |

`PlanView` = `{ planId, sessionId, toolCallId, status, actionCount, createdAt, expiresAt, decidedAt,
devicePhases, agentPhases, claim: { deviceId, phase, expiresAt } | null, actions: [{ n, executor, after,
level, ready, state, output }], agentResults: [{ phase, value }] }` (dates ISO 8601 ; `executor` ∈
`device`, `agent` ; `devicePhases` / `agentPhases` = phases closes ; `output` = sortie enregistrée,
§8.5, `null` après la clôture du plan, PC56) ; **aucun contenu en clair** : le plan se lit dans
`pendingToolCall` (§3.4), les `agentResults` sont chiffrés (§9). `deviceId` : identifiant 00 §3.2 tiré
par l'appareil, opaque pour l'API. Effets de la décision, dans une transaction : `updateMany`
conditionné à `status = proposed`, `decidedAt`, états `skipped` (avec la cascade), dépôt de
`decision:<planId>` ; `reject`, ou `accept` avec une action d'agent prête, passe la conversation
`queued` et réveille le runtime. `failed` en `progress` passe en `skipped` les seules dépendantes
transitives de l'action (PC54) ; le statut du plan est recalculé (§7.1). Débit : compteur des routes utilisateur du mode runtime
(120 / min, 09 §4.1).

**Autres routes utilisateur**

| Méthode et chemin | Auth | Changement |
|---|---|---|
| `POST /api/orgs/:orgId/ai/runtime/delegations` | U | corps : `mandateVersion?` (`1` si absent, ou `2`), `mode?` et `ownerRsaSpkiHex?` (obligatoires si `2`, interdits si `1`) ; `mode = auto` → `isFeatureAllowed(autonomous_mode)` sinon `403 feature_not_allowed` ; forme invalide → `400 delegation_invalid` (03 §4.1) |
| `GET …/delegations/current`, `DelegationView` | U | ajoute `mandateVersion`, `mode` |
| `GET …/delegations/:delegationId/mandate` | U | ajoute `version`, `mode` (`plan` pour v1), `ownerRsaSpkiHex` (`null` pour v1) |
| `POST /api/threads/:threadId/key-envelope` | U (créateur) | **nouvelle** (C1 §2.6) : `{ "ctx": "thread:<threadId>", "version": 1, "commitment", "signature" }` (`b64` canoniques) ; seulement si l'appelant est le `creatorId` d'une `ThreadKey` du salon et que l'enveloppe est vide ; `200 { threadId, updated }`, même enveloppe : `updated: 0` ; `403 forbidden`, `404 not_found`, `409 envelope_exists`. Sert aussi aux humains (`OrgLayout.vue:349`) |
| Routes de création (catégorie, salon, dossier, fichier texte) | U | en-tête facultatif `X-Synco-Plan: <planId>/<n>` : enregistrement de la sortie de l'action pour la durée du plan (§8.5, PC56) ; aucun refus nouveau, aucun droit changé |

### 12.2 Canal du runtime (`/api/runtime/v1`, ajouts à 04 §4)

| Méthode et chemin | Auth | Corps | Succès | Refus |
|---|---|---|---|---|
| `POST /conversations/:sessionId/plans` | S+A, bail | `{ leaseEpoch, baseRev, messages, title?, pendingToolCall, consumedInbox, events?, plan: { planId, toolCallId, actionCount, createdAt, expiresAt, actions: [{ n, executor, after }], serverDigests: [{ n, sha256Hex }] } }` | `201 { rev, planId }` : transcript écrit **et** ligne créée dans une transaction, statut `awaiting_confirmation` | `400 invalid_body` (forme ; `pendingToolCall.name ≠ propose_actions` ; `planId` ou `toolCallId` ≠ ceux de `pendingToolCall` ; `actionCount` hors 1..20 ; `actions` qui ne couvre pas exactement `1..actionCount` ; `after` non conforme (entiers distincts `< n`) ; `n` de `serverDigests` hors plage, en double ou d'exécutant `device` ; `expiresAt` hors `]maintenant, maintenant + confirmationTimeoutSecs + 300]`), `409 plan_exists`, `409 rev_conflict`, `409 lease_conflict` |
| `GET /conversations/:sessionId/plans/:planId` | S+A | — | `200 PlanView` | `404 not_found`, `403 out_of_scope` |
| `POST /conversations/:sessionId/plans/:planId/agent-result` | S+A, bail | `{ leaseEpoch, baseRev, phase, value: "gcm1:…" }` | `200 { rev, status }` : valeur rangée, conversation `awaiting_confirmation`, push si des actions d'appareil sont prêtes (§8.3) | `400 invalid_body`, `404 not_found`, `409 plan_phase_mismatch` (`phase` ≠ phases d'agent closes + 1, action d'agent prête ou `executing`), `409 plan_not_executing` (plan terminé : le worker ferme `propose_actions`), `409 rev_conflict`, `409 lease_conflict` |
| `POST /conversations/:sessionId/tools/:name/execute` | S+A | `{ leaseEpoch, args?, argsRefs?, refs?, plan?: { planId, n } }` | inchangé ; avec `plan`, l'état de l'action suit et sa sortie est enregistrée (§8.3, §8.5) | + `403 action_not_accepted`, `409 action_state_conflict`, `409 plan_phase_mismatch`, `409 plan_not_executing` |
| `POST /e2ee/threads` | S+A | + `plan?: { planId, n }` | inchangé ; sortie enregistrée (§8.5) | + `403 autonomy_required`, `403 feature_not_allowed`, `403 action_not_accepted`, `409 action_state_conflict`, `409 plan_phase_mismatch` |
| `GET /delegations` | S | — | ajoute `mandateVersion`, `mode`, `ownerRsaSpkiHex` | — |
| Routes `rt1` et L03f | | | conditions du §10.4 | |

Flux (04 §6) : `delegation.revoked.reason` peut valoir `autonomy_withdrawn` ; `conversation.wake.reason`
`decision` couvre `plan_decision` (dont l'arrêt) et `plan_result`.

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
`AI_AUTONOMY_WITHDRAWN` (07 §7). Une ligne `AiActionPlanAction` par action porte l'exécutant, `after`, l'état et la
sortie enregistrée (identifiants, effacée à la clôture, §8.5) ; `AiActionPlan` porte les compteurs de
phases, le claim et les résultats de phase d'agent (chiffrés). **Aucun contenu en clair** : ni nom, ni argument, ni résumé.

## 14. Codes d'erreur

| Code | Où | Sens |
|---|---|---|
| `plan_invalid` | worker (résultat d'outil), appareil (`reason`), API `400` (forme) | Plan hors des règles du §5 |
| `plan_rejected` | résultat de `propose_actions` | Refus de l'utilisateur ou plan invalide à l'appareil (`reason`) |
| `plan_limit` | `lastErrorCode` (`failed`) | Plus de 3 plans consécutifs dans un tour |
| `plan_exists` | API 409 | `planId` déjà utilisé |
| `plan_not_pending` | API 409 | Décision sur un plan déjà décidé autrement ou expiré |
| `plan_claimed` / `plan_not_claimable` / `plan_claim_lost` | API 409 | Phase réclamée par un autre appareil / statut ou expiration ne permettant pas le claim / claim expiré ou repris |
| `plan_not_executing` | API 409 | Plan terminé, arrêté ou expiré : aucune action ne démarre plus |
| `plan_phase_mismatch` | API 409 | Action non prête, mauvais exécutant, numéro de phase inattendu, ou phase close alors qu'il reste une action prête (§8, §9) |
| `action_state_conflict` | API 409 | Transition d'action invalide (dont seconde exécution) |
| `action_output_missing` | API 409 | `done` d'une action d'appareil sans sortie enregistrée par la route de création (§8.5) |
| `action_not_accepted` | API 403 | Verrou du §8.4 (action non acceptée, condensat ou `refs` différents) |
| `autonomy_required` | API 403, superviseur | Délégation ou mandat vérifié non `auto` |
| `feature_not_allowed` | API 403 | Politique d'org (ou opt-in absent) |
| `feature_reserved` | API 409 | Fonctionnalité réservée (§11.1) |
| `autonomy_withdrawn` | `revokedReason`, `delegation.revoked.reason` | Retrait du mode autonome (§11.4) |

## 15. Questions tranchées (PC44 à PC48, 2026-11-21)

L00f avait laissé cinq questions que ni C1 ni les PC ne tranchaient. L'utilisateur les a tranchées
après la livraison ; le texte qui en dépendait (« provisoire ») est réécrit.

| Question | Décision | Où |
|---|---|---|
| **QP1** — Ordre d'exécution d'un plan mixte (appareil + agent) | **PC44 : ordre libre**, contraire de la recommandation « appareil d'abord ». Phases alternées selon le graphe de dépendances ; une action d'appareil peut dépendre d'une action d'agent ; chaque phase d'appareil se clôt par un `plan_result:k` partiel ; l'agent reprend après chaque phase et signale la suivante (`plan_agent_result:k`, push) ; l'app doit être ouverte pour chaque phase d'appareil, le plan attend sinon, `expiresAt` vaut pour le plan entier ; une phase = un seul appareil. L'arrêt total sur échec est remplacé par PC54, les phases précalculées par des phases dynamiques (PC58) | §1, §5, §7, §8.1 à §8.3, §9, §12 |
| **QP2** — `serverDigests` et `argsRefs` | **PC47 : recommandation adoptée.** Condensat de `JCS({tool, args, argsRefs})`, `argsRefs` omis s'il est absent ; l'appel porte `args` non résolus et `refs` résolues ; l'API vérifie le condensat puis chaque `ref` contre la sortie enregistrée de l'action visée. Pour une action d'appareil, l'API connaît la sortie parce qu'elle a créé l'objet (en-tête `X-Synco-Plan`), sans rien lire de chiffré ; fuite résiduelle assumée : le lien objet ↔ action de plan | §8.4, §8.5 |
| **QP3** — Mécanique de la pause au retrait (PC40) | **PC45 : recommandation adoptée** | §11.4, 08 §2.2 |
| **QP4** — Clé RSA servie du propriétaire et `ownerRsaSpkiHex` | **PC46 : recommandation adoptée**, l'empreinte du mandat v2 prime | §10.3, 03 §4.1 |
| **QP5** — Détails fixés par analogie | **PC48 : ratifiés tels quels**, sauf `AiFeaturePolicyEvent` : **conservé 1 an, purge bornée** (RGPD), et non plus sans purge | §3.3, §9, §11, §14, 07 §10 |

### Second amendement (PC54 à PC58, 2026-11-21)

| Décision | Contenu | Où |
|---|---|---|
| **PC54** — Échec | Seules les dépendantes transitives (`after`, qui couvre `argsRefs`) de l'action en échec passent `skipped` ; les actions indépendantes continuent, sur les deux exécutants. Remplace l'arrêt total du premier amendement | §7.1, §7.3 |
| **PC55** — Message pendant un plan | Après l'acceptation, un message n'arrête pas le plan ; il est traité **après** la clôture de `propose_actions` (pas à la phase d'agent suivante). Arrêt explicite : route `POST …/stop`, statut `stopped`, élément `plan_decision` `stop` | §7.1, §8.6, §9, §12.1 |
| **PC56** — Lien objet ↔ plan | La sortie enregistrée (`X-Synco-Plan`) n'existe que le temps du plan, effacée à la clôture, purge bornée de rattrapage ; inscrite au catalogue RGPD | §8.5, 07 §9, §11 |
| **PC57** — Mode autonome | Absence de recontrôle API des `refs` du `thread.create` autonome acceptée | §8.4, §10.6 |
| **PC58** — Graphe et parallélisme | `after` = `needs` ; `groups` de présentation ; actions prêtes exécutées en parallèle (concurrence 4, maximum 8, des deux côtés) ; `429` : 3 nouveaux essais ; consigne au modèle ; présentation en graphe pour L12 ; `category.create` et `categoryId` pour le cas « catégories puis salons ». **Ajustement de PC44** : phases dynamiques (une séance d'exécution par exécutant, qui peuvent se chevaucher) au lieu de phases précalculées strictement alternées, qui sérialisaient des branches indépendantes | §3, §4, §8.1 à §8.3, §8.7, §17 |

**Risques acceptés** : (1) références du `thread.create` autonome non recontrôlées par l'API (PC57,
§10.6) ; (2) pendant un plan, l'API sait quel objet créé correspond à quelle action (métadonnée sans
contenu, effacée à la clôture, PC47, PC56) ; (3) condensat d'une action refusée devinable si ses
arguments ont peu d'entropie (C1 §2.3).

## 16. Répartition par lot

| Lot | Prend dans ce document |
|---|---|
| L01c | 03 §4.1 (octets, lecture v1/v2), §3.3 (JCS, AAD), §8.1 (niveaux, actions prêtes), §9 (AAD des résultats de phase), fonctions pures TS et Rust, vecteurs `mandate-v2.json` et `action-plan.json` rejoués des deux côtés |
| L03g | §7, §8.1 (actions prêtes), §8.4 à §8.7, §9, §10.4, §12.1, §12.2, 07 §3, §5, §10 (`AiActionPlan`) ; vecteurs : condensats, `executeCases`, `runCases`, `categoryPlan`, `validationCases` pour la forme vue par l'API |
| L03h | §11, §12.3, 07 §10 (politiques, purge du journal), 03 §8.1 (`autonomy_withdrawn`) |
| L08d | §2, §3 (dont la description de l'outil), §5, §7.3, §8.1, §8.3, §8.6, §8.7, §10.3 ; `propose_actions`, reprise après chaque phase, exécution parallèle, `agent-result`, `refs`, `created_key` / `repose` conditionnés, épingle du mandat v2 |
| L10 à L13 | §4 à §8.2, §8.6, §8.7, §10.2, §11.3, §17 (graphe du plan, arrêt), écrans de C1 §3 et §5.5 |

## 17. Présentation du plan (L12, L13 ; PC58)

Même vue pour la **validation** (avant décision) et le **suivi** (pendant et après l'exécution), à la
manière des jobs de GitHub Actions :

- **Graphe par niveaux** : une colonne par niveau (§8.1), de gauche à droite ; chaque action est une
  carte ; un lien relie chaque action à celles de son `after`. Les cartes d'un même `group` sont
  encadrées ensemble, avec le `label` du groupe (« Catégorie Finance et ses salons »).
- **Carte d'action** : intitulé généré par l'app à partir du `kind` et des `args` (« Créer le salon
  #budget dans Finance »), jamais à partir du texte du modèle ; exécutant (« sur votre appareil » ou
  « par Synco AI ») ; ligne « Dépend de : … » qui nomme les actions requises ; état par une icône et une
  couleur : en attente (gris), en cours (animation), fait (vert), échec (rouge, avec la raison courte),
  ignorée (barrée, avec la cause : décochée, dépendance en échec, plan arrêté ou expiré). Un clic ouvre
  le détail : ce que fait l'action, ses arguments lisibles, de quoi elle dépend et qui dépend d'elle.
- **Validation** : cases à cocher sur les cartes ; décocher montre aussitôt la cascade sur le graphe
  (cartes qui passent « ignorée ») avant l'envoi ; règles des actions sensibles inchangées (C1 §3) ;
  le `summary` du modèle est affiché à part, en citation.
- **Suivi** : bouton « Arrêter le plan » (confirmation par la fenêtre de l'app, jamais `confirm()`),
  bandeau « en cours sur votre autre appareil » si un autre appareil tient le claim, bandeau « Votre
  message sera traité à la fin du plan » (§8.6), compteur « 7 / 12 faites ».
- **Mobile et écrans étroits** : repli en **liste** ordonnée par niveau puis par `n`, avec des en-têtes
  de niveau (« Étape 1 : en parallèle », …) et de groupe, la ligne « Dépend de » sur chaque élément, et
  les mêmes états. Aucune rangée de boutons par action (C1 §5.5) : le détail s'ouvre au toucher.

