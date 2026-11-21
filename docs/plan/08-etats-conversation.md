# 08 — Machine à états d'une conversation

Complète `02_architecture.md §3`. Les états sont stockés dans `AiChatSession.status` (chaîne, 07 §4),
le régime dans `AiChatSession.regime`. Conventions : [00 §3](00-vue-ensemble.md).

## 1. États

| État | Régime | Sens | Worker |
|---|---|---|---|
| `idle` | tous | Rien à faire ; dernier tour terminé | aucun |
| `awaiting_confirmation` | `server` (historique), `runtime` | Un outil attend la décision de l'utilisateur | aucun (le worker s'arrête) |
| `awaiting_client_tool` | `server` (historique) | Outil `client` à exécuter par le navigateur (`aiTurnRunner.ts:168`) | — |
| `queued` | `runtime` | Du travail attend un worker (message, décision, clé arrivée, reprise) | à lancer |
| `running` | `runtime` | Un worker détient le bail et travaille | 1 |
| `awaiting_user` | `runtime` | Outil interactif (`ask_question`, `request_image_upload`) | aucun |
| `awaiting_key` | `runtime` | Clé de l'org absente de la délégation (03 §11) | aucun |
| `failed` | `runtime` | Échec ; `lastErrorCode` dit pourquoi (§6) | aucun |
| `cancelled` | `runtime` | Annulé par l'utilisateur | aucun |

Le régime `client` n'utilise pas ces états (la boucle tourne dans le navigateur ; statut `idle`).

« Local » dans `02_architecture.md §3` = régime `client` ou `server`.

```
                 switch-to-runtime
 (client|server) ────────────────▶ idle ◀──────────────────────────────────────────┐
        ▲                          │ message (boîte)                                │ tour terminé
        │ switch-to-local,         ▼                                                │
        │ révocation        ┌──▶ queued ──(bail pris, worker lancé)──▶ running ─────┤
        │ (depuis tout      │      ▲  ▲                                 │ │ │ │      │
        │  état runtime)    │      │  └──── bail expiré (plantage) ─────┘ │ │ │      │
        │                   │      │                                      │ │ │      │
        │   confirm/answer/ │      ├── awaiting_confirmation ◀────────────┘ │ │      │
        │   upload/message  │      ├── awaiting_user ◀──────────────────────┘ │      │
        │   clé arrivée     │      └── awaiting_key ◀─────────────────────────┘      │
        │                   │                                                         │
        │                   └──── message ─── failed ◀── erreur ── running            │
        │                   └──── message ─── cancelled ◀── cancel ── (tout état actif)
```

## 2. Transitions

| De | Évènement | Vers | Déclenché par | Écrit par |
|---|---|---|---|---|
| `client`/`server` (tout statut sauf `awaiting_*` du régime `server`) | `switch-to-runtime` (04 §5) | `idle`, ou `queued` si la requête apporte un message | utilisateur | API |
| `idle`, `failed`, `cancelled` | élément `message` déposé (05 §6.2) | `queued` | utilisateur (WS → runtime → API, ou API directe) | API, au dépôt |
| `queued` | bail pris (07 §4.1) | `running` | superviseur | runtime |
| `running` | tour terminé, boîte vide | `idle` | worker | runtime |
| `running` | tour terminé, boîte non vide | `running` (tour suivant, même worker) | worker | runtime |
| `running` | outil `mutating` avec politique `ask` (D5), ou outil `client` mutant | `awaiting_confirmation` | worker | runtime |
| `running` | outil `interactive` | `awaiting_user` | worker | runtime |
| `running` | clé manquante et indispensable | `awaiting_key` | worker | runtime |
| `awaiting_confirmation` | `confirm` | `queued` | utilisateur | API, au dépôt |
| `running` | outil `propose_actions` (plan d'action, L00f) : `POST …/plans` | `awaiting_confirmation` (`pendingToolCall` = `propose_actions`) | worker | runtime |
| `awaiting_confirmation` (plan) | `plan_decision` `reject` (route de décision) | `queued` ; `propose_actions` clos par `{"error":"plan_rejected"}` | utilisateur | API, à la décision |
| `awaiting_confirmation` (plan) | `plan_decision` `accept` | `queued` s'il existe une action d'agent prête, sinon inchangé (l'appareil exécute) (PC44, PC58) | utilisateur | API |
| `awaiting_confirmation` (plan accepté) | `plan_result:<k>` (fin d'une phase d'appareil) | `queued` si une action d'agent est devenue prête ou si le plan est fini ; sinon inchangé (12 §8.2) | appareil | API, au dépôt |
| `running` (plan accepté) | `POST …/plans/:planId/agent-result` (plus aucune action d'agent prête, plan non fini) | `awaiting_confirmation` (même `pendingToolCall`), push si des actions d'appareil attendent (12 §8.3) | worker | API |
| `awaiting_confirmation`, `running` (plan accepté) | `message` (PC55) | **inchangé** : le message attend dans la boîte et sera traité au tour qui suit la clôture du plan (12 §8.6) | utilisateur | API |
| `awaiting_confirmation` (plan accepté) | `plan_decision` `stop` (route « Arrêter le plan », PC55) | `queued` ; le worker ferme `propose_actions` avec le bilan (`stopped`), puis traite les messages en attente | utilisateur | API, à l'arrêt |
| `awaiting_confirmation` (plan accepté) | `expiresAt` (12 §7.1) | `queued` ; le worker ferme `propose_actions` avec le bilan | — | API (tâche périodique) |
| `awaiting_user` | `answer` ou `upload` | `queued` | utilisateur | API, au dépôt |
| `awaiting_confirmation` (hors plan accepté), `awaiting_user` | `message` | `queued` ; l'outil en attente est clos par le worker avec le résultat `{"error":"superseded_by_user_message"}` | utilisateur | API puis runtime |
| `awaiting_key` | entrée ajoutée pour `awaitingKey` (03 §11) | `queued` | client (P11) | API, à l'ajout de l'entrée |
| `awaiting_key` | `message` | `queued` ; l'outil est clos par `{"error":"key_unavailable"}` | utilisateur | API puis runtime |
| `running` | erreur non récupérable (§6) | `failed` | worker | runtime |
| `running` | bail expiré sans renouvellement (plantage, coupure) | `queued` | — (constaté à la prise de bail suivante) | runtime (relance) |
| `queued`, `awaiting_*` | `cancel` | `cancelled` | utilisateur | API, au dépôt (aucun worker) |
| `running` | `cancel` | `cancelled` | utilisateur | runtime (le worker interrompt le flux du fournisseur, enregistre, quitte) |
| `awaiting_confirmation`, `awaiting_user` | délai dépassé (09 §3) | `failed` (`confirmation_timeout`) | — | API (tâche périodique) |
| `awaiting_key` | délai dépassé (09 §3) | `failed` (`key_timeout`) | — | API (tâche périodique) |
| tout état `runtime` | `switch-to-local`, délégation révoquée ou expirée, désappairage, départ de l'org | régime `client`, `idle` | utilisateur, admin, API | API |

Règles communes :

- Chaque transition écrite par l'API ou le runtime ajoute une ligne `AiChatSessionEvent` (07 §5) et
  envoie l'évènement `status` aux clients connectés (via le worker si `running`, sinon l'API émet
  `ai:session-status` sur le socket de l'utilisateur).
- Toute transition vers `queued` écrite par l'API notifie le runtime (`conversation.wake`, 04 §6).
- Toute sortie du régime `runtime` (dernière ligne) **clôt le bail** : l'API incrémente `leaseEpoch`
  et vide `leaseHolder`, ce qui interdit toute écriture à un worker encore vivant (07 §4.3) ; elle
  révoque l'autorisation (`conversation.revoked`). Si un outil était `executing`, il est marqué
  `error` avec `unknown_outcome` par le client à la prochaine ouverture (même règle qu'en §5).
- Notifications push (07 §7) : `AI_TURN_DONE` (→ `idle` après un tour), `AI_AWAITING_CONFIRMATION`,
  `AI_AWAITING_USER`, `AI_AWAITING_KEY`, `AI_FAILED` ; jamais pour `cancelled` ni pour une transition
  déclenchée par l'utilisateur lui-même.

`AiChatSession.awaitingKey` (07 §4) vaut `"<kind>:<ref>"` tant que l'état est `awaiting_key`, sinon
`null` ; c'est lui que l'API compare aux entrées ajoutées.

### 2.1 Réalisation par l'API (révisé après la vague B, 2026-11-19)

- **`awaitingKey` transmis par le runtime** : le worker l'envoie dans `PUT …/transcript` ou
  `POST …/status` (`"thread:<id>"` ou `"space:<id>"`), obligatoire avec `awaiting_key`, interdit
  sinon (04 §4.2). L'API le remet à `null` à toute autre transition. La sortie de `awaiting_key` est
  faite par l'API à l'ajout de l'entrée attendue, que ce soit par un **dépôt** de délégation ou par
  un **ajout** d'entrées (client ou runtime), puis `conversation.wake` `reason: "keys"`
  (`wakeAwaitingKey`, `synco_api/src/services/aiRuntime/delegationService.ts:307-343`).
- **Transitions au dépôt** (`inboxTransition`, `synco_api/src/services/aiRuntime/conversationState.ts:49-63`) :
  `message` depuis `idle`, `failed`, `cancelled`, `awaiting_confirmation`, `awaiting_user`,
  `awaiting_key` → `queued` ; `confirm` depuis `awaiting_confirmation` → `queued` ; `answer` /
  `upload` depuis `awaiting_user` → `queued` ; `cancel` depuis `queued` ou `awaiting_*` →
  `cancelled`. Tout autre cas : aucun changement (le worker en cours, ou le suivant, consomme
  l'élément ; hors d'état → `stale_decision`). Écriture par `updateMany` conditionné au statut lu,
  trois essais ; `lastErrorCode` et `awaitingKey` remis à `null`.
- **Transitions après l'écriture du worker** (`afterWorkerWrite`,
  `synco_api/src/services/aiRuntime/conversationLease.ts:228-273`) : un élément déposé pendant
  `running` ne peut pas faire changer l'état au dépôt. Après chaque `PUT …/transcript` ou
  `POST …/status`, l'API journalise la transition du worker, puis applique la même table aux
  éléments **restés non consommés**, à partir du **nouvel** état, dans l'ordre de dépôt : le premier
  qui produit une transition l'emporte. Ainsi une fin de tour `idle` avec un message non consommé
  repasse aussitôt `queued`, une attente avec sa décision déjà déposée aussi, et le runtime est
  réveillé (`inbox` ou `decision`).
- **Filet** : `GET /conversations?state=pending` liste aussi les conversations `idle` qui ont un
  élément `message` non consommé (04 §4.1).
- **Bascule** : `switch-to-runtime` aboutit toujours à `idle` (la requête n'apporte pas de message ;
  le premier message passe par la boîte).
- **Push** : pour les transitions qu'il écrit, le runtime décide lui-même et appelle
  `POST …/push` (04 §4.2) ; l'API n'envoie elle-même que les push des transitions qu'elle écrit
  (délais dépassés : `AI_FAILED`). Correspondance de l'API (`pushForStatus`,
  `conversationState.ts:70-87`) : `idle` → `AI_TURN_DONE` si `lastErrorCode` est `null` ou
  `step_limit` ; `awaiting_confirmation`, `awaiting_user`, `awaiting_key`, `failed` → le type
  correspondant.
- **Socket** : chaque transition écrite par l'API ou par le worker émet `ai:session-status` vers le
  propriétaire.

### 2.2 Plan d'action (ajouté par L00f, 2026-11-21 ; 12)

- Le plan **généralise** `awaiting_confirmation` : même état, même push `AI_AWAITING_CONFIRMATION`, même
  délai `confirmationTimeoutSecs` (expiration : 12 §7.1). L'état du
  plan lui-même (`proposed` … `done`) vit dans `AiActionPlan` (12 §7) et s'affiche dans la carte (L12).
- Un `message` **avant la décision** (plan `proposed`) : `queued`, `propose_actions` clos par
  `{"error":"superseded_by_user_message"}`, plan `rejected`. **Après l'acceptation** (PC55) : le message
  n'arrête pas le plan ; il est traité au tour qui suit la clôture de `propose_actions` (le `tool_result`
  doit précéder tout nouveau message de l'utilisateur), pas à la phase d'agent suivante. Seule la route
  « Arrêter le plan » arrête un plan accepté (plan `stopped`, 12 §8.6).
- **Graphe et phases dynamiques (PC44, PC58 ; 12 §8.1)** : chaque exécutant exécute en parallèle les
  actions prêtes qui lui reviennent ; l'appareil et l'agent peuvent avancer en même temps sur des
  branches indépendantes. La conversation est `queued` / `running` tant que l'agent a du travail, sinon
  `awaiting_confirmation` (l'app doit être ouverte pour les actions d'appareil ; sans appareil, elles
  attendent jusqu'à `expiresAt`). L'appareil peut exécuter pendant que la conversation est `running`.
- Reprise du worker (12 §8.3) : il lit les `plan_result:<k>` reçus, exécute les actions d'agent prêtes,
  puis soit rend la main (`agent-result`, `awaiting_confirmation`), soit, quand le plan est fini, arrêté
  ou expiré, ferme `propose_actions` par un `tool_result` portant les états et les sorties ; le tour
  continue (`running`) et traite les messages arrivés pendant le plan.
- Échec (PC54) : une action en échec n'ignore que ses dépendantes ; le plan continue.
- Expiration (12 §7.1) : elle vaut pour le plan entier, aucune action ne démarre après `expiresAt`. Plan
  jamais décidé : `failed` `confirmation_timeout` (C1). Plan accepté : `queued`, clôture avec le bilan.
- Une action exécutée par l'agent suit §5 : `executing` jamais relancé, `unknown_outcome`.
- Au plus 3 plans consécutifs par tour, sinon `failed` `plan_limit`.
- **Retrait du mode autonome** (PC40, 12 §11.4) : les conversations restent en régime `runtime`, en
  pause, et reprennent en mode plan au prochain dépôt de délégation ; mécanique (PC45) : autorisations
  de session conservées, `queued` / `running` → `awaiting_key`, `awaitingKey = "delegation:<runtimeId>"`, sortie vers `queued`
  au dépôt, `key_timeout` au-delà de `keyTimeoutSecs`. C'est la seule révocation qui ne fait pas sortir
  du régime `runtime` (ligne « tout état `runtime` » ci-dessus).

## 3. Sortie du mode runtime

`switch-to-local` (utilisateur) et révocations (délégation, désappairage, départ) :

1. régime `client`, statut `idle`, `runtimeId = null`, bail clos (§2) ; l'API vide aussi
   `pendingToolCall` et `awaitingKey`, et pose `lastErrorCode = "revoked"` sauf pour une sortie
   demandée par l'utilisateur (`switched_to_local`) ou une suppression (`session_deleted`)
   (révisé après la vague B, 2026-11-19 ; `exitRuntimeRegime`,
   `synco_api/src/services/aiRuntime/conversationLifecycle.ts:83-150`) ;
2. autorisation révoquée, entrée `conv` supprimée de la délégation (`delegation.entries_removed`
   au runtime, après `conversation.revoked`) ;
3. le schéma reste `conv-gcm1-v1` : la conversation se poursuit en local avec la même `CK`
   (fournisseur piloté par le navigateur ; pas de régime `server`, 03 §6.3) ;
4. les éléments non consommés de la boîte restent visibles dans l'historique comme « non traités »
   (le client les affiche et peut les renvoyer à sa boucle locale).

## 4. Tours, file et annulation

- **Un tour** = traitement d'un ou plusieurs éléments de la boîte jusqu'à une réponse finale du
  modèle, une attente (`awaiting_*`), une erreur ou un plafond.
- **Messages pendant un tour** : le worker relit la boîte avant chaque appel au fournisseur ; les
  nouveaux messages sont ajoutés à l'historique à cet endroit (« pris en compte à l'étape suivante »).
- **Annulation pendant un tour** : le worker interrompt l'appel en cours au fournisseur, n'exécute
  plus aucun outil, marque les outils `pending` comme `rejected`, enregistre (`cancelled`), quitte.
  Un outil déjà `executing` va jusqu'au bout (on n'interrompt pas un effet de bord à moitié) puis son
  résultat est enregistré.
- **Attentes** : le worker enregistre l'état puis **quitte** (P3) ; la décision relancera un worker
  (`queued`). D'où le changement d'`epoch` dans l'exemple de 05 §10.
- **Annulation hors tour** (révisé après la vague B, 2026-11-19) : un `cancel` déposé sur une
  conversation `queued` ou `awaiting_*` la fait passer `cancelled` **au dépôt**, sans consommer les
  éléments de la boîte : c'est le worker suivant qui les consomme (et décide de leur sort) ; un dépôt
  par l'API ne réveille pas le runtime quand la conversation est désormais `cancelled`. Un `cancel`
  déposé pendant `running` ne change rien au dépôt : le worker le lit dans la boîte (règle
  ci-dessus) ; s'il reste non consommé quand le worker écrit une attente, l'API applique
  `cancelled` après cette écriture (§2.1).

## 5. Plantage et reprise

**Écriture anticipée des outils** : avant d'exécuter un outil `mutating` (serveur ou E2EE), le worker
enregistre l'historique avec `toolCalls[i].status = "executing"` (`PUT …/transcript`). Il n'exécute
l'outil qu'après la confirmation de cette écriture. Après l'exécution, il enregistre `done` (ou
`error`) et le message `tool` avec le résultat chiffré.

**Reprise** (nouveau worker après un bail expiré, un redémarrage du runtime, un `kill -9`) :

1. Le worker relit l'historique enregistré (dernière révision) : c'est le point de reprise ; ce qui
   n'était pas enregistré (texte en cours de génération) est perdu et régénéré.
2. Tout appel d'outil `mutating` au statut `executing` n'est **jamais** relancé : il passe en `error`
   et reçoit le message `tool` au résultat chiffré
   `{"error":"unknown_outcome","note":"L'exécution de cet outil a été interrompue : son résultat est inconnu. Vérifie l'état avant de réessayer."}`,
   avec un `AiChatSessionEvent` `tool_unknown_outcome` (révisé après L07 : `code` = **nom de l'outil** ;
   `lease_lost` n'a pas de `code`). Le modèle décide de la suite. Un appel mutant `accepted` qui ne
   correspond pas au `pendingToolCall` déchiffré n'est pas relancé : clos `tool_call_unverified`
   (06 §9). Même issue inconnue (`unknown_outcome`) pour une erreur de transport **après** l'envoi
   d'une action mutante ; les refus locaux du relais, émis avant tout envoi, sont un échec simple.
3. Un outil **non mutant** au statut `executing` est relancé (lecture sans effet de bord).
4. Les outils `pending` restent en attente de leur décision (état `awaiting_confirmation`).
5. Garde-fou : 3 plantages du worker pour la même conversation en 10 minutes → `failed`
   (`worker_crash_loop`), sans nouvelle relance automatique.

Qui relance : le superviseur, au démarrage et après chaque reconnexion du flux de notifications,
interroge `GET /api/runtime/v1/conversations?state=pending` (04 §4.1), qui inclut les conversations
`running` dont le bail a expiré (et, depuis la vague B, les `idle` avec un message non consommé) ;
il prend le bail (`queued` implicite) puis lance le worker.

Journal (révisé après L03c, 2026-11-20 ; Q15 = A) : le worker écrit lui-même l'`AiChatSessionEvent`
`tool_unknown_outcome` de l'étape 2 (et `lease_lost`) par le champ facultatif `events: [{ type, code? }]`
de `PUT …/transcript` et `POST …/status` (04 §4.2, 07 §5), dans la transaction de l'écriture qui les
porte. Un worker qui a perdu le bail ne peut pas écrire son propre `lease_lost` : le worker suivant le
constate et l'écrit.

## 6. Codes d'erreur (`lastErrorCode`, évènement `error`)

| Code | État atteint | Sens |
|---|---|---|
| `provider_error` | `failed` | Le fournisseur LLM a échoué après 3 tentatives (backoff 1 s, 4 s, 16 s) |
| `provider_not_configured` | `failed` | **Ajouté par L03d (2026-11-21, Q30 / PC16)** à `CONVERSATION_ERROR_CODES` (`lastErrorCode`, `error` de `transcript` et de `status`) : fournisseur non activé pour l'org, sans clé, ou passerelle refusée. `provider_error` reste l'échec d'un fournisseur configuré. **Le runtime n'écrit pas encore ce code** : il écrit `provider_error` dans ces cas (`crates/supervisor/src/workers.rs:130`) ; adoption **ouverte** |
| `provider_auth` | `failed` | Clé ou ticket du fournisseur refusé |
| `budget_exceeded` | `failed` | `maxTokensPerConversation` atteint, ou quota de tokens du mandataire (`proxy_token_budget`, 10 §4) — révisé après L07 |
| `step_limit` | `idle` | `maxStepsPerTurn` ou `maxTokensPerTurn` atteint, ou quota d'appels du mandataire (`proxy_call_budget`, 10 §4) : le tour s'arrête, l'utilisateur peut relancer (« continue ») — révisé après L07 |
| `turn_timeout` | `failed` | `maxTurnDurationSecs` dépassé |
| `confirmation_timeout` | `failed` | Décision attendue trop longtemps (09 §3) |
| `key_timeout` | `failed` | Clé attendue trop longtemps (09 §3) |
| `worker_crash_loop` | `failed` | §5.5 |
| `plan_limit` | `failed` | Plus de 3 plans d'action consécutifs dans un tour (L00f, 12 §7.3) |
| `tool_failed` | (pas de changement) | Un outil a échoué ; son résultat d'erreur est donné au modèle |
| `revoked` | régime `client` | Délégation, autorisation ou runtime révoqués |
| `internal` | `failed` | Erreur interne |

## 7. Correspondance pour l'affichage (app)

| État | Dock et vue (L12, L13) |
|---|---|
| `queued` | « En attente » (et « runtime injoignable » si le runtime est hors ligne) |
| `running` | « En cours » + flux direct |
| `awaiting_confirmation` | « Confirmation demandée » + `PendingActionBar` |
| `awaiting_confirmation` avec `propose_actions` | « N actions à valider » + carte du plan (L12, L13 ; C1 §3) ; « en cours sur votre autre appareil » si un autre appareil a le claim |
| `awaiting_user` | « Réponse attendue » |
| `awaiting_key` | « Ouvrez Synco pour donner accès » |
| `idle` | « Terminé » |
| `failed` | « Échec » + message selon le code |
| `cancelled` | « Annulé » |
