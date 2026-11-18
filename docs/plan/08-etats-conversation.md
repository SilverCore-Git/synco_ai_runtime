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
| `awaiting_user` | `answer` ou `upload` | `queued` | utilisateur | API, au dépôt |
| `awaiting_confirmation`, `awaiting_user` | `message` | `queued` ; l'outil en attente est clos par le worker avec le résultat `{"error":"superseded_by_user_message"}` | utilisateur | API puis runtime |
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

## 3. Sortie du mode runtime

`switch-to-local` (utilisateur) et révocations (délégation, désappairage, départ) :

1. régime `client`, statut `idle`, `runtimeId = null`, bail clos (§2) ;
2. autorisation révoquée, entrée `conv` supprimée de la délégation ;
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
   avec un `AiChatSessionEvent` `tool_unknown_outcome`. Le modèle décide de la suite.
3. Un outil **non mutant** au statut `executing` est relancé (lecture sans effet de bord).
4. Les outils `pending` restent en attente de leur décision (état `awaiting_confirmation`).
5. Garde-fou : 3 plantages du worker pour la même conversation en 10 minutes → `failed`
   (`worker_crash_loop`), sans nouvelle relance automatique.

Qui relance : le superviseur, au démarrage et après chaque reconnexion du flux de notifications,
interroge `GET /api/runtime/v1/conversations?state=pending` (04 §4.1), qui inclut les conversations
`running` dont le bail a expiré ; il prend le bail (`queued` implicite) puis lance le worker.

## 6. Codes d'erreur (`lastErrorCode`, évènement `error`)

| Code | État atteint | Sens |
|---|---|---|
| `provider_error` | `failed` | Le fournisseur LLM a échoué après 3 tentatives (backoff 1 s, 4 s, 16 s) |
| `provider_auth` | `failed` | Clé ou ticket du fournisseur refusé |
| `budget_exceeded` | `failed` | `maxTokensPerConversation` atteint |
| `step_limit` | `idle` | `maxStepsPerTurn` atteint : le tour s'arrête, l'utilisateur peut relancer (« continue ») |
| `turn_timeout` | `failed` | `maxTurnDurationSecs` dépassé |
| `confirmation_timeout` | `failed` | Décision attendue trop longtemps (09 §3) |
| `key_timeout` | `failed` | Clé attendue trop longtemps (09 §3) |
| `worker_crash_loop` | `failed` | §5.5 |
| `tool_failed` | (pas de changement) | Un outil a échoué ; son résultat d'erreur est donné au modèle |
| `revoked` | régime `client` | Délégation, autorisation ou runtime révoqués |
| `internal` | `failed` | Erreur interne |

## 7. Correspondance pour l'affichage (app)

| État | Dock et vue (L12, L13) |
|---|---|
| `queued` | « En attente » (et « runtime injoignable » si le runtime est hors ligne) |
| `running` | « En cours » + flux direct |
| `awaiting_confirmation` | « Confirmation demandée » + `PendingActionBar` |
| `awaiting_user` | « Réponse attendue » |
| `awaiting_key` | « Ouvrez Synco pour donner accès » |
| `idle` | « Terminé » |
| `failed` | « Échec » + message selon le code |
| `cancelled` | « Annulé » |
