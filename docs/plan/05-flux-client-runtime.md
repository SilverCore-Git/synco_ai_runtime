# 05 — Flux client ↔ runtime (WebSocket direct)

Le client (synco_app) parle **directement** au runtime (P6) pour suivre une conversation en mode
runtime : flux d'évènements en direct, envoi de messages et de décisions. L'historique enregistré vient
de l'API (déchiffré localement). Conventions : [00 §3](00-vue-ensemble.md).

## 1. Connexion

```
wss://<url du runtime>/v1/conversations/<sessionId>/ws
```

1. Le client obtient un ticket `srt1` (02 §3) et l'URL du runtime par
   `POST /api/orgs/:orgId/ai/sessions/:sessionId/runtime-ticket`.
2. Le runtime n'accepte la mise à niveau que si l'en-tête `Origin` est dans ses origines configurées
   (origine de l'app web, schémas des applis Capacitor / Tauri) ; sinon `403` HTTP.
3. Première trame du client, **dans les 10 s** : `hello` (§6.1) avec le ticket. Le ticket n'est
   jamais mis dans l'URL (les mandataires inverses journalisent les URL).
4. Le runtime vérifie le ticket (02 §5, `conv` = `<sessionId>` du chemin), que la conversation lui est
   autorisée (autorisation connue, 04 §3) et répond `ready` (§5.1), sinon ferme (§7).

Au plus 5 connexions simultanées par conversation (plusieurs onglets ou appareils du même
utilisateur) ; toutes reçoivent les mêmes évènements.

## 2. Trames

- Trames **texte** JSON (UTF-8), une trame = un message. Trames binaires refusées (`4400`).
- Enveloppe commune : `{ "v": 1, "t": "<type>", … }`. Champ inconnu : ignoré par le client,
  **refusé** par le runtime (désérialisation stricte, `4400`).
- Tailles maximales : client → runtime 256 Kio ; runtime → client 1 Mio (un `snapshot` plus gros
  est remplacé par `ready { mode: "reload" }` : le client relit l'historique par l'API).

## 3. Époques et numéros de séquence

- `epoch` = `leaseEpoch` du bail du worker en cours (07 §4) : il augmente à chaque lancement de worker
  pour cette conversation, y compris après un redémarrage du runtime.
- `seq` : entier commençant à 1 pour chaque `epoch`, +1 par évènement envoyé, attribué par le
  **worker** (il entre dans l'AAD des deltas).
- Tout évènement runtime → client porte `epoch` et `seq`, sauf `ready`, `queued`, `pong`.
- Le superviseur garde, par conversation, un tampon circulaire des derniers évènements (09 §2 :
  2 000 évènements ou 4 Mio) pour la reprise.

Reprise : le client envoie dans `hello` le dernier `{ epoch, seq }` reçu. Même `epoch` et `seq + 1`
encore dans le tampon → le runtime rejoue la suite (`ready { mode: "replay" }`) ; sinon il envoie
`ready { mode: "snapshot" }` puis un `snapshot`.

## 4. Chiffrement des champs sensibles

Tout contenu de conversation dans une trame est chiffré par la clé de conversation `CK` au format
`gcm1:` (03 §6.3), pour qu'un mandataire TLS, un journal du runtime ou un relais éventuel (D10) n'ait
jamais de clair. Le format et l'AAD sont **ceux des champs persistés** ; les deltas ont des noms de
champ propres, avec `epoch` et `seq`, pour qu'un delta ne puisse être ni rejoué ni déplacé.

| Trame | Champ | `messageId` de l'AAD | `fieldName` de l'AAD | Clair |
|---|---|---|---|---|
| `text` | `delta` | id du message assistant | `ws:text:<epoch>:<seq>` | texte |
| `thinking` | `delta` | id du message assistant | `ws:thinking:<epoch>:<seq>` | texte |
| `tool_call` | `args` | id du message assistant | `tool_call_arguments:<toolCallId>` | JSON |
| `tool_result` | `result` | id du message `tool` | `tool_result` | JSON |
| `snapshot` | `state` | `__snapshot__` | `snapshot:<epoch>:<seq>` | JSON (§5.2) |
| `error` | `detail` (facultatif) | `__error__` | `error:<epoch>:<seq>` | texte |
| `message` (client) | `content` | `id` du message | `content` | texte |
| `answer` (client) | `value` | `__answer__` | `answer:<toolCallId>` | texte |

AAD complète : `utf8(sessionId ":" messageId ":" fieldName)`. Exemple : `text`, `epoch` 2, `seq` 42,
« Bonjour » →
`gcm1:7+/v7+/v7+/v7+/vz06FC0lBPxpIkGJG6F0dJbtwRzSPLvs=` avec l'AAD
`0f0e0d0c-0b0a-4908-8706-050403020100:3c2b1a09-8f7e-4d6c-9b5a-493827161504:ws:text:2:42`
([exemples/exemples.json](exemples/exemples.json), clé `gcm1ws`).

En clair : types, identifiants, statuts, nom des outils, `mutating`, `category`, usage (tokens),
codes d'erreur.

## 5. Runtime → client

### 5.1 `ready`

```json
{ "v": 1, "t": "ready", "status": "running", "rev": 12, "epoch": 2, "lastSeq": 41, "mode": "replay" }
```

`status` : statut de la conversation (08) ; `rev` : révision enregistrée dans l'API ; `mode` :
`replay` | `snapshot` | `idle` (aucun worker : l'historique de l'API suffit) | `reload` (relire
l'historique puis se reconnecter).

### 5.2 `snapshot`

```json
{ "v": 1, "t": "snapshot", "epoch": 2, "seq": 42, "baseRev": 12, "state": "gcm1:…" }
```

`state` déchiffré : `{ "messages": StoredMessage[], "status": "...", "pendingToolCall": {...} | null }`
— les messages **postérieurs** à `baseRev` (étape en cours, pas encore enregistrée), champs déjà en
clair à l'intérieur (ils sont protégés par le chiffrement de `state`). Si l'historique du client est
antérieur à `baseRev`, il le relit d'abord.

### 5.3 Évènements de déroulement

| `t` | Champs (en plus de `epoch`, `seq`) | Sens |
|---|---|---|
| `text` | `messageId`, `delta` (chiffré) | Morceau de réponse |
| `thinking` | `messageId`, `delta` (chiffré) | Morceau de raisonnement |
| `tool_call` | `messageId`, `toolCallId`, `name`, `category`, `mutating`, `interactive`, `status`, `args` (chiffré) | Appel d'outil créé ou changé d'état (`pending` → `accepted`/`rejected` → `executing` → `done`/`error`, `ToolCallStatus`, `synco_api/src/services/ai/types.ts:1`) |
| `tool_result` | `messageId` (message `tool`), `toolCallId`, `name`, `result` (chiffré) | Résultat |
| `status` | `status`, `reason?` (code) | Changement d'état de la conversation (08) |
| `usage` | `messageId`, `promptTokens?`, `completionTokens?`, `totalTokens?`, `reasoningTokens?` | Usage d'un appel au fournisseur (comme `UsageInfo`, `types.ts:12-17`) |
| `error` | `code`, `detail?` (chiffré) | Erreur de la conversation (le statut suit dans un `status`) |

Correspondance avec l'affichage existant (`WireEvent`, `synco_api/src/services/ai/types.ts:44-53`) :
`tool_call` `pending` + `category` `server` ≈ `tool_call_pending` ; `tool_call` `pending` + `client` ou
`interactive` ≈ `tool_call_client_required` ; `tool_result` ≈ `tool_call_result` ; `status` `idle`
≈ `done`. L12 adapte la source d'évènements derrière une interface commune.

### 5.4 Accusés et maintien

- `queued` : `{ "v": 1, "t": "queued", "id": "<id de l'élément>" }`, envoyé **après** que l'élément
  a été rendu durable dans l'API (`POST /api/runtime/v1/conversations/:id/inbox`, 04 §4.2).
- `pong` : réponse à `ping`.

## 6. Client → runtime

### 6.1 `hello`

```json
{ "v": 1, "t": "hello", "ticket": "srt1.…", "resume": { "epoch": 2, "seq": 41 } }
```

`resume` vaut `null` à la première connexion.

### 6.2 Éléments de boîte de réception

Chaque élément est durable : le runtime le dépose dans la boîte de réception de la conversation
(API) avant d'envoyer `queued`, puis le worker le consomme à l'étape suivante (`consumedInbox` dans
l'écriture de l'historique, 04 §4.2). Si le WebSocket n'est pas disponible, le client dépose le même
élément par l'API : `POST /api/orgs/:orgId/ai/sessions/:sessionId/inbox` (L03), qui réveille le
runtime (`conversation.wake`). Ids idempotents :

| `t` | Champs | `id` de l'élément | Effet |
|---|---|---|---|
| `message` | `id` (UUID v4 tiré par le client), `content` (chiffré), `createdAt` (ISO 8601) | `id` | Message utilisateur : devient tel quel un `StoredMessage` `user`. Pendant un tour : mis en file, pris en compte à l'étape suivante. |
| `confirm` | `toolCallId`, `decision` : `accept` \| `reject` | `confirm:<toolCallId>` | Décision sur un outil en `awaiting_confirmation` |
| `answer` | `toolCallId`, `value` (chiffré) | `answer:<toolCallId>` | Réponse à `ask_question` |
| `upload` | `toolCallId`, `ref` | `upload:<toolCallId>` | Référence d'une image envoyée par la voie normale (`request_image_upload`) ; le format exact de `ref` est fixé par L12 |
| `cancel` | `id` (UUID v4) | `cancel:<id>` | Annuler le tour en cours (08 §4) |

Un élément qui ne correspond pas à l'état (décision pour un outil qui n'attend rien, double réponse)
est consommé et ignoré, avec un évènement `error { code: "stale_decision" }`.

### 6.3 `ping`

`{ "v": 1, "t": "ping" }` toutes les 25 s ; sans trame reçue pendant 60 s, chaque côté ferme.

Débit client → runtime : 20 trames / 10 s par connexion, au-delà `4429`.

## 7. Fermetures et codes d'erreur

| Code WebSocket | Raison (code machine) | Sens |
|---|---|---|
| `4400` | `bad_frame` | Trame invalide, binaire, trop grande, champ inconnu |
| `4401` | code de ticket (02 §10) | Ticket refusé |
| `4403` | `forbidden` / `revoked` | Conversation non autorisée sur ce runtime, ou révoquée en cours de route |
| `4404` | `not_runtime` | La conversation n'est pas (ou plus) en mode runtime |
| `4408` | `hello_timeout` | Pas de `hello` en 10 s |
| `4409` | `too_many_connections` | Plus de 5 connexions |
| `4429` | `rate_limited` | Débit dépassé |
| `4503` | `shutting_down` | Arrêt du runtime ; se reconnecter avec backoff |
| `4500` | `internal` | Erreur interne |

Codes de l'évènement `error` (sans fermeture) : `stale_decision`, `key_unavailable`,
`provider_error`, `budget_exceeded`, `step_limit`, `confirmation_timeout`, `tool_failed`,
`internal`.

Reconnexion du client : backoff 1 s → 30 s avec gigue ; nouveau ticket à chaque tentative ; après
`4401 ticket_expired` une seule nouvelle tentative immédiate.

## 8. Journaux

Le runtime ne journalise ni ticket, ni valeur `gcm1:`, ni contenu de trame. Seuls : `sessionId`,
type de trame, taille, code de fermeture.

## 9. Mode dégradé (runtime injoignable, D10)

Si le client ne joint pas le runtime (hors réseau de l'entreprise, runtime arrêté) :

- historique en lecture seule par l'API (`GET /api/orgs/:orgId/ai/sessions/:id`, déchiffré avec `CK`),
  statut à jour (écrit par le worker) ;
- les messages et décisions passent par la boîte de réception de l'API (§6.2) ; ils seront traités
  quand le runtime les verra ;
- pas de flux en direct ; indicateur « runtime injoignable ».

Un relais du flux par l'API n'est pas prévu en v1 (D10) ; s'il était décidé, les trames de ce
document pourraient être relayées telles quelles (contenu déjà chiffré).

## 10. Exemple de séquence

```
C → R  {"v":1,"t":"hello","ticket":"srt1.ai-2026-11.eyJ…","resume":null}
R → C  {"v":1,"t":"ready","status":"idle","rev":12,"epoch":1,"lastSeq":0,"mode":"idle"}
C → R  {"v":1,"t":"message","id":"3c2b1a09-…","content":"gcm1:…","createdAt":"2026-11-18T10:00:00.000Z"}
R → C  {"v":1,"t":"queued","id":"3c2b1a09-…"}
R → C  {"v":1,"t":"status","epoch":2,"seq":1,"status":"running"}
R → C  {"v":1,"t":"text","epoch":2,"seq":2,"messageId":"9a8b…","delta":"gcm1:…"}
R → C  {"v":1,"t":"tool_call","epoch":2,"seq":3,"messageId":"9a8b…","toolCallId":"call_1","name":"create_task","category":"server","mutating":true,"interactive":false,"status":"pending","args":"gcm1:…"}
R → C  {"v":1,"t":"status","epoch":2,"seq":4,"status":"awaiting_confirmation"}
C → R  {"v":1,"t":"confirm","toolCallId":"call_1","decision":"accept"}
R → C  {"v":1,"t":"queued","id":"confirm:call_1"}
R → C  {"v":1,"t":"tool_call","epoch":3,"seq":1,…,"status":"executing","args":"gcm1:…"}
R → C  {"v":1,"t":"tool_result","epoch":3,"seq":2,"messageId":"7c6d…","toolCallId":"call_1","name":"create_task","result":"gcm1:…"}
R → C  {"v":1,"t":"usage","epoch":3,"seq":3,"messageId":"9a8b…","promptTokens":812,"completionTokens":64,"totalTokens":876}
R → C  {"v":1,"t":"status","epoch":3,"seq":4,"status":"idle"}
```

(L'`epoch` change après la confirmation parce que le worker s'est arrêté pendant l'attente, 08 §4.)
