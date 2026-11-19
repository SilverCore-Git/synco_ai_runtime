# 02 — Tickets

Un ticket est une autorisation courte, signée par synco_api avec Ed25519, que le runtime ou la
passerelle vérifient **localement** avec la clé publique de l'API, sans appel réseau par requête.
Le format reprend `sct1` du CDN (`synco_cdn/docs/plan/02-tickets.md`, `synco_api/src/cdn/cdnTickets.ts`),
pour les mêmes raisons (pas de JWT, pas de champ `alg`, analyse en quelques lignes).

## 1. Deux familles

| Préfixe | Destinataire | Opération | Usage |
|---|---|---|---|
| `srt1` | runtime (`rt` = `runtimeId`) | `connect` | Ouvrir le WebSocket d'une conversation (05) |
| `sgt1` | passerelle (`gw` = URL canonique de la passerelle) | `llm` | `GET /models` et `POST /v1/chat/completions` (P7) |

Le ticket CDN `sct1` n'est accepté par **aucun** des deux, et inversement.

## 2. Format et domaines de signature

```
<préfixe>.<kid>.<contenu>.<signature>
```

| Partie | Contenu |
|---|---|
| préfixe | `srt1` ou `sgt1` ; tout autre préfixe est refusé par le vérificateur concerné |
| `kid` | identifiant de la clé de signature, `^[a-z0-9-]{1,32}$` (même contrainte que `CDN_TICKET_KID`, `cdnConfig.ts:96-99`) |
| contenu | JSON compact, `b64u` |
| signature | Ed25519, 64 octets, `b64u` |

Octets signés :

```
srt1 : "synco-ai-runtime-ticket\0" ‖ utf8("srt1." kid "." contenu)
sgt1 : "synco-ai-gateway-ticket\0" ‖ utf8("sgt1." kid "." contenu)
sct1 : "synco-cdn-ticket\0"        ‖ utf8("sct1." kid "." contenu)        (rappel, cdnTickets.ts:23-24)
```

Les trois domaines sont distincts **et** les préfixes sont distincts : une signature valable pour
l'un ne l'est pour aucun autre, même si la même clé signait les trois. Longueur maximale d'un ticket :
**2 048 octets**, contrôlée avant tout décodage.

Clé de l'API : une paire Ed25519 **propre aux tickets IA** (variables `AI_TICKET_PRIVATE_KEY(_FILE)`
et `AI_TICKET_KID`, sur le modèle de `cdnConfig.ts:84-99`), distincte de la clé des tickets CDN. La
même clé signe `srt1` et `sgt1` ; les domaines les séparent.

Configuration réelle (révisé après la vague B, 2026-11-19 ;
`synco_api/src/services/aiRuntime/runtimeConfig.ts:10-20`, `:79-101`) : les deux variables ou
aucune. Aucune → module runtime désactivé : `503 runtime_disabled` sur le canal interne, sur les
routes utilisateur de la refonte et sur `GET /api/ai/ticket-keys`. Configuration partielle ou
invalide → l'API refuse de démarrer. Rotation : `AI_TICKET_NEXT_PUBLIC_KEYS` (clés publiées
d'avance) et `AI_TICKET_PREVIOUS_PUBLIC_KEYS` (anciennes clés encore publiées), format
`kid=clé_b64u,…` (§7).

## 3. Revendications de `srt1` (op `connect`)

| Champ | Type | Sens |
|---|---|---|
| `op` | `"connect"` | Seule opération v1 |
| `sub` | identifiant (00 §3.2) | Utilisateur |
| `org` | identifiant | Organisation |
| `rt` | UUID | Runtime visé |
| `conv` | identifiant | Conversation (`AiChatSession.id`) |
| `iat` | entier (s) | Émission |
| `exp` | entier (s) | Expiration |

Émission (L02/L03) : `POST /api/orgs/:orgId/ai/sessions/:sessionId/runtime-ticket`, uniquement si
l'appelant est **propriétaire** de la conversation, membre de l'org, module IA actif, que la
conversation est en régime `runtime` sur ce runtime et qu'une autorisation de session active existe
(04 §3). Réponse : `{ "ticket": "srt1…", "expiresAt": <ms>, "url": "<url du runtime>" }`.

Refus (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/aiRuntimeTickets.ts:71-111`), dans
l'ordre : `403 forbidden` (non membre), `403 ai_disabled` (module IA coupé ou org bannie),
`403 runtime_not_allowed` (politique runtime de l'org, 07 §6), `404 session_not_found` (conversation
absente, d'un autre utilisateur ou d'une autre org : même réponse), `409 not_runtime`,
`409 runtime_unavailable` (pas de runtime actif, ou ce n'est pas celui de la conversation),
`409 authorization_inactive` (autorisation ou délégation révoquée, expirée ou discordante). Réponse
servie avec `Cache-Control: no-store` ; le ticket n'est jamais journalisé.

## 4. Revendications de `sgt1` (op `llm`)

| Champ | Type | Sens |
|---|---|---|
| `op` | `"llm"` | Seule opération |
| `sub` | identifiant | Utilisateur pour qui l'appel est fait |
| `org` | identifiant | Organisation |
| `gw` | chaîne ≤ 255 | URL canonique de la passerelle (`canonicalGatewayUrl`, `orgAiConfig.ts:43-50`), telle que configurée dans l'org |
| `rt` | UUID, **facultatif** | Présent si le ticket est demandé par un runtime pour un worker (04 §4) |
| `iat`, `exp` | entiers (s) | Émission, expiration |

Émission :

- navigateur (boucle locale, L11) : `POST /api/orgs/:orgId/ai/gateway-ticket` (membre de l'org,
  module IA actif, fournisseur `gateway` activé avec cette URL) ;
- runtime : `POST /api/runtime/v1/tickets/llm` (requête signée + autorisation de session, 04 §4).

Réponses (révisé après la vague B, 2026-11-19) : `{ "ticket": "sgt1…", "expiresAt": <ms>, "url": "<gw>" }`
dans les deux cas. Refus du navigateur : `403 forbidden`, `403 ai_disabled`,
`409 gateway_not_configured` (`aiRuntimeTickets.ts:53-69`) ; refus du runtime : ceux du canal
(04 §8) et `409 gateway_not_configured` (`synco_api/src/routes/runtimeInternal/runtime.ts:128-143`).

## 5. Vérification (ordre)

Identique à `sct1` (`synco_cdn/docs/plan/02-tickets.md` « Vérification ») :

1. Longueur ≤ 2 048, exactement quatre parties, préfixe attendu → sinon `ticket_invalid`
   (`ticket_missing` si vide).
2. `kid` connu → sinon `ticket_unknown_key`.
3. Signature valide avec le domaine du vérificateur, **avant** tout décodage JSON → sinon
   `ticket_invalid`.
4. JSON strict : champs inconnus refusés, types exacts, identifiants conformes (00 §3.2), `op` connu →
   sinon `ticket_invalid`.
5. `iat − 30 s ≤ maintenant < exp + 30 s` → sinon `ticket_expired` (ou `ticket_invalid` si pas encore
   valide) ; `exp − iat ≤ durée maximale` (§6) → sinon `ticket_invalid`.
6. `op` correspond à la route → sinon `ticket_wrong_operation`.
7. Destinataire : runtime : `rt` = son `runtimeId` ; passerelle : `gw` = son URL publique configurée →
   sinon `ticket_wrong_audience`.
8. Organisation : runtime : `org` = l'org appairée ; passerelle : `org` ∈ liste `SYNCO_ALLOWED_ORGS`
   de sa configuration (obligatoire, sinon n'importe quelle org Synco qui saisirait l'URL d'une
   passerelle pourrait obtenir des tickets pour elle) → sinon `ticket_wrong_org`. La passerelle
   refuse de **démarrer** si la liste est absente ou vide (après retrait des blancs) ; aucune option
   « toutes les organisations » n'existe (`Synco_AI_Gateway/src/config.rs:118-121`, tests `:227-234`).
9. Runtime uniquement : `conv` = conversation du chemin du WebSocket ; `sub` et `conv` absents de la
   liste de révocation en mémoire (alimentée par le flux de notifications, 04 §6) → sinon
   `ticket_wrong_conversation` / `ticket_revoked`.

Chaque échec répond **401** avec le code (HTTP pour la passerelle ; fermeture `4401` avec le code en
raison pour le WebSocket du runtime, 05 §7), jamais le détail.

## 6. Durées

| Ticket | Durée émise | Durée maximale acceptée | Renouvellement |
|---|---|---|---|
| `srt1` | 300 s | 600 s | Nouveau ticket à chaque (re)connexion ; un WebSocket ouvert n'a pas besoin d'un ticket valide pour rester ouvert : il est coupé par une révocation (04 §6) |
| `sgt1` | 300 s | 900 s | Le client (ou le worker) en redemande un 60 s avant `exp`, ou une seule fois sur `401 ticket_expired` |

Tolérance d'horloge : 30 s (comme `sct1`).

## 6 bis. Comportement de la passerelle (révisé après la vague B, 2026-11-19)

La passerelle (L04, `Synco_AI_Gateway`, `readme.md`) n'est plus qu'un proxy LLM authentifié :

| Route | Ticket | Rôle |
|---|---|---|
| `GET /health` | non | `ok`, n'appelle pas Ollama |
| `GET /models` | `sgt1` | `{ "models": [...] }`, restreint à `SYNCO_ALLOWED_MODELS` s'il est défini |
| `POST /v1/chat/completions` | `sgt1` | Relais en flux vers Ollama (format OpenAI) |
| toute autre route | — | `404 not_found`, n'atteint jamais Ollama (`src/app.rs:233-243`) |

Ordre de `POST /v1/chat/completions` (`src/app.rs:148-215`) :

1. Ticket vérifié (§5) **avant** toute lecture du corps → `401 <code de §10>`.
2. Concurrence : `SYNCO_MAX_CONCURRENT_PER_USER` (défaut **4**) par `sub`, puis
   `SYNCO_MAX_CONCURRENT_REQUESTS` (défaut **16**) au total (`src/config.rs:9-10`, `src/limits.rs`) →
   `429 too_many_requests_user` / `429 too_many_requests`, `Retry-After: 1`, Ollama non appelé. La
   place est tenue pendant tout le flux et rendue à sa fin ou à la déconnexion du client (la requête
   vers Ollama est alors abandonnée).
3. Corps ≤ `SYNCO_MAX_BODY_BYTES` (défaut **1 Mio**, configurable, `src/config.rs:6`) →
   `413 body_too_large` (contrôlé sur `Content-Length` puis à la lecture) ; lu en moins de 30 s →
   `408 body_timeout`.
4. Réécriture (`src/relay.rs:9-26`, `:54-91`), dans l'ordre : objet JSON → sinon `400 invalid_json`
   (`400 invalid_body` si ce n'est pas un objet) ; `model` chaîne non vide → sinon
   `400 invalid_body` ; `model` autorisé → sinon `403 model_not_allowed` ; `messages` tableau → sinon
   `400 invalid_body`. Seuls ces champs sont relayés : `model`, `messages`, `tools`,
   `tool_choice`, `stream`, `stream_options`, `temperature`, `top_p`, `stop`, `seed`,
   `presence_penalty`, `frequency_penalty`, `response_format`, `reasoning_effort`, `reasoning`,
   `max_completion_tokens` ; tout autre champ (`options`, `keep_alive`, `user`…) est supprimé.
   `max_tokens` (et `max_completion_tokens` s'il est fourni) est plafonné à `SYNCO_MAX_TOKENS`
   (défaut 4 096 ; valeur absente, négative, nulle ou non numérique → le plafond) ; `n` forcé à 1.
5. Seul `Content-Type: application/json` part vers Ollama (ni le ticket, ni aucun autre en-tête du
   client). Ollama injoignable → `502 ollama_unavailable` ; réponse d'erreur d'Ollama →
   `502 upstream_error`, sans relayer son texte.

Journaux : rien par requête au niveau `info` ; la trace `DEBUG` ne contient que méthode, chemin
(jamais la requête de l'URL), statut et durée. CORS : une seule origine `ALLOWED_ORIGIN`, sinon aucun
en-tête CORS (seul le runtime peut appeler).

## 7. Publication et rotation de la clé publique

`GET /api/ai/ticket-keys` — public, sans authentification :

```json
{ "v": 1, "keys": { "ai-2026-11": "RQigeqlBcH8-stuUyIl6gLLBGXR2tt4hOsJz332GxP8" } }
```

(`b64u` des 32 octets de la clé publique Ed25519.) Le runtime et la passerelle la lisent au démarrage,
puis toutes les 10 minutes, et sur un `kid` inconnu (au plus une fois par minute). L'URL de l'API est
dans leur configuration ; la connexion est en HTTPS vérifié.

Rotation (comme le CDN) : publier la nouvelle clé publique à côté de l'ancienne ; signer avec la
nouvelle après au moins 10 minutes ; retirer l'ancienne après la durée maximale d'un ticket (15 min).

Précisions (révisé après la vague B, 2026-11-19) :

- **Publication anticipée** : la nouvelle clé est publiée par `AI_TICKET_NEXT_PUBLIC_KEYS` avant
  de devenir la clé courante ; l'ancienne reste publiée par `AI_TICKET_PREVIOUS_PUBLIC_KEYS`. La
  réponse fusionne anciennes, prochaines et courante (`runtimeConfig.ts:79-101`). Procédure :
  `synco_api/.env.example`.
- La réponse est servie avec `Cache-Control: public, max-age=60` ; `503 runtime_disabled` si le
  module n'est pas configuré (`synco_api/src/routes/aiRuntimeTickets.ts:116-129`).
- Passerelle (`Synco_AI_Gateway/src/keys.rs:10-28`) : relecture toutes les 600 s, sur `kid` inconnu
  au plus une fois par 60 s ; réponse ≤ 64 Kio et ≤ 16 clés, forme stricte `{ "v": 1, "keys": {…} }` ;
  **échec fermé** : une réponse invalide n'écrase jamais le cache, et sans relecture réussie pendant
  1 h les clés ne sont plus utilisées (tout ticket refusé) ; au démarrage sans API joignable, tout
  ticket est refusé jusqu'à la première lecture. API jointe en HTTPS vérifié, HTTP seulement vers
  `localhost`, sans redirection.

## 8. Révocation

- **Runtime** : liste en mémoire, alimentée par le flux de notifications (04 §6) : `user.revoked`
  (`sub`, `until`), `conversation.revoked` (`conv`). Un ticket de ce `sub` émis avant `until`, ou pour
  cette conversation, est refusé ; les WebSocket ouverts concernés sont fermés (`4403`). Chaque entrée
  expire après la durée maximale d'un ticket.
  **Écart (révisé après la vague B, 2026-11-19)** : l'API n'émet **jamais** `user.revoked` en v1 (le
  type existe, `synco_api/src/services/aiRuntime/runtimeStreamEvents.ts:25`, sans émetteur). La
  perte de droits d'un utilisateur arrive au runtime par `delegation.revoked` et
  `conversation.revoked` (03 §8) ; voir 00 §6 Q13.
- **Passerelle** : pas de liste ; la durée courte suffit (une perte de droits prend effet au plus tard
  au renouvellement).

## 9. Exemples

Clé de démonstration : graine Ed25519 `0x2b` × 32, `kid` = `ai-2026-11`, clé publique ci-dessus.

`srt1` (revendications `{"op":"connect","sub":"66666666-7777-4888-9999-aaaaaaaaaaaa","org":"cm3orgexample0000000000001","rt":"7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f","conv":"0f0e0d0c-0b0a-4908-8706-050403020100","iat":1795000290,"exp":1795000590}`) :

```
srt1.ai-2026-11.eyJvcCI6ImNvbm5lY3QiLCJzdWIiOiI2NjY2NjY2Ni03Nzc3LTQ4ODgtOTk5OS1hYWFhYWFhYWFhYWEiLCJvcmciOiJjbTNvcmdleGFtcGxlMDAwMDAwMDAwMDAwMSIsInJ0IjoiN2QzZjJjMWUtOGE0Yi00YzZkLTllMGYtMWEyYjNjNGQ1ZTZmIiwiY29udiI6IjBmMGUwZDBjLTBiMGEtNDkwOC04NzA2LTA1MDQwMzAyMDEwMCIsImlhdCI6MTc5NTAwMDI5MCwiZXhwIjoxNzk1MDAwNTkwfQ.CQVERsruVeM6rlrpaogw9bxwPboOt8sPU1mir3x6yYjoYjPY-z9zCDvAV8uqAkBDrM3Wkjjzasb8pmPWIm89Cw
```

`sgt1` : [exemples/exemples.json](exemples/exemples.json), clé `tickets.sgt1`. Ed25519 étant
déterministe, ces valeurs sont reproductibles.

## 10. Codes d'erreur (révisé après la vague B, 2026-11-19)

Vérification d'un ticket (runtime : fermeture `4401` ; passerelle : HTTP `401`) :

| Code | Sens |
|---|---|
| `ticket_missing` | Aucun ticket |
| `ticket_invalid` | Format, signature, JSON, durée ou contrainte invalide |
| `ticket_unknown_key` | `kid` inconnu (après une relecture des clés) |
| `ticket_expired` | Expiré (au-delà de la tolérance) |
| `ticket_wrong_operation` | `op` ne correspond pas à la route |
| `ticket_wrong_audience` | `rt` ou `gw` ne désigne pas ce vérificateur |
| `ticket_wrong_org` | Org non appairée (runtime) ou non autorisée (passerelle) |
| `ticket_wrong_conversation` | `conv` ≠ conversation demandée |
| `ticket_revoked` | Utilisateur ou conversation révoqués |

Émission (API, §3, §4) :

| Code | HTTP | Sens |
|---|---|---|
| `runtime_disabled` | 503 | Clés de tickets IA non configurées |
| `forbidden` | 403 | Appelant non membre de l'org |
| `ai_disabled` | 403 | Module IA coupé ou org bannie |
| `runtime_not_allowed` | 403 | Politique runtime de l'org (07 §6) |
| `session_not_found` | 404 | Conversation absente ou d'un autre |
| `not_runtime` | 409 | Conversation hors régime `runtime` |
| `runtime_unavailable` | 409 | Pas de runtime actif, ou autre runtime que celui de la conversation |
| `authorization_inactive` | 409 | Autorisation ou délégation inactive |
| `gateway_not_configured` | 409 | Fournisseur `gateway` non activé ou sans URL |

Passerelle, hors ticket (§6 bis) : `not_found` 404, `too_many_requests_user` / `too_many_requests`
429, `body_too_large` 413, `body_timeout` 408, `invalid_json` / `invalid_body` 400,
`model_not_allowed` 403, `ollama_unavailable` / `upstream_error` 502.
