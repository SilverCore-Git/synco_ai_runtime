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
   passerelle pourrait obtenir des tickets pour elle) → sinon `ticket_wrong_org`.
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

## 8. Révocation

- **Runtime** : liste en mémoire, alimentée par le flux de notifications (04 §6) : `user.revoked`
  (`sub`, `until`), `conversation.revoked` (`conv`). Un ticket de ce `sub` émis avant `until`, ou pour
  cette conversation, est refusé ; les WebSocket ouverts concernés sont fermés (`4403`). Chaque entrée
  expire après la durée maximale d'un ticket.
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

## 10. Codes d'erreur

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
