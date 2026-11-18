# 09 — Limites et valeurs par défaut

Propositions chiffrées pour les décisions ouvertes **D4** (durée des délégations) et **D6** (plafonds),
plus les autres bornes de la spécification. Toutes les valeurs sont réglables dans la configuration du
runtime (L05) ; celles marquées « org » peuvent aussi être **abaissées** par l'org (`aiConfig.runtime`,
07 §6), jamais relevées au-delà de la configuration du runtime.

## 1. D4 — Durée d'une délégation

| Option | Défaut | Maximum | Conséquence |
|---|---|---|---|
| **A. 7 jours, renouvelée à l'ouverture** (recommandée) | 7 j | réglable par l'admin de 1 h à 30 j (`maxDelegationDays`, org) ; plafond du runtime 30 j | Une conversation lancée le vendredi continue le week-end. Un utilisateur qui n'ouvre plus Synco pendant 7 jours perd l'arrière-plan (ses conversations repassent en local, 08 §3). |
| B. 24 heures | 24 h | 7 j | Fenêtre d'exposition plus courte ; mais une absence d'un jour arrête les conversations de fond, ce qui va contre l'objectif « fermer Synco, revenir plus tard ». |
| C. 30 jours | 30 j | 90 j | Confort maximal ; un appareil temporaire qui garde un mois de clés (et de capacité d'agir) sans contrôle. |

Règles communes, quelle que soit l'option :

- **Renouvellement** (03 §7.2) : à l'ouverture de l'app déverrouillée et toutes les 6 h tant qu'elle
  reste ouverte, si la durée restante est inférieure à **50 %** de la durée ; nouvelle délégation
  complète (nouvelle `DK`, nouvel `exp`).
- **Durée minimale** : 1 h (en dessous, l'API refuse : `delegation_invalid`).
- **Horloge** : `|iat − maintenant| ≤ 300 s` au dépôt.
- Ce que fixe la spec selon l'option : la valeur par défaut de `maxDelegationDays` (07 §6), le
  plafond du runtime (`max_delegation_days`), le contrôle `exp − iat` (API au dépôt, runtime à
  l'ouverture, 03 §4), et `AiSessionAuthorization.expiresAt` (= expiration de la délégation).

**Recommandation** : A (7 jours, admin libre entre 1 h et 30 jours).

## 2. D6 — Plafonds du worker et du runtime

| Plafond | Valeur proposée | Portée | Où appliqué | Justification |
|---|---|---|---|---|
| `maxStepsPerTurn` | **25** appels au fournisseur par tour | org | worker | La boucle locale s'arrête à 8 (`clientAgent.ts:46`) : trop court pour un travail de fond ; 25 couvre une recherche + plusieurs outils. Atteint → `idle` + `step_limit`. |
| `maxTokensPerConversation` | **2 000 000** tokens (entrée + sortie, cumulés) | org | worker | Garde-fou de coût ; ~ quelques euros sur un modèle cloud courant. Atteint → `failed` `budget_exceeded`. |
| `maxTokensPerTurn` | **300 000** | org | worker | Évite qu'un seul tour consomme tout le budget. |
| `maxTurnDurationSecs` | **1 800** (30 min) | org | worker | Au-delà → `failed` `turn_timeout`. |
| `maxOutputTokensPerCall` | **4 096** | org | worker | Comme le plafond du relais de l'API (`aiProxy.ts:144`). |
| `maxToolResultBytes` | **256 Kio** (tronqué au-delà, avec mention) | runtime | worker | Protège le contexte du modèle et la taille de l'historique. |
| `idleShutdownSecs` | **60 s** | runtime | superviseur | Le worker ne vit que lorsqu'il travaille (P3) ; 60 s évitent de relancer pour un message tapé juste après. |
| Workers simultanés par utilisateur | **3** | org | superviseur | Au-delà, la conversation reste `queued`. |
| Workers simultanés par runtime | **8** par défaut ; recommandé : ⌊RAM libre × 0,6 / 512 Mio⌋ | runtime | superviseur | Dimensionnement à ajuster avec la mesure de L06. |
| RAM par worker (`memory.max`) | **512 Mio** (`memory.high` 448 Mio) | runtime | cgroup (L06) | Un worker = boucle + client HTTP + historique en mémoire ; la recherche sémantique locale (Q6) peut demander plus : à mesurer. Dépassement → OOM de **ce** worker seul. |
| CPU par worker (`cpu.max`) | **1 CPU** (`100000 100000`) | runtime | cgroup | Le travail est surtout de l'attente réseau. |
| Process par worker (`pids.max`) | **64** | runtime | cgroup | Empêche les bombes de fork. |
| Durée d'un appel au fournisseur | 120 s sans octet reçu ; 10 min au total | runtime | worker | |
| Bail (`LEASE_MS`) | **60 s**, renouvelé toutes les 20 s | — | API / worker | Relance après plantage en ≤ 60 s. |
| Tampon de reprise (05 §3) | **2 000** évènements ou **4 Mio** par conversation | runtime | superviseur | |
| `signed_request` du worker | 20 / s, rafale 50 | runtime | superviseur | |

**Recommandation** : ces valeurs, à revoir après les mesures de L06 (coût d'un worker vide, temps de
lancement) et les premiers essais de L07.

## 3. Délais d'attente

| Attente | Délai | Au-delà |
|---|---|---|
| `awaiting_confirmation`, `awaiting_user` | **7 jours** (org) | `failed` `confirmation_timeout` (08 §2) — dépend aussi de D5 |
| `awaiting_key` | **7 jours** | `failed` `key_timeout` |
| `queued` (runtime hors ligne) | aucun | reste `queued` ; affiché « runtime injoignable » |
| `hello` du WebSocket client | 10 s | fermeture `4408` |

## 4. Débits et tailles

| Élément | Limite |
|---|---|
| Ticket | 2 048 octets ; `srt1` 300 s émis / 600 s max ; `sgt1` 300 s / 900 s max ; tolérance 30 s |
| `POST <url>/v1/challenge` | 10 / min par adresse IP, 60 / min au total |
| Canal interne (par runtime) | 50 requêtes / s, rafale 200 ; corps 256 Kio (8 Mio pour `PUT …/transcript`) |
| Fenêtre des requêtes internes | ±60 s ; nonces gardés 120 s |
| Historique d'une conversation (`messages`) | 8 Mio sérialisés ; au-delà, refus d'écriture (`invalid_body`) et `failed` `internal` — compaction hors v1 |
| Entrées par délégation | 5 000 |
| Dépôt de délégations | 10 / h par utilisateur |
| Ajout d'entrées (client) | 1 requête / 5 s, ≤ 500 entrées par requête |
| Trames WebSocket client | 256 Kio (client → runtime), 1 Mio (runtime → client) ; 20 trames / 10 s par connexion ; 5 connexions par conversation |
| Boîte de réception | 100 éléments non consommés par conversation ; 20 dépôts / 10 s |
| Notifications push | 1 / 30 s par conversation |
| `POST /metrics` | 1 / min |
| Trames du pipe | 1 Mio (JSON), 64 Kio (clés) |
| Synchro P11 (client) | regroupement 5 s ; backoff 30 s → 30 min ; 5 tentatives par session de l'app |
