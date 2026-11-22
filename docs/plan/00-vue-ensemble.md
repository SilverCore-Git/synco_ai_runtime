# 00 — Vue d'ensemble de la spécification

Ce dossier fige les **protocoles et formats** du Synco AI Runtime (lot L00 de la refonte Synco AI). Il
remplace l'esquisse `04_protocoles.md` du dossier de projet : en cas d'écart, **ce dossier fait foi**.
Les lots L01 à L13 l'implémentent ; un changement de format passe par une modification de ce dossier,
relue comme la première version.

**Révision après la vague B (2026-11-19, lot L00b)** : les écarts acceptés pendant L01 à L04 (crate,
API, passerelle) sont reportés dans 01, 02, 03, 04, 05, 07, 08 et 09 (sections marquées « révisé
après la vague B »), avec la source exacte dans le code ; aucun format chiffré ni exemple n'a changé.
Les tensions relevées et non tranchées sont les questions Q11 à Q17 (§6).

| Document | Contenu |
|---|---|
| [01-appairage-et-certificat.md](01-appairage-et-certificat.md) | Clés du runtime, empreinte, code d'appairage, défi de possession, certificat signé par un admin, épinglage TOFU, désappairage |
| [02-tickets.md](02-tickets.md) | Tickets `srt1` (runtime) et `sgt1` (passerelle) : format, domaines, revendications, durées, rotation, erreurs |
| [03-delegation.md](03-delegation.md) | Mandat, enveloppe de tête, entrées de clés, clé de conversation, synchro P11, renouvellement, révocation, clés créées par le runtime (FC4) |
| [04-canal-interne.md](04-canal-interne.md) | Requêtes signées runtime → API, autorisation de session, liste fermée des routes du runtime, flux de notifications |
| [05-flux-client-runtime.md](05-flux-client-runtime.md) | WebSocket client ↔ runtime : messages, chiffrement champ par champ, séquences, reprise, erreurs |
| [06-superviseur-worker.md](06-superviseur-worker.md) | Pipe superviseur ↔ worker : cadrage, messages, clés, plafonds |
| [07-modele-de-donnees.md](07-modele-de-donnees.md) | Modèles Prisma ajoutés ou étendus, bail par `updateMany` conditionné |
| [08-etats-conversation.md](08-etats-conversation.md) | Machine à états d'une conversation, transitions, plantages |
| [09-limites-et-valeurs-par-defaut.md](09-limites-et-valeurs-par-defaut.md) | Propositions chiffrées pour D4 et D6, autres plafonds |
| [12-plan-action.md](12-plan-action.md) | Plan d'action (format, chiffrement, types d'action, validation, états, exécution, verrou `ask`), mode autonome, politiques d'org des fonctionnalités IA ; figé par L00f (C1, PC34 à PC43), amendé par PC44 à PC48 puis PC54 à PC58 |
| [vectors/README.md](vectors/README.md) | Vecteurs de test à produire par L01 et L02 ; vecteurs figés par L00f (`mandate-v2.json`, `action-plan.json`) |
| [exemples/](exemples/) | Exemples calculés (non normatifs) qui illustrent chaque format |

## 1. Rappel de l'architecture

```
 synco_app (navigateur, mobile, Tauri)
   │  détient AK et les clés d'identité ; crée le mandat et les enveloppes de délégation
   │
   ├── HTTPS ───────────────▶ synco_api : droits, registre des runtimes, tickets Ed25519,
   │                          délégations (opaques), autorisations de session, conversations
   │                          chiffrées, outils « serveur », notifications push
   │                                   ▲
   │                                   │ canal interne : requêtes signées Ed25519 par le runtime
   │                                   │ (+ identifiant d'autorisation de session) ; WebSocket
   │                                   │ sortant pour les notifications
   │                                   │
   └── WSS direct + ticket srt1 ─▶ synco_ai_runtime (chez le client)
                                   superviseur : seule clé privée du runtime, vérifie les tickets,
                                   ouvre les délégations, lance les workers
                                      │ pipe : clés de LA conversation uniquement
                                      ▼
                                   worker (1 process isolé par conversation active) :
                                   boucle d'agent, LLM, outils, enregistrement chiffré
```

Le runtime est un **appareil temporaire de l'utilisateur, limité à l'organisation** (P5) : il reçoit,
chiffrées pour lui, les clés de l'org auxquelles l'utilisateur a accès, jamais l'AK ni une clé
d'identité. Il n'est **pas** un `UserDevice` (`synco_api/prisma/schema.prisma:167`) : un appareil
reçoit l'enveloppe de l'AK, le runtime jamais.

## 2. Glossaire

| Terme | Définition |
|---|---|
| **Runtime** | Service Rust auto-hébergé par le client (P1, P2). Identifié par `runtimeId` (UUID v4 tiré au premier démarrage). En v1, appairé à **une seule** organisation. |
| **Superviseur** | Process principal du runtime. Seul détenteur des clés privées du runtime (mesure 7). Vérifie les tickets, ouvre les délégations, lance et surveille les workers, sert le dashboard. N'exécute jamais la boucle d'agent. |
| **Worker** | Process isolé (P3) qui fait tourner **une** conversation. Reçoit par le pipe les seules clés de cette conversation. |
| **Clés du runtime** | Trois paires : `sig` (Ed25519, signe les requêtes vers l'API), `kex` (ECDH P-256, reçoit les délégations), `csk` (ECDSA P-256, signe le défi de possession et les enveloppes FC4 des clés que le runtime crée). Cf. 01 §1. |
| **Empreinte** | SHA-256 de l'identifiant et des trois clés publiques du runtime (01 §2). Affichée dans le dashboard et dans Synco (mesure 4). |
| **Certificat** | Déclaration signée par un admin de l'org avec sa clé de signature d'identité (ECDSA P-256, FC4) : org, runtime, URL, clés publiques (mesure 1). |
| **Défi de possession** | Échange direct client → runtime qui prouve la détention des clés privées `csk` et `kex` certifiées (mesure 2). |
| **Épinglage TOFU** | Mémorisation locale, par le client, de l'empreinte du runtime de l'org vue la première fois (mesure 3). |
| **Délégation** | Ensemble daté, lié à un utilisateur, une org et un runtime, qui transmet au runtime des clés de l'org. Composée d'un **mandat**, d'une **enveloppe de tête** et d'**entrées**. Identifiée par `delegationId`. |
| **Mandat** | Partie de la délégation signée par l'utilisateur avec sa clé de signature d'identité. Il authentifie la délégation : l'API ne peut pas en forger une. |
| **Enveloppe de tête** | Chiffrement ECDH P-256 + HKDF + AES-GCM de la clé de délégation `DK` vers la clé `kex` du runtime, avec une AAD qui contient utilisateur, org, runtime, périmètre et expiration (mesure 5). |
| **Entrée** | Une clé de l'org (salon, espace, conversation) chiffrée sous `DK`, avec une AAD qui la lie à la délégation et à son contexte. |
| **Clé de conversation (`CK`)** | Clé AES-256 propre à une conversation en mode runtime ; chiffre ses champs au format `gcm1:` (03 §6). |
| **Autorisation de session** | Enregistrement de l'API, créé à la bascule d'une conversation, qui permet au runtime d'agir **pour cet utilisateur, sur cette conversation**. Son identifiant (`authId`) accompagne chaque requête du runtime (04 §3). |
| **Ticket** | Jeton court signé Ed25519 par l'API : `srt1` pour se connecter au runtime, `sgt1` pour appeler la passerelle. Vérifié localement (02). |
| **Bail** | Droit exclusif et temporaire d'un worker d'écrire une conversation, pris et renouvelé par `updateMany` conditionné (07 §4). |
| **Bascule** | Passage explicite d'une conversation du mode local au mode runtime, ou retour. |
| **Régime** | Où tourne la boucle d'une conversation : `client`, `server` ou `runtime` (02_architecture §2). |
| **Plan d'action** | Liste fermée d'actions proposée par l'agent (outil interne `propose_actions`), chiffrée sous `CK`, que l'utilisateur accepte en tout ou en partie et que **son appareil** exécute avec ses clés ; les actions serveur sont exécutées par l'agent après acceptation, selon un graphe de dépendances explicite : chaque action prête s'exécute aussitôt, en parallèle, sur l'appareil ou chez l'agent (PC44, PC58, 12 §8.1). |
| **Mode autonome** | Option de l'utilisateur, autorisée par la politique de l'org, où le runtime crée lui-même les salons avec sa signature `rt1` ; consentement signé dans le mandat v2 (`mode = auto`, 03 §4.1). Défaut : mode plan. |
| **Politique de fonctionnalité** | Réglage de l'org (tout le monde / personne / personne sauf) d'une fonctionnalité IA « pratique mais moins sûre », que chacun active ensuite lui-même (12 §11). |

## 3. Conventions communes à tous les documents

### 3.1 Encodages

| Notation | Sens |
|---|---|
| `b64` | Base64 standard RFC 4648 §4, **avec** remplissage `=`. Utilisé pour tout ce qui appartient à la famille E2EE existante (signatures FC4, commitments, scellés RSA, valeurs `gcm1:`), parce que le code existant l'emploie (`btoa`, `STANDARD` dans `crypto.rs`). |
| `b64u` | Base64 URL RFC 4648 §5, **sans** remplissage. Utilisé pour les nouveaux formats transportés dans des URL, en-têtes et tickets (comme `sct1`). |
| `hex` | Hexadécimal **minuscule**, sans séparateur. |
| `utf8(s)` | Octets UTF-8 de la chaîne `s`, sans BOM ni terminaison. |
| `‖` | Concaténation d'octets. |
| `\0` | L'octet nul `0x00`. |
| `JWK-EC` | Clé publique P-256 sous forme de JSON canonique **RFC 7638** : exactement `{"crv":"P-256","kty":"EC","x":"<b64u 32 o>","y":"<b64u 32 o>"}`, clés dans cet ordre, sans espace. C'est la forme de `canonicalEcJwk` (`synco_app/src/assets/utils/keyTrust.ts:152`) et de `ecCanonical` (`e2eeV4.ts:473`). |
| Signature ECDSA | P-256 + SHA-256, encodage **IEEE P1363** (`r ‖ s`, 64 octets) : c'est ce que produit et attend WebCrypto. RustCrypto doit être configuré pour ce format, pas DER. |
| Signature Ed25519 | 64 octets (RFC 8032), clé publique brute 32 octets. |

**Piège (L01)** : `canonicalJwk` de `e2eeV4.ts:322` construit l'objet `{kty, crv, x, y}` et les
formats existants qui le sérialisent (`createDeviceEnvelope`, `deviceCertBytes`, liaison) produisent
donc `{"kty":"EC","crv":"P-256",…}`. Ces formats existants gardent leur ordre. **Tous les nouveaux
formats de ce dossier utilisent l'ordre RFC 7638** (`crv` d'abord).

### 3.2 Chaînes signées ou authentifiées

Les octets signés ou passés en AAD sont des chaînes UTF-8 de champs séparés par `|`, préfixées d'une
étiquette de version (`synco-rt-…-v1`), dans le style des formats E2EE existants
(`synco-e4-device-cert|…`, `synco-key-envelope-v1|…`). Pour que la concaténation reste non ambiguë,
**chaque champ est validé avant usage** :

| Champ | Contrainte |
|---|---|
| identifiants (`orgId`, `userId`, `runtimeId`, `delegationId`, `sessionId`, `messageId`, `threadId`, `workspaceId`, `toolCallId`, `authId`) | `^[A-Za-z0-9_-]{1,64}$` (UUID et cuid passent ; ni `|` ni `:`) |
| URL de runtime | forme canonique de 01 §3 (ne contient ni `|` ni espace) |
| entiers (`iat`, `exp`, `version`, `serial`, `seq`, `epoch`) | décimal ASCII sans signe ni zéro de tête, ≤ 2⁵³ − 1 |
| `JWK-EC` | forme canonique ci-dessus (ni `|` ni espace) |
| `kind`, `scope`, `purpose` | valeurs énumérées dans le document concerné |

Une valeur qui ne respecte pas sa contrainte est **refusée** ; elle n'est jamais échappée.

### 3.3 Horloge

Les dates des formats sont des **secondes Unix** entières (`iat`, `exp`, horodatages de requêtes).
Tolérance d'horloge : 30 s pour les tickets (comme `sct1`), 60 s pour les requêtes internes (comme
`internalAuth.ts`). Les colonnes Prisma restent des `DateTime`.

### 3.4 Codes d'erreur

Chaque refus renvoie un **code machine** stable (`snake_case`), jamais le détail interne ni une valeur
reçue. Le message lisible est construit côté client. Les codes sont listés dans chaque document.

## 4. Invariants de sécurité et lots qui les testent (révisé après la vague B, 2026-11-19 ; révisé après L03c/L05, 2026-11-20)

Rattachement de chaque invariant de `03_securite.md §4` au document qui le spécifie et au lot qui écrit
le test qui échoue sans la protection.

| Invariant (03 §4) | Spécifié dans | Testé par |
|---|---|---|
| Un ticket mal signé, expiré, d'une autre org ou d'un autre runtime est refusé par le runtime et la passerelle | 02 §5, §6 | L02 (vecteurs), L05 (runtime), L04 (passerelle) |
| Le domaine de signature des tickets runtime diffère de celui du CDN | 02 §2 | L00 (domaines figés ici), L02 (vecteur « ticket `sct1` présenté au runtime »), L04 |
| L'API refuse toute requête du runtime sans signature valide, hors fenêtre ou rejouée | 04 §2 | L02 |
| L'API ne sert au runtime que les données chiffrées de l'org de la délégation, jamais une autre org ni les DM | 04 §4, §5 | L03 |
| Une délégation expirée ou révoquée bloque l'accès côté API même si le runtime l'ignore | 03 §8, 04 §3 | L03 |
| Une enveloppe de délégation copiée vers un autre runtime / org / utilisateur ne s'ouvre pas | 03 §3, §4 | L01 (vecteurs négatifs), L10 (côté TS) ; L05 vérifie aussi le mandat |
| Le client refuse de déléguer si le certificat n'est pas signé par un admin épinglé, si la clé a changé ou si le défi échoue | 01 §5, §6.3, §8 | L10 |
| Le client ne transmet jamais l'AK ni une clé privée d'identité au runtime | 03 §2 | L10 (inspection des charges) ; L01 (la crate n'a pas d'API pour sceller l'AK vers un runtime) |
| Un worker ne lit pas `/proc` des autres, le disque hôte, ni n'ouvre de connexion non autorisée | 06 §6 | L06 |
| Un worker qui dépasse son plafond RAM/CPU est tué sans affecter les autres | 06 §6, 09 §2 | L06 |
| Aucune clé ni contenu en clair dans les journaux | 04 §7, 05 §8, 06 §7 | tous (L02, L03, L04, L05, L07, L10) |
| Le dashboard n'expose aucun contenu de conversation | 06 §5 (métriques sans contenu), 11 §5 | L08 (`dashboard_sans_contenu_de_conversation`) |
| Un outil exécuté par l'IA applique exactement les permissions de l'utilisateur | 04 §5 | L14, L15 (et L03 pour la route) |
| Un outil mutant en cours au moment d'un plantage n'est jamais relancé | 08 §5 | L07 |
| La passerelle refuse tout appel sans ticket valide et n'expose qu'un sous-ensemble fixe d'Ollama | 02 §6 | L04 |

Invariants **ajoutés** par cette spécification (mêmes règles : test qui échoue sans la protection) :

| Invariant ajouté | Spécifié dans | Testé par |
|---|---|---|
| Une délégation dont le mandat n'est pas signé par l'utilisateur (clé épinglée par le runtime) est refusée, même si son enveloppe s'ouvre | 03 §4 | L01 (vecteur), L05 |
| Une entrée écrite sous une autre `DK`, ou avec une AAD d'une autre délégation, est refusée | 03 §5 | L01, L05 |
| Un `kind` d'entrée hors liste (`dm`, `support`, `account`, `identity`…) est refusé par l'API **et** par le runtime | 03 §2 | L03, L05 |
| Le runtime n'utilise jamais, pour l'utilisateur A, une clé reçue dans la délégation de l'utilisateur B | 03 §9 | L05, L07 |
| Deux workers ne peuvent pas écrire la même conversation (bail + jeton de clôture `leaseEpoch`) | 07 §4 | L03 |
| Un `encryptionScheme` ne régresse jamais (pas de passage d'un schéma chiffré à `null` ni de `conv-gcm1-v1` à `gateway-aes-gcm-v1`) | 03 §6, 07 §2 | L03 |
| Une clé créée par le runtime porte une enveloppe `rt1` vérifiable par les clients à jour, et reste acceptée (TOFU) par les clients anciens | 03 §10 | L07 (production), L10 (vérification), L01 (vecteur) ; **côté API : route de pose a posteriori livrée par L03c (Q11 = B, 04 §4.3, 03 §10.1)** — entre la création et la pose le salon reste accepté en TOFU, et l'API ne peut pas vérifier `commitment` |

Invariants **ajoutés pendant la vague B** (révisé après la vague B, 2026-11-19), chacun déjà couvert par
un test qui échoue sans la protection :

| Invariant | Spécifié dans | Testé par (test existant) |
|---|---|---|
| L'anti-rejeu est propre à chaque runtime et n'évince jamais un nonce valide : un runtime qui sature son ensemble n'obtient que `429`, jamais la réacceptation d'une requête capturée | 04 §2.3 étape 5 | L02 (`synco_api/src/services/aiRuntime/runtimeAuth.test.ts:370`, `:391`, `:398`) |
| Le corps d'une requête interne n'est lu qu'après en-têtes, horloge et runtime actif ; lectures non authentifiées bornées par IP | 04 §1, §2.3 | L02 (`runtimeAuth.test.ts:338`, `:349`) |
| `x-synco-auth` présent sur une route « S » déclenche quand même le second verrou (M1) ; un `:sessionId` de chemin différent de l'autorisation est refusé | 04 §2.3 étape 6, §3.2 | L02 (`runtimeAuth.test.ts:219`, `:275`), L03b (`synco_api/src/routes/runtimeInternal/runtimeChannelE2e.test.ts:181`) |
| Un outil `deny` n'est jamais exécuté par l'API, même si le worker l'ignore ; aucune action d'outil sans le bail courant | 04 §4.3, §5 | L03b (`synco_api/src/routes/runtimeInternal/runtimeE2eeWrites.test.ts:150`, `:175`, `:233`) |
| Un changement d'état IA de l'org (bannie, IA ou mode runtime coupés, membre retiré) révoque les délégations concernées | 03 §8.1 | L03b (`synco_api/src/services/aiRuntime/runtimePolicyEnforcement.test.ts:60-88`) |
| Le désappairage purge toutes les entrées ; un `runtimeId` désappairé ne revient ni dans une autre org ni avec d'autres clés | 01 §7.1, §9 | L02 (`synco_api/src/routes/aiRuntimeRoutes.test.ts:245`, `:253`) |
| Le runtime vérifie le mandat sur l'enveloppe qu'il ouvre : un mandat authentique ne fait pas accepter une enveloppe forgée | 03 §4 | L01 (`crates/synco-e2ee/tests/roundtrip.rs:338`, `:384`) ; L05 (usage d'`accept_delegation`) |
| La passerelle refuse de démarrer sans `SYNCO_ALLOWED_ORGS` non vide | 02 §5 étape 8 | L04 (`Synco_AI_Gateway/src/config.rs:226`, `tests/proxy.rs:464`) |
| La passerelle borne la concurrence (16 au total, 4 par utilisateur) sans appeler Ollama au-delà, et ne relaie que les champs de sa liste blanche | 02 §6 bis | L04 (`Synco_AI_Gateway/tests/proxy.rs:519`, `:569`, `src/relay.rs:152`) |

Invariants **ajoutés après L03c et L05** (révisé après L03c/L05, 2026-11-20), chacun couvert par un test qui
échoue sans la protection (L03c : `synco_api`, sur `574caaf` ; L05 : `synco_ai_runtime`) :

| Invariant | Spécifié dans | Testé par (test existant) |
|---|---|---|
| Un utilisateur banni de la plateforme n'obtient rien du canal même avec une délégation encore active (second verrou **et** contrôle métier), et toutes ses délégations sont révoquées au bannissement (`user_banned`) | 03 §8.1, 04 §3.2 | L03c (`synco_api/src/routes/runtimeInternal/runtimeChannelE2e.test.ts:255`, `:294` ; `runtimeChannelL03.test.ts:286` ; `src/services/aiRuntime/runtimePolicyEnforcement.test.ts:133` ; `src/routes/aiRuntimeBan.test.ts:25`, `:36`) |
| Une enveloppe `rt1` n'est posée qu'**une fois** sur un salon : une enveloppe différente est refusée (`envelope_exists`), y compris en course | 03 §10.1, 04 §4.3 | L03c (`synco_api/src/routes/runtimeInternal/runtimeE2eeWrites.test.ts:288`, `:299`) |
| `user.revoked` est émis après `delegation.revoked`, avec `until` arrondi au supérieur | 02 §8, 04 §6 | L03c (`synco_api/src/services/aiRuntime/delegationService.test.ts:55-70`, `runtimePolicyEnforcement.test.ts:70`) |
| Les délais `awaiting_*` ne peuvent qu'être abaissés par l'org (valeur invalide ou supérieure → 7 j) | 07 §6, 09 §3 | L03c (`synco_api/src/services/aiRuntime/runtimeMaintenance.test.ts:114`, `:129`) |
| Les `events` d'un worker ne sont écrits que si l'écriture qui les porte réussit | 04 §4.2 | L03c (`synco_api/src/routes/runtimeInternal/runtimeChannelL03.test.ts:369`) |
| L'API et la crate partagent la même règle d'URL (vecteurs `urlCases` identiques) | 01 §3 | L03c (`synco_api/tests/vectors/synco-e2ee/vectors.test.ts`) |
| Un mandat neuf signé par une clé de signature retirée est refusé par le runtime | 03 §4 | L05 (`crates/supervisor/src/vault.rs:382`) |
| Le désappairage efface les clés déléguées ; une révocation ou un désappairage pendant le chargement n'installe rien | 03 §9, 01 §9 | L05 (`crates/supervisor/tests/integration.rs:473`, `:673`, `:692`) |
| Le relais `signed_request` refuse tout chemin hors liste et borne débit, taille et requêtes en vol | 06 §4, §4.1 | L05 (`crates/supervisor/tests/integration.rs:638` ; `src/workers.rs:540`) |
| Les connexions WebSocket non authentifiées sont plafonnées (8 par adresse, 256 au total) | 05 §1, 09 §4.1 | L05 (`crates/supervisor/src/server.rs:262` ; `tests/integration.rs:708`) |
| Le runtime refuse tout ticket sans relecture réussie des clés publiques depuis 1 h | 02 §5 | L05 (`crates/supervisor/src/client_ws.rs`, test `cles_de_tickets_perimees_apres_une_heure`) |
| Un flux de notifications d'une autre org est fermé ; les autorisations persistées sont purgées et réconciliées | 04 §6, 03 §9 | L05 (`crates/supervisor/tests/integration.rs:725`, `:748`) |

## 5. Décisions de la porte A (tranchées le 2026-11-18)

Ce tableau **fait foi**. Les analyses d'options des sections suivantes sont conservées pour mémoire ;
partout où la spec écrit « dépend de Dx », appliquer la valeur ci-dessous.

| # | Décision retenue |
|---|---|
| D1 | **Option A** : les clés API des fournisseurs LLM sont dans la configuration du runtime. `GET /api/runtime/v1/llm-policy` ne renvoie aucun secret ; la route `llm-credentials` **n'existe pas** ; `Organization.aiProviderKeys` n'est jamais lu pour le mode runtime. La passerelle est appelée avec un ticket `sgt1`. **Réalisation (L06, 2026-11-20)** : le superviseur est un **mandataire LLM** qui injecte la clé dans la requête du worker ; **aucune trame `llm_credential`** n'est envoyée, la clé ne passe jamais par le pipe (06 §2, 10 §4). URL **et** clé viennent de la seule configuration du runtime (`[llm.providers.<id>]`), jamais d'une URL fournie par l'API ; liste blanche du mandataire : `POST /chat/completions` (`/v1/chat/completions` pour la passerelle) et `GET /models` ; quotas D6 appliqués par le mandataire (10 §4). |
| D2 | **Option A** : la crate vit dans `crates/synco-e2ee` du workspace du runtime, importable par dépendance git. |
| D3 | Licence ajoutée par l'utilisateur (`LICENSE`, commit `cc6e0b9`) : **tous droits réservés**, code publié à des fins de transparence. La crate n'est réutilisable que par les projets de Silvercore ; P8 s'entend dans ce sens. |
| D4 | **Option A** : 7 jours par défaut, renouvellement à l'ouverture de Synco quand il reste moins de 50 % ; maximum réglable par l'admin entre 1 h et 30 jours (09 §1). |
| D5 | **Option A** : politique par outil `auto` / `ask` / `deny`, défaut selon le niveau de risque (affiné par L14 à la porte E) ; `ask` → `awaiting_confirmation` + notification ; délai 7 jours puis `failed` (`confirmation_timeout`). |
| D6 | Valeurs proposées en 09 §2 **adoptées**, à réviser après les mesures de L06 ; l'org peut les abaisser, jamais les relever. **Révisée le 2026-11-21 (porte C, PC12, Q22 tranchée) : `memory.high` retiré, `memory.max` seul** (09 §2, 10 §5). Le code du superviseur écrit encore `memory.high = max` et lit `worker_memory_high_mib` (ignoré) : nettoyage dans un lot du superviseur, **ouvert** (journal, L07c). Les quotas d'appels et de tokens sont appliqués par le mandataire LLM du superviseur (10 §4). |
| D7 | **Option A** : le régime `server` est conservé tel quel. |
| D10 | **Option A** : pas de relais par l'API en v1 ; mode dégradé de 05 §9 ; le runtime doit présenter un certificat TLS reconnu par les navigateurs (Q7) ; **pas de TLS natif en v1 : mandataire inverse obligatoire** (décision de l'orchestrateur, L05 ; 01 §3). |

Questions du §6, réponses de la porte A : **Q1** clé par conversation `CK`, `AiSessionKey` jamais
déléguée (accepté) ; **Q2** affichage du signataire et de l'empreinte avant la première délégation,
sans exiger la signature du propriétaire, risque résiduel documenté ; **Q3**, **Q4** (lecture actuelle :
`exp` dans l'enveloppe de tête et le mandat), **Q5**, **Q6**, **Q7**, **Q8**, **Q10** : propositions de
cette spec acceptées ; **Q9** : les documents du dossier de projet sont corrigés (séparateur `:`).

### Décisions du point d'étape B (tranchées le 2026-11-19)

| # | Décision retenue |
|---|---|
| Q11 | **Option B** : la signature `rt1` d'un salon créé par le runtime est posée **après** sa création, par une route dédiée du canal (forme fixée par L03c) ; entre la création et la pose, le salon reste accepté en TOFU par les clients. |
| Q12 | **Option A** : l'API applique la règle d'URL canonique de la crate (vecteurs partagés) ; `http://localhost\|127.0.0.1:<port>` seulement derrière une variable de développement de l'API. |
| Q13 | **Option A** : l'API émet `user.revoked` à chaque révocation de toutes les délégations d'un utilisateur. |
| Q14 | (a) **Option A** : délais `awaiting_*` réglables par l'org dans `aiConfig.runtime.limits` (abaissables seulement). (b) **Option B** : baisser `maxDelegationDays` n'écourte pas les délégations existantes ; elles courent jusqu'à `exp` (≤ 30 j), à documenter dans l'écran admin (L11). |
| Q15 | **Option A** : champ facultatif `events: [{ type, code? }]` (`tool_unknown_outcome`, `lease_lost`) dans `PUT …/transcript` et `POST …/status`. |
| Q16 | (a) à (e) **ratifiés** tels que décrits en §6. |
| Q17 | **Option C** : au bannissement d'un utilisateur, ses délégations sont révoquées (raison `user_banned`) **et** le second verrou refuse tout utilisateur banni (`auth_invalid`). |

### Décisions de la conception C1 (tranchées le 2026-11-21, figées par L00f dans 12)

| # | Décision retenue | Où |
|---|---|---|
| PC34 | **Plan d'action** : l'agent ne signe plus ; il établit un plan, que l'appareil de l'utilisateur exécute en son nom après acceptation dans l'app | 12 §1 à §9 |
| PC35 | Deux modes : **plan** par défaut ; **autonome** en option, activé par l'utilisateur, où le runtime signe avec **sa** clé sous mandat (jamais la clé de l'utilisateur) ; PC31 à PC33 (L03f, L08c) maintenus pour ce mode | 12 §10, 03 §4.1 |
| PC36 | Politique d'org des fonctionnalités IA « pratiques mais moins sûres » : tout le monde / personne / personne sauf ; activation par l'utilisateur avec avertissement ; sélection par recherche | 12 §11 |
| PC37 | Acceptation **partielle**, cascade sur les actions dépendantes montrée avant validation | 12 §6 |
| PC38 | Les outils serveur `ask` passent aussi par le plan ; verrou API **`action_not_accepted`** | 12 §2, §8.3 |
| PC39 | `autonomous_mode` sur **personne** par défaut, administrateurs compris (exception visible et journalisée) ; activation individuelle | 12 §11.1, §11.6 |
| PC40 | Retrait du mode autonome : délégation `auto` révoquée aussitôt, conversations **en pause**, reprise en mode plan | 12 §11.4, 08 §2.2 |
| PC41 | `folder.create` et `file.create_text` (appareil) en v1, livrés juste après `thread.create` ; règle PC6 | 12 §4 |
| PC42 | Politiques v1 : `autonomous_mode`, `runtime_mode` (existant repris), `tool_auto_accept` (« toujours accepter » jamais pour un outil sensible) ; les autres **réservées** | 12 §11.1 |
| PC43 | Un format jamais livré n'a pas à être relu (le mandat v1, livré, reste lu ; l'ancien `created_threads.json` de L08b ne l'est plus) | 03 §4.1 |

Le reste de C1 (mandat v2 avec `mode`, `AiActionPlan`, éléments `plan_decision` / `plan_result`, route
d'enveloppe du créateur, `autonomy.allowed`) est repris tel quel dans 12.

### Décisions sur les questions de L00f (tranchées le 2026-11-21 après la livraison de L00f, 12 §15)

| # | Décision retenue | Où |
|---|---|---|
| PC44 | QP1 : **ordre libre** dans un plan mixte (contraire de la recommandation « appareil d'abord ») : phases alternées appareil / agent selon le graphe de dépendances ; une action d'appareil peut dépendre d'une action d'agent ; chaque phase d'appareil se clôt par un `plan_result:<k>` partiel ; l'agent reprend après chaque phase et signale la suivante (`plan_agent_result:<k>`, push) ; app ouverte pour chaque phase d'appareil, sinon le plan attend, et `expiresAt` vaut pour le plan entier ; une phase est réservée par un seul appareil. *Amendé* : arrêt sur échec remplacé par PC54, phases précalculées par des phases dynamiques (PC58) | 12 §1, §5, §7, §8.1 à §8.3, §9, §12 ; 04, 07, 08 |
| PC45 | QP3 : pause au retrait comme recommandé : autorisations conservées, `queued` / `running` → `awaiting_key` (`delegation:<runtimeId>`), reprise au dépôt suivant, `key_timeout` | 12 §11.4, 03 §8.1, 07 §9, 08 §2.2 |
| PC46 | QP4 : l'empreinte `ownerRsaSpkiHex` du mandat v2 vérifié prime sur l'épingle TOFU ; écart → `409 member_key_changed` et alerte ; v1 : TOFU actuel | 12 §10.3, 03 §4.1 |
| PC47 | QP2 : condensat de `JCS({tool, args, argsRefs})` (`argsRefs` omis s'il est absent) ; l'appel porte `args` non résolus et `refs` résolues ; l'API vérifie le condensat puis chaque `ref` contre la sortie qu'elle a enregistrée en créant l'objet (en-tête `X-Synco-Plan` pour l'appareil), sans rien lire de chiffré | 12 §8.4, §8.5 ; 04 §5, 07 §10 |
| PC48 | QP5 : détails ratifiés tels quels, sauf `AiFeaturePolicyEvent` **conservé 1 an** avec une purge bornée (RGPD) | 12 §15, 07 §9, §10, 09 |

### Second amendement du plan d'action (tranché le 2026-11-21, 12 §15)

| # | Décision retenue | Où |
|---|---|---|
| PC54 | **Échec** : seules les dépendantes transitives (`after`, qui couvre `argsRefs`) de l'action en échec sont ignorées ; les actions indépendantes continuent, dans toutes les phases (remplace l'arrêt total du premier amendement) | 12 §7.1, §7.3 ; 04, 07, 08 |
| PC55 | **Message pendant un plan accepté** : le plan continue, le message est traité au tour qui suit la clôture de `propose_actions` ; arrêt explicite par la route « Arrêter le plan » (`POST …/plans/:planId/stop`, statut `stopped`, élément `plan_decision` `stop`) | 12 §8.6, §9, §12.1 ; 07, 08 |
| PC56 | **Lien objet ← plan / action** (`X-Synco-Plan`, colonne `output`) : conservé le temps du plan, effacé à la clôture, purge bornée de rattrapage ; inscrit au catalogue RGPD | 12 §8.5 ; 07 §9, §11 |
| PC57 | **Mode autonome** : l'absence de recontrôle API des `refs` du `thread.create` autonome est un risque accepté | 12 §8.4, §10.6, §15 |
| PC58 | **Graphe et parallélisme, façon GitHub Actions** : `after` = `needs`, `groups` de présentation, `category.create` et `categoryId` ; actions prêtes exécutées en parallèle (concurrence 4, maximum 8, des deux côtés), `429` réessayé 3 fois ; consigne au modèle ; présentation en graphe par niveaux (repli en liste sur mobile). **Ajustement de PC44** : phases dynamiques (séances par exécutant qui peuvent se chevaucher) au lieu de phases précalculées strictement alternées | 12 §3, §4, §8.1 à §8.3, §8.7, §17 ; 04, 07, 08, 09 |
| PC59 | `category.create` et `categoryId` sur `thread.create` validés | 12 §4 |
| PC60 | Concurrence 4 par défaut, 8 au plus ; 3 nouveaux essais sur `429` : validés | 12 §8.7, 09 |
| PC61 | Plan de **100 actions** au plus (était 20) ; 2 000 dépendances, clair ≤ 256 Kio, corps de `POST …/plans` ≤ 1 Mio ; au-delà, l'agent découpe en plusieurs plans (`plan_too_large`, consigne de 12 §3.1) ; groupes repliés par défaut au-delà de 30 actions | 12 §3, §5, §12.2, §14, §17 ; 04, 07, 09 |
| PC62 | Un plan accepté qui expire relance la conversation pour un bilan : validé | 12 §7.1, 08 |
| PC69 | **Empreintes à la décision** : pour chaque action serveur acceptée, la décision porte l'empreinte recalculée par l'app depuis le plan déchiffré ; l'API refuse toute empreinte différente de `serverDigests` (`409 plan_digest_mismatch`) ; `serverDigests` exposé dans la vue du plan | 12 §8.4, §12.1, §14 |
| PC70 | **`cancel` pendant un plan accepté** vaut `stop` du plan (plus de nouvelle action, `executing` jusqu'au terme, bilan, messages plus retenus après l'arrêt) | 12 §7.1, §8.6 |

## 5 bis. Analyse des décisions (pour mémoire)

Les décisions D4 et D6 sont traitées dans [09-limites-et-valeurs-par-defaut.md](09-limites-et-valeurs-par-defaut.md).
Les autres sont présentées ici. La spécification est écrite pour **tenir quel que soit le choix** ; les
passages qui en dépendent sont marqués « dépend de Dx ».

### D1 — Où vivent les clés API des fournisseurs LLM utilisées par le runtime ?

| Option | Effet sur la spec |
|---|---|
| **A. Dans la configuration du runtime** (recommandée) | La route `GET /api/runtime/v1/llm-policy` (04 §4) ne renvoie que la **politique** de l'org (fournisseurs et modèles autorisés, `reasoningEffort`), jamais de secret. Le superviseur lit ses propres clés et les passe au worker dans la partie binaire de `init` (06 §3), ou, si L06 choisit un proxy réseau du superviseur, ne les passe pas du tout et les injecte lui-même dans les requêtes sortantes. `Organization.aiProviderKeys` n'est jamais lu pour le mode runtime. |
| B. Dans Synco (`aiProviderKeys`), transmises au runtime | Ajouter la route `GET /api/runtime/v1/llm-credentials` (signée, sans autorisation de session, réservée au runtime de l'org), qui renvoie les clés déchiffrées par `prisma-field-encryption`. La clé API transite alors par Synco à chaque démarrage du runtime : Synco reste dépositaire d'un secret qui sert hors de Synco. |
| C. Les deux (runtime prioritaire, repli sur Synco) | A + B, avec un champ `source` dans la politique. Double surface. |

Dans tous les cas, la passerelle est appelée avec un ticket `sgt1` (02 §4) obtenu par le runtime pour
l'utilisateur (route `POST /api/runtime/v1/tickets/llm`), pas avec une clé.

**Recommandation** : A. C'est cohérent avec P1 (tout est chez le client) et retire un secret des mains
de Synco.

### D2 — Emplacement de la crate `synco-e2ee`

| Option | Effet sur la spec |
|---|---|
| **A. Workspace du runtime** `crates/synco-e2ee` (recommandée) | Chemins de [vectors/README.md](vectors/README.md) : `crates/synco-e2ee/tests/vectors/`. Import ailleurs par dépendance git sur le dépôt public. |
| B. Dépôt dédié | Seuls les chemins des vecteurs et la ligne `[dependencies]` des crates du runtime changent. Les formats ne changent pas. |

**Recommandation** : A, extraction plus tard si un second projet s'en sert. Aucun format n'en dépend.

### D3 — Licence du dépôt public `synco_ai_runtime` et de la crate

Aucun format n'en dépend. Sans fichier `LICENSE`, le dépôt est « tous droits réservés » : un tiers peut
le lire mais ni le réutiliser ni le modifier, ce qui limite l'intérêt d'une crate « réutilisable » (P8)
et l'audit par les clients. **Pas de recommandation** (choix de l'utilisateur) ; si la crate doit
pouvoir être importée par d'autres projets, il faut une licence explicite au moins pour elle.

### D5 — Politique de confirmation des outils mutants en l'absence de l'utilisateur

La spec prévoit dès maintenant :

- un champ `toolPolicy` (outil → `auto` | `ask` | `deny`) dans la politique runtime de l'org (07 §6),
  transmis au worker dans `init` (06 §3) ;
- l'état `awaiting_confirmation` et le message `confirm` (05 §5), qui fonctionnent quelle que soit la
  politique ;
- la notification push `AI_AWAITING_CONFIRMATION` (07 §7).

| Option | Effet sur la spec |
|---|---|
| **A. Par outil, défaut par niveau de risque** (recommandée) | `toolPolicy` rempli par L14. `deny` → le worker répond à l'appel par le résultat chiffré `{"error":"tool_denied_by_policy"}` sans exécuter. |
| B. Tout `ask` | `toolPolicy` vide ; tout outil `mutating` passe par `awaiting_confirmation`. |
| C. Tout `auto` | Supprime l'état `awaiting_confirmation` du mode runtime ; risque fort (une injection de prompt agit sans contrôle). Non recommandé. |

Délai d'attente d'une confirmation : 09 §3 (proposition : 7 jours, puis `failed` avec
`confirmation_timeout`). **Recommandation** : A.

### D7 — Conserver le régime `server` actuel ?

| Option | Effet sur la spec |
|---|---|
| **A. Oui, inchangé** (recommandée) | Les statuts historiques (`idle`, `awaiting_confirmation`, `awaiting_client_tool`) restent écrits par `aiTurnRunner.ts` pour le régime `server` (08 §2). Les routes `/ai/chat` restent. Une conversation `server` peut basculer en runtime (03 §6.4). |
| B. Retirer le régime `server` | Les conversations `server` existantes restent lisibles (formats rétrocompatibles) ; la bascule vers le runtime devient le seul moyen de les continuer avec OpenAI/Mistral/Gemini sans runtime → une org sans runtime perd ces fournisseurs. La machine à états de 08 ne change pas. |

**Recommandation** : A (le runtime est une option, P4).

### D10 — Relais par l'API pour les clients qui ne joignent pas le runtime

| Option | Effet sur la spec |
|---|---|
| **A. Hors v1** (recommandée) | Mode dégradé décrit en 05 §9 : historique en lecture seule depuis l'API, envoi de messages par l'API (file d'attente, 04 §4) qui réveille le runtime ; pas de flux en direct. |
| B. Relais en v1 | L'API ouvrirait un WebSocket vers le runtime et relaierait les trames. La spec le permet **sans changer le chiffrement** : tous les champs sensibles des trames sont déjà chiffrés par `CK` (05 §4), l'API ne verrait que des métadonnées (types, tailles, rythme). Il faudrait un ticket `srt1` avec `via:"api"` et un en-tête de relais signé. Contredit l'intention de P6 (« l'API ne relaie pas le flux ») : à trancher explicitement. |

**Recommandation** : A, et documenter que le runtime doit être joignable en HTTPS par les navigateurs
des membres (certificat TLS reconnu par les navigateurs, cf. question Q7 ci-dessous).

## 6. Questions et tensions relevées pour la porte A (révisé après la vague B, 2026-11-19 ; révisé après L03c/L05, 2026-11-20 ; révisé après la porte C et L03d, 2026-11-21)

| # | Point | Proposition de cette spec |
|---|---|---|
| Q1 | P5 cite « la clé IA » (`AiSessionKey`) parmi les clés déléguées. Or cette clé est **partagée par toute l'org** (`AiSessionKey`, contexte `ai:<orgId>`, `AiSessionKeyService.ts:106`) : la déléguer donnerait au runtime de quoi lire toutes les conversations `gateway` de tous les membres que l'API lui servirait. | Une **clé par conversation** `CK` (03 §6) ; `AiSessionKey` n'est **jamais** déléguée en v1. Les anciennes conversations `gateway` basculées vers le runtime sont rechiffrées par le client sous une nouvelle `CK`. C'est plus restrictif que P5 (« seulement » est une borne haute), mais c'est un choix de format à confirmer. |
| Q2 | Le statut d'admin vient de l'API. Le client vérifie la signature du certificat avec la clé épinglée de l'admin, mais ne peut pas prouver que ce membre **est** admin. Une API malveillante alliée à un membre (ou à un compte de membre compromis avec ses clés) peut faire certifier un faux runtime. | Le client affiche à chaque utilisateur, avant sa première délégation, **qui** a signé le certificat et l'empreinte (01 §7). Variante plus stricte à trancher : exiger la signature du **propriétaire** de l'org (`Organization.ownerId`) — même limite (l'API désigne le propriétaire), mais un seul signataire possible. |
| Q3 | Le runtime vérifie les mandats avec la clé de signature de l'utilisateur, qu'il ne peut obtenir **que** par l'API. | Épinglage TOFU côté runtime + suivi de la chaîne de transitions d'identité (03 §4). Une API malveillante dès le premier contact peut tromper le runtime : même limite que le TOFU des clients, à documenter. |
| Q4 | Mesure 5 : « l'AAD de chaque enveloppe de délégation contient … l'expiration ». | L'expiration est dans l'AAD de l'**enveloppe de tête** et dans le **mandat signé** ; les entrées ne l'ont pas, elles sont liées à la délégation par `delegationId` et par `DK`, qui n'est obtenable que par l'enveloppe de tête (03 §5). Mettre `exp` dans chaque entrée imposerait de tout rechiffrer à chaque renouvellement, ce que la spec fait de toute façon (03 §7) : l'alternative est donc possible à coût nul si la porte A préfère la lecture littérale. |
| Q5 | Clés créées par le runtime (outil `create_thread`) : les clients actuels vérifient l'enveloppe FC4 avec la clé du **créateur** ; le runtime n'a pas la clé d'identité de l'utilisateur. | Créateur `rt1:<delegationId>`, signature par la clé `csk` du runtime, chaîne vérifiable par le mandat de l'utilisateur (03 §10). Les clients actuels ne connaissent pas ce créateur et retombent sur le TOFU (`keyEnvelope.ts:132-137`) : compatible, mais sans vérification tant que l'app n'est pas mise à jour. À noter : aujourd'hui, `createThreadHelper` (`OrgAI.vue:495`) ne signe **aucune** enveloppe pour les salons créés par l'IA. |
| Q6 | `search_messages` s'appuie sur l'index chiffré et sur un modèle d'embedding exécuté dans le navigateur (`Xenova/paraphrase-multilingual-MiniLM-L12-v2`, `semantic.worker.ts:10`). | Le runtime devra calculer des vecteurs compatibles (même modèle) pour chercher : à traiter par L07/L14. Le canal interne prévoit la lecture de l'index dans le périmètre (04 §4). **Réalisation (L07, 2026-11-20)** : `search_messages` est en **repli lexical** sur les index déchiffrés ; le modèle d'embedding ne peut pas tourner dans le bac à sable (ni fichier, ni réseau, ~120 Mio de poids, aucun moteur ONNX). **Question ouverte** : Q24. |
| Q7 | « Runtime limité à l'intranet » et navigateurs : le client parle **directement** au runtime en `wss://`. Il faut un certificat TLS reconnu par les navigateurs et les applis mobiles des membres, et un CORS limité à l'origine de l'app. | Documenté ; lié à D10. Un certificat auto-signé ne fonctionnera pas dans les navigateurs. **Révisé après L05, 2026-11-20** : le runtime ne termine pas TLS ; un mandataire inverse obligatoire présente le certificat (01 §3). |
| Q8 | La bascule d'une conversation `client` (blob RSA `isE2EE`, `AIService.ts:917-927`) ou `server` (clair) vers le runtime impose de **réécrire l'historique** au format `StoredMessage[]` chiffré par `CK`. | Conversion par le client à la bascule (03 §6.4) ; la conversion depuis le format d'affichage du régime `client` est à valider par L11. L'historique `server` a déjà été vu en clair par l'API : le rechiffrer protège la suite, pas le passé. |
| Q9 | Doc vs code : `02_architecture.md` et `03_securite.md` décrivent l'AAD des champs `gcm1:` comme `session|message|champ`. Le code utilise `:` (`crypto.rs:64-66`, `synco_app/src/assets/utils/crypto.ts:963`). | La spec suit le **code** (`:`). Les documents du dossier de projet sont à corriger. |
| Q10 | Le runtime doit-il apparaître dans la liste des appareils de l'utilisateur (paramètres E2EE v4) ? | Non en v1 (ce n'est pas un `UserDevice`) ; il apparaît dans *Paramètres → Synco AI → Runtime* avec l'état de la délégation. À confirmer côté produit. |

### Questions ouvertes après la vague B (ajoutées le 2026-11-19 ; **tranchées au point d'étape B, appliquées par L03c le 2026-11-20** ; analyses conservées pour mémoire)

Statut (révisé après L03c, 2026-11-20 ; source : `synco_api/vibe/features/SYNCOAI_REFONTE_FEATURE.md` §13) : **Q11 à Q17 sont
tranchées (§5) et appliquées par L03c** — Q11 = B (route `key-envelope`, 04 §4.3), Q12 = A (règle d'URL de la
crate, 01 §3), Q13 = A (`user.revoked` émis, 02 §8), Q14 (a) = A (délais réglables, 09 §3) et (b) = B (aucun
changement de code, 09 §1), Q15 = A (`events`, 04 §4.2), Q16 ratifiée sans changement de code, Q17 = C
(03 §8.1). La colonne « Options » ci-dessous est l'analyse d'origine ; le texte des documents 01 à 09 fait foi.

| # | Point | Options et impact (aucune n'est choisie ici) |
|---|---|---|
| Q11 | **(appliquée par L03c)** **Signature `rt1` d'un salon créé par le runtime** (03 §10, 04 §4.3). L'enveloppe `rt1` signe `ctx = thread:<threadId>`, mais l'id du salon est tiré par l'API pendant `POST /e2ee/threads` : le runtime ne peut pas le signer d'avance. Aujourd'hui la route accepte `commitment` / `signature` (ensemble ou absents) mais le runtime ne peut pas les produire pour le bon `ctx` : le salon est accepté en **TOFU** par tous les clients, comme les salons créés par l'IA dans l'app actuelle (`CreateNewThread.vue`, `OrgAI.vue` n'envoient pas de `commitment`). L'invariant « clé créée par le runtime vérifiable par les clients à jour » (§4) n'est donc pas tenu pour ce cas. | **A. Le runtime propose l'id, validé par l'API** (recommandée par l'orchestrateur) : `POST /e2ee/threads` reçoit un champ `id` (conforme à 00 §3.2, de la forme des ids de salon) tiré par le runtime ; l'API refuse un id mal formé ou déjà pris (`409`) et crée le salon sous cet id ; le runtime signe `thread:<id>` avant l'appel ; une seule requête, aucune fenêtre sans signature. Impact : le service partagé `createThread` doit accepter un id injecté (réservé au canal, la route HTTP reste inchangée) ; nouveau champ et nouveau code dans 04 §4.3 ; vecteur `rt1` sur un id choisi (L01) ; L07 tire l'id. **B. Route de pose a posteriori** : nouvelle route S+A (bail exigé), par exemple `POST /e2ee/threads/:threadId/key-envelope { commitment, signature }`, qui pose l'enveloppe sur les `ThreadKey` de `creatorId = rt1:<délégation de l'autorisation>` encore sans `commitment`, sans jamais en écraser une. Impact : une route de plus dans la liste fermée ; deux requêtes, donc un état intermédiaire (salon créé non signé) en cas d'échec ; entre les deux, un client peut charger la clé et l'épingler en TOFU sans vérification, puis voir apparaître une enveloppe qu'il n'a pas vérifiée à la première vue. |
| Q12 | **(appliquée par L03c)** **URL canonique : la règle de l'API diffère de celle de la crate** (01 §3). `canonicalRuntimeUrl` (`synco_api/src/services/aiRuntime/runtimeFormats.ts:41-54`) accepte des URL que `canonical_runtime_url` refuse (IPv6, `_` dans l'hôte, `//` et ponctuation dans le chemin) et refuse tout `http`, même sous drapeau de développement. | A. Porter la règle de la crate dans l'API (même algorithme, vecteurs d'URL partagés), avec `http://localhost|127.0.0.1:<port>` admis seulement derrière une variable de développement de l'API. Impact : une validation de plus dans `runtimeRegistry.ts`, vecteurs à ajouter (L01/L02). B. Laisser l'écart : l'API n'est pas une autorité, le client refuse ; coût : un certificat accepté par l'API puis refusé par tous les clients (runtime inutilisable jusqu'à recertification), et pas d'appairage `http` de développement de bout en bout. |
| Q13 | **(appliquée par L03c)** **`user.revoked` n'est jamais émis** (02 §8, 04 §6) : la liste de révocation des tickets du runtime n'est alimentée que par `conversation.revoked`. | A. Émettre `user.revoked` `{ userId, until = maintenant }` à chaque révocation de toutes les délégations d'un utilisateur (départ, membre non autorisé, révocation par l'utilisateur ou l'admin) : un ticket `srt1` émis avant est refusé même pour une conversation encore inconnue du runtime. Impact : appels à ajouter dans `delegationService.ts`, aucun changement de format. B. Retirer `user.revoked` de la spec : `delegation.revoked` + `conversation.revoked` suffisent, puisque le runtime exige à la connexion une autorisation connue (05 §1 étape 4) et que l'autorisation est révoquée avec la délégation. Impact : 02 §8 et 04 §6 à simplifier ; le runtime doit alors garantir qu'il n'accepte aucun WebSocket sans autorisation active connue. |
| Q14 | **(appliquée par L03c)** **Limites de la politique de l'org non appliquées** : (a) les délais `awaiting_*` sont fixes à 7 jours, alors que 09 §3 les dit réglables par l'org ; (b) baisser `maxDelegationDays` n'écourte pas une délégation existante ; (c) le bannissement d'un **utilisateur** (et non de l'org) : voir Q17. | (a) A : ajouter un champ de délai à `aiConfig.runtime.limits` (07 §6), lu par la maintenance ; B : retirer « (org) » de 09 §3. (b) A : à l'enregistrement de la politique, révoquer (raison à créer, par exemple `policy_shortened`) les délégations dont `exp − iat` dépasse le nouveau maximum ; B : laisser courir jusqu'à `exp` (≤ 30 j) et le documenter dans l'écran admin. (c) : Q17. |
| Q15 | **(appliquée par L03c)** **Journal `tool_unknown_outcome` et `lease_lost`** (07 §5, 08 §5) : aucune route du canal ne permet au runtime d'écrire un `AiChatSessionEvent`. | A. Champ facultatif `events: [{ type, code? }]` (types limités à `tool_unknown_outcome`, `lease_lost`) dans `PUT …/transcript` et `POST …/status`. B. L'API déduit `tool_unknown_outcome` du clair de l'historique (`toolCalls[i].status` passé d'`executing` à `error` sous un autre `leaseEpoch`) et journalise `lease_lost` quand elle reprend un bail expiré. C. Retirer ces deux types de 07 §5 (journal tenu par l'API seule). |
| Q16 | **(appliquée par L03c)** **Écarts mineurs reportés tels quels, à ratifier** : (a) le désappairage clôt le bail sans incrémenter `leaseEpoch` (01 §9 ; protection équivalente, mais contraire à la règle commune de 08 §2) ; (b) `awaitingKey` n'admet que `thread` et `space`, pas `conv` (04 §4.2) ; (c) ajout d'entrées par le client limité à 3 / 15 s au lieu de 1 / 5 s (09 §4.1) ; (d) le dépôt dans la boîte prend la trame **sans `v`** (05 §5.4, §6.2) ; (e) `POST /register` ne compare pas l'URL envoyée à celle du certificat (01 §7). | Proposition : ratifier (a) à (e) tels que décrits ; sinon, chaque point est une modification locale du code de L02/L03 sans changement de format chiffré. |
| Q17 | **(appliquée par L03c)** **Utilisateur banni de la plateforme** (`User.bannedAt`, `POST /api/admin/users/:id/ban`, `synco_api/src/routes/admin.ts:440`) : ses requêtes à lui sont refusées par `banMiddleware`, mais le canal interne n'y passe pas (requêtes du runtime) et ni le second verrou (`runtimeAuth.ts:392-394`) ni `loadAuthorizedConversation` ne lisent `User.bannedAt` ; ses délégations ne sont pas révoquées (hors périmètre de M2, `SYNCOAI_REFONTE_FEATURE.md` §12.3). Le runtime peut donc continuer d'agir pour lui jusqu'à `exp` (≤ 30 j). | A. Révoquer ses délégations au bannissement (`revokeDelegations(ctx, { userId }, <raison à créer, par exemple user_banned>)`, appel dans `admin.ts`) et passe de maintenance en filet. B. Ajouter `User.bannedAt` à l'étape 4 du second verrou (`auth_invalid`) sans révoquer (accès rétabli à la levée du bannissement). C. A + B. Impact commun : test qui échoue sans la protection ; pour A, nouvelle valeur de `revokedReason` (07 §3). |

### Questions ouvertes après L03c et L05 (ajoutées le 2026-11-20 ; **Q18, Q19, Q20 et Q21 tranchées à la porte C (2026-11-21) et appliquées par L03d**)

Statut (2026-11-21 ; source : `synco_api/vibe/features/SYNCOAI_REFONTE_FEATURE.md` §14) : **Q18** = A (PC18,
route `GET /authorizations?state=active`, 04 §4.1) ; **Q19** = A (PC21, plancher de 1 h, 09 §3, 07 §6) ;
**Q20** (PC22) = rétention de 90 jours des `AiChatSessionEvent`, autres limites documentées sans code
(07 §5) ; **Q21** (PC23, PC26) = réinitialisation par un humain puis nouvelle pose par le runtime créateur
(03 §10.1, 04 §4.3, 04 §6). Autres décisions de L03d : **PC16** `provider_not_configured` (Q30, 08 §6) ;
**PC17** `displayName` (04 §4.1, 11 §5) ; **PC19** limiteur de la synchro des clés (09 §4.1) ;
**PC5** (Q23, 04 §4.3). **`user.revoked` n'est pas émis à l'expiration d'une délégation** (PC24 :
inchangé ; Q13 = A ne le fait émettre que pour les révocations, 02 §8). Le **côté API** est livré ; l'**adoption
par le runtime** (appel de la route Q18, traitement de `thread.envelope_reset`, `displayName`, code
`provider_not_configured`) reste **ouverte** (relu dans le code, 04 §4). Les analyses d'origine sont
conservées ci-dessous pour mémoire.

Relevées pendant le report de L03c et L05 dans cette spécification. Aucune n'est choisie ici ; chaque
point est une limite connue du code livré, sans changement de format chiffré.

| # | Point | Options et impact (aucune n'est choisie ici) |
|---|---|---|
| Q18 | **(tranchée = A à la porte C, PC18 ; route livrée par L03d ; adoption par le runtime ouverte)** **Route « autorisations actives de l'org pour ce runtime »** (03 §9). Le runtime persiste les autorisations de session connues (`authorizations.json`, données publiques) pour qu'un client d'une conversation `idle` ne soit pas refusé après un redémarrage (`GET /conversations?state=pending` ne liste pas les `idle`). Il les réconcilie à chaque ouverture du flux par un `GET /conversations/:sessionId` **par conversation** (`crates/supervisor/src/runtime.rs`, `reconcile_authorizations`), faute de route de liste (`docs/journal.md`, L05, correction 9). | A. Ajouter à la liste fermée (04 §4.1) une route S, par exemple `GET /authorizations?state=active`, qui renvoie `{ sessionId, userId, authId }[]` des autorisations actives de l'org pour ce runtime : un seul appel par reconnexion du flux ; impact : une route, un test de périmètre (L03), 04 §4.1 ; le runtime remplace la boucle par un appel. B. Garder la réconciliation par conversation : aucun changement d'API ; coût : un appel signé par conversation connue à chaque reconnexion (borné par le débit de 50 / s, 04 §2.3). C. Ne plus persister les autorisations : un client d'une conversation `idle` reçoit `4403` après un redémarrage tant que l'API n'a pas renvoyé `conversation.authorized` ; impact : contredit le besoin signalé par L05. |
| Q19 | **(tranchée = A à la porte C, PC21 : plancher de 1 h, appliqué par L03d)** **Minimum des délais `awaiting_*`** (07 §6, 09 §3). `confirmationTimeoutSecs` et `keyTimeoutSecs` admettent tout entier ≥ 1 : une org (ou un administrateur) peut fixer 1 s et faire échouer toute attente de confirmation ou de clé à la passe de maintenance suivante (relecture M3 de L03c, `SYNCOAI_REFONTE_FEATURE.md` §13.6 bis, marquée « question ouverte pour l'utilisateur »). | A. Fixer un minimum, par exemple 1 h, dans la normalisation (`normalizeAiConfig`) : valeur inférieure → défaut ou minimum à choisir. B. Laisser ≥ 1 s : c'est le choix de l'admin de l'org, et la passe de 60 s limite la résolution. |
| Q20 | **(tranchée à la porte C, PC22 : rétention de 90 jours appliquée par L03d ; `lease_lost` écrit par le worker suivant et M5 laissés tels quels, documentés)** **Journal `lease_lost` et rétention** (07 §5, 08 §5). Les `events` du worker exigent le bail courant : un worker qui a perdu son bail ne peut pas écrire son propre `lease_lost` ; seul le worker suivant le constate. Les `AiChatSessionEvent` n'ont aucune rétention (supprimés avec la conversation). Voir aussi M5 : un utilisateur banni peut obtenir un ticket `sgt1` jusqu'à 15 s après si la révocation au bannissement a échoué (03 §8.1). (`SYNCOAI_REFONTE_FEATURE.md` §13.6 bis, M4 et M5.) | A. Laisser tel quel et le documenter (état actuel). B. Faire écrire `lease_lost` par l'API quand elle reprend un bail expiré (ancienne option B de Q15) ; ajouter une purge des événements anciens à la maintenance (durée à fixer). C. Ajouter `loadAuthorizedConversation` à `POST /tickets/llm` pour fermer la fenêtre de M5. |
| Q21 | **(tranchée à la porte C, PC23 / PC26 : solution C + nouvelle pose, API livrée par L03d ; adoption par le runtime et l'app ouverte)** **Enveloppe `rt1` fausse : aucune voie de reprise** (03 §10.1, désormais décrite avec sa réparation). L'API ne vérifie pas `commitment` (elle n'a pas la clé du salon) et la pose est définitive (`envelope_exists`) : un runtime bogué qui pose une enveloppe correctement signée mais avec un engagement faux rend la clé du salon refusée par tous les clients à jour, sans moyen de réparer en v1 sauf intervention en base (`SYNCOAI_REFONTE_FEATURE.md` §13.3, « Limite inhérente à l'option B »). | A. Accepter la limite (état actuel), en couvrant le risque par les vecteurs de L01 et les tests de L07. B. Autoriser le **remplacement** d'une enveloppe `rt1` par le même créateur tant qu'aucun client ne l'a épinglée (à définir) ; impact : route et règle de plus. C. Réparation par un administrateur (suppression de l'enveloppe, nouvelle pose) ; impact : route admin, journalisation. |

### Questions ouvertes après L06, L07, L07b et L08 (ajoutées le 2026-11-20 par L00d ; **Q22, Q23, Q25, Q26, Q27, Q28 et Q30 tranchées à la porte C, 2026-11-21**)

Statut (2026-11-21 ; source : `suivi.md` PC5, PC8, PC9 à PC12, PC16, PC27 ; `docs/journal.md`, L07c, L05b,
L03d) : **Q22** = D6 révisée, `memory.high` retiré (PC12) ; **Q23** = catégorie par défaut et membres d'un
espace sur le canal, livrés par L03d (PC5), adoption par le worker ouverte ; **Q25** = épinglage par le
superviseur (PC8, réalisé par L05b), décisions de PC27 reportées sous Q25 ; **Q26** (PC9), **Q27** (PC10),
**Q28** (PC11) réalisées par L07c ; **Q30** = code ajouté (PC16, L03d). **Q24** (PC7) et **Q29** (PC13 à PC15) : décisions reportées dans leurs lignes ci-dessous.

Reportées depuis `docs/journal.md` (L06 à L08) ; chacune est une limite connue du code livré ou un
choix remonté à l'utilisateur. Aucune n'est choisie ici ; les renvois pointent vers le texte qui décrit
l'état **actuel**.

| # | Point | Où c'est décrit |
|---|---|---|
| Q22 | **(tranchée le 2026-11-21, PC12 : `memory.high` retiré, `memory.max` seul ; D6 révisée, §5)** **`memory.high` (D6)**. Sans espace d'échange (exigé pour qu'aucune clé n'aille sur disque), `memory.high` ralentit un worker indéfiniment au lieu de le tuer (essai : vivant après 120 s, 5 141 évènements `high`, aucun OOM). Le code écrit `max` et ignore `worker_memory_high_mib` (avertissement de `--check-config`). La recommandation (retirer `memory.high` de D6, garder `memory.max`) a été **adoptée**. Reste à nettoyer dans le code du superviseur (`sandbox/cgroup.rs`, `launcher.rs`, `cli.rs`, `config.rs`, `workers.rs`, `sandbox/mod.rs`, `tests/sandbox.rs`, exemple TOML) : **ouvert**, lot du superviseur non planifié. | 10 §5, 09 §2 |
| Q23 | **(tranchée à la porte C, PC5 : les deux ajouts d'API livrés par L03d ; adoption par le worker ouverte)** **`create_thread` en réel** : était bloqué tant que l'API n'offrait pas (a) une **catégorie par défaut** posée côté API sur la route du canal (`POST /e2ee/threads` exige un `categoryId` que le canal n'expose pas ; le worker ne le transmet que s'il figure dans les arguments, hors du schéma de l'outil) et (b) les **membres d'un espace** sur le canal (aujourd'hui la clé d'un salon d'espace n'est scellée que pour le propriétaire). Sans cela l'outil échoue (`invalid_body`). Avis de la revue : ajouter les deux côté API, et refuser `create_thread` dans un espace d'ici là. L'API offre maintenant `categoryId` facultatif (`409 no_default_category`) et `GET /e2ee/members/keys?spaceId=` (04 §4.3) ; le worker ne les utilise pas encore (**ouvert**). | 04 §4.3, 06 §9 |
| Q24 | **(tranchée le 2026-11-21, PC7 : `search_messages` lexical en v1)** **`search_messages` lexical** (suite de Q6) : acceptable en v1 d'après la revue ; alternative évoquée : `POST /embeddings` via le mandataire, ce qui élargirait la liste blanche de L06 (10 §4). À trancher. | 00 Q6, 06 §9 |
| Q25 | **Épinglage TOFU persistant des clés RSA publiques des membres** (revue L07, I5). **Tranchée le 2026-11-21 (PC8)** : épinglage par le superviseur, lot dédié L05b, bloquant avant production. **Réalisée par L05b** : `member-rsa-pins.json` (SHA-256 de la SPKI, par org et utilisateur) ; au relais de `GET /e2ee/members/keys`, une clé changée sans chaîne de transitions d'identité valide (partant de la clé de signature épinglée) remplace la réponse par `409 member_key_changed` : refus global de `create_thread`, rien n'est scellé ; alerte et acceptation manuelle de la clé affichée au dashboard. Corrigée après revue (I1 à I5, M1 à M6) : rotation seulement par une chaîne qui reproduit exactement l'historique de signature épinglé et garantie par une clé non retirée, aucun retour arrière, écriture hors du verrou d'état et bornes (2 000 épingles par org). **Limite inhérente au TOFU** (I5) : à la première vue, une API malveillante peut injecter un destinataire inconnu ou servir sa propre clé pour un membre jamais vu ; seuls les membres déjà vus sont protégés. **Reste ouvert** (questions à l'utilisateur, `docs/journal.md`, L05b) : (0) l'app ne montre pas au membre l'empreinte de sa propre clé : la vérification par l'admin ne peut pas comparer d'empreintes (I4) ; (a) liaison de la clé RSA du propriétaire au mandat signé (changement du format du mandat côté app, lu ancien et nouveau) ; (b) route du canal servant la chaîne de transitions de **tout** membre de l'org, pour accepter automatiquement la rotation d'un membre qui n'a jamais délégué (aujourd'hui : acceptation par l'admin seulement). **Décisions PC27 (2026-11-21, reportées en 03 §10.1 et 06 §4.3)** : (a) l'app affichera l'empreinte RFC 7638 de la clé RSA locale du membre, pour une vérification hors bande (L10 / L11) : répond à la question (0) ; (b) un mandat v2 inclura l'empreinte SPKI de la clé RSA du propriétaire, en priorité, le runtime lisant v1 et v2 : répond à (a) ; (d) un reset E2EE sans transition signée bloque la création de salons jusqu'à l'acceptation par l'admin du runtime (v1) ; (e) refus global en v1, avec un raffinement `scope=owner` plus tard ; (c) la route « chaîne de transitions » est **reportée** (la question (b) ci-dessus reste donc sans route). **PC28** : bornes de `member-rsa-pins.json` décidées (plafond de sécurité de 50 000 par org réglable dans la configuration ; épingles inactives depuis plus de 180 jours archivées en compact, empreinte seule, toujours détectées au retour ; éviction de la plus ancienne archive en cas de débordement ; alerte du dashboard à 80 %) : **décidé, implémentation au lot L05c ; le code actuel applique encore 2 000**. **PC29** : `AiThreadEnvelopeEvent` conservé **1 an**, purge bornée de l'API (lot L03e, en cours). **PC30** : limite de **1 000 membres par org**, invitations en attente comprises (API L03e, app L01b), ce qui reste très en dessous du plafond d'épingles. Format du mandat v2 : **figé par L00f (2026-11-21), 03 §4.1** ; son usage par le superviseur est tranché par **PC46** (l'empreinte du mandat v2 prime sur l'épingle TOFU, 12 §10.3). | 04 §4.3, 06 §4.3, §9 |
| Q26 | **(tranchée le 2026-11-21, PC9 ; réalisée par L07c)** **Flux coupé** : `BadStream` réessayable pour **tous** les fournisseurs, OpenAI / `custom` / passerelle compris (écart volontaire avec le TS, qui terminait en `stop`). Nouvel essai seulement si rien n'a été diffusé. | 06 §9 |
| Q27 | **(tranchée le 2026-11-21, PC10 ; réalisée par L07c)** **`reasoning_effort` pour les modèles Mistral qui n'acceptent que `high|none`** (`mistral-small-2603`, `mistral-medium-3-5`) : `high` si l'effort de l'org est `medium` ou `high`, rien sinon ; autres modèles, alias `*-latest` compris : rien. **Reste ouvert** (question de l'orchestrateur) : couvrir aussi les alias `mistral-*-latest` ? | 06 §9 |
| Q28 | **(tranchée le 2026-11-21, PC11 ; réalisée par L07c)** **Raisonnement Gemini** : désactivé jusqu'à un test réel avec une clé (`include_thoughts` non demandé ; aucun essai réel contre Mistral ou Gemini à ce jour). **Reste ouvert** : PC11 lu comme « ne pas demander les pensées » ; faut-il aussi ne plus envoyer `reasoning_effort` à Gemini (L07b l'envoie) ? | 06 §9 |
| Q29 | **(en partie tranchée le 2026-11-21 : PC13 mot de passe local seul en v1, donc pas de ticket Synco pour (a) ; PC14 pas de compteur par outil pour (b), l'usage étant des analytics de ressources par session et par utilisateur ; PC15 mot de passe par la commande `dashboard-password` ; (c) non tranché)** **Dashboard** : (a) connexion par **ticket Synco** pour les admins de l'org **en complément** du mot de passe local (nouvelle route API et rôle) ; (b) **compteur d'appels par outil** dans `metrics` (évolution du protocole worker) pour nommer l'outil dans la chronologie ; (c) le dashboard **n'est actif que si un mot de passe local existe** (sinon journal `dashboard_disabled`, pas de page « aucun mot de passe ») : confirmer ce choix. | 11 §1, §5, §7 |
| Q30 | **(tranchée à la porte C, PC16 ; code ajouté par L03d)** **Code `provider_not_configured`** (08 §6) : fournisseur non configuré, sans clé ou passerelle refusée. Le runtime écrit encore `provider_error` dans ce cas (cause exacte au journal du runtime) : adoption **ouverte**. | 10 §4, 08 §6 |
