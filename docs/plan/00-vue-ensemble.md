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
| [vectors/README.md](vectors/README.md) | Vecteurs de test à produire par L01 et L02 |
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

## 4. Invariants de sécurité et lots qui les testent (révisé après la vague B, 2026-11-19)

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
| Le dashboard n'expose aucun contenu de conversation | 06 §5 (métriques sans contenu) | L08 |
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
| Une clé créée par le runtime porte une enveloppe `rt1` vérifiable par les clients à jour, et reste acceptée (TOFU) par les clients anciens | 03 §10 | L07 (production), L10 (vérification), L01 (vecteur) — **en suspens pour les salons créés par le runtime** (Q11) |

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

## 5. Décisions de la porte A (tranchées le 2026-11-18)

Ce tableau **fait foi**. Les analyses d'options des sections suivantes sont conservées pour mémoire ;
partout où la spec écrit « dépend de Dx », appliquer la valeur ci-dessous.

| # | Décision retenue |
|---|---|
| D1 | **Option A** : les clés API des fournisseurs LLM sont dans la configuration du runtime. `GET /api/runtime/v1/llm-policy` ne renvoie aucun secret ; la route `llm-credentials` **n'existe pas** ; `Organization.aiProviderKeys` n'est jamais lu pour le mode runtime. La passerelle est appelée avec un ticket `sgt1`. |
| D2 | **Option A** : la crate vit dans `crates/synco-e2ee` du workspace du runtime, importable par dépendance git. |
| D3 | Licence ajoutée par l'utilisateur (`LICENSE`, commit `cc6e0b9`) : **tous droits réservés**, code publié à des fins de transparence. La crate n'est réutilisable que par les projets de Silvercore ; P8 s'entend dans ce sens. |
| D4 | **Option A** : 7 jours par défaut, renouvellement à l'ouverture de Synco quand il reste moins de 50 % ; maximum réglable par l'admin entre 1 h et 30 jours (09 §1). |
| D5 | **Option A** : politique par outil `auto` / `ask` / `deny`, défaut selon le niveau de risque (affiné par L14 à la porte E) ; `ask` → `awaiting_confirmation` + notification ; délai 7 jours puis `failed` (`confirmation_timeout`). |
| D6 | Valeurs proposées en 09 §2 **adoptées**, à réviser après les mesures de L06 ; l'org peut les abaisser, jamais les relever. |
| D7 | **Option A** : le régime `server` est conservé tel quel. |
| D10 | **Option A** : pas de relais par l'API en v1 ; mode dégradé de 05 §9 ; le runtime doit présenter un certificat TLS reconnu par les navigateurs (Q7). |

Questions du §6, réponses de la porte A : **Q1** clé par conversation `CK`, `AiSessionKey` jamais
déléguée (accepté) ; **Q2** affichage du signataire et de l'empreinte avant la première délégation,
sans exiger la signature du propriétaire, risque résiduel documenté ; **Q3**, **Q4** (lecture actuelle :
`exp` dans l'enveloppe de tête et le mandat), **Q5**, **Q6**, **Q7**, **Q8**, **Q10** : propositions de
cette spec acceptées ; **Q9** : les documents du dossier de projet sont corrigés (séparateur `:`).

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

## 6. Questions et tensions relevées pour la porte A (révisé après la vague B, 2026-11-19)

| # | Point | Proposition de cette spec |
|---|---|---|
| Q1 | P5 cite « la clé IA » (`AiSessionKey`) parmi les clés déléguées. Or cette clé est **partagée par toute l'org** (`AiSessionKey`, contexte `ai:<orgId>`, `AiSessionKeyService.ts:106`) : la déléguer donnerait au runtime de quoi lire toutes les conversations `gateway` de tous les membres que l'API lui servirait. | Une **clé par conversation** `CK` (03 §6) ; `AiSessionKey` n'est **jamais** déléguée en v1. Les anciennes conversations `gateway` basculées vers le runtime sont rechiffrées par le client sous une nouvelle `CK`. C'est plus restrictif que P5 (« seulement » est une borne haute), mais c'est un choix de format à confirmer. |
| Q2 | Le statut d'admin vient de l'API. Le client vérifie la signature du certificat avec la clé épinglée de l'admin, mais ne peut pas prouver que ce membre **est** admin. Une API malveillante alliée à un membre (ou à un compte de membre compromis avec ses clés) peut faire certifier un faux runtime. | Le client affiche à chaque utilisateur, avant sa première délégation, **qui** a signé le certificat et l'empreinte (01 §7). Variante plus stricte à trancher : exiger la signature du **propriétaire** de l'org (`Organization.ownerId`) — même limite (l'API désigne le propriétaire), mais un seul signataire possible. |
| Q3 | Le runtime vérifie les mandats avec la clé de signature de l'utilisateur, qu'il ne peut obtenir **que** par l'API. | Épinglage TOFU côté runtime + suivi de la chaîne de transitions d'identité (03 §4). Une API malveillante dès le premier contact peut tromper le runtime : même limite que le TOFU des clients, à documenter. |
| Q4 | Mesure 5 : « l'AAD de chaque enveloppe de délégation contient … l'expiration ». | L'expiration est dans l'AAD de l'**enveloppe de tête** et dans le **mandat signé** ; les entrées ne l'ont pas, elles sont liées à la délégation par `delegationId` et par `DK`, qui n'est obtenable que par l'enveloppe de tête (03 §5). Mettre `exp` dans chaque entrée imposerait de tout rechiffrer à chaque renouvellement, ce que la spec fait de toute façon (03 §7) : l'alternative est donc possible à coût nul si la porte A préfère la lecture littérale. |
| Q5 | Clés créées par le runtime (outil `create_thread`) : les clients actuels vérifient l'enveloppe FC4 avec la clé du **créateur** ; le runtime n'a pas la clé d'identité de l'utilisateur. | Créateur `rt1:<delegationId>`, signature par la clé `csk` du runtime, chaîne vérifiable par le mandat de l'utilisateur (03 §10). Les clients actuels ne connaissent pas ce créateur et retombent sur le TOFU (`keyEnvelope.ts:132-137`) : compatible, mais sans vérification tant que l'app n'est pas mise à jour. À noter : aujourd'hui, `createThreadHelper` (`OrgAI.vue:495`) ne signe **aucune** enveloppe pour les salons créés par l'IA. |
| Q6 | `search_messages` s'appuie sur l'index chiffré et sur un modèle d'embedding exécuté dans le navigateur (`Xenova/paraphrase-multilingual-MiniLM-L12-v2`, `semantic.worker.ts:10`). | Le runtime devra calculer des vecteurs compatibles (même modèle) pour chercher : à traiter par L07/L14. Le canal interne prévoit la lecture de l'index dans le périmètre (04 §4). |
| Q7 | « Runtime limité à l'intranet » et navigateurs : le client parle **directement** au runtime en `wss://`. Il faut un certificat TLS reconnu par les navigateurs et les applis mobiles des membres, et un CORS limité à l'origine de l'app. | Documenté ; lié à D10. Un certificat auto-signé ne fonctionnera pas dans les navigateurs. |
| Q8 | La bascule d'une conversation `client` (blob RSA `isE2EE`, `AIService.ts:917-927`) ou `server` (clair) vers le runtime impose de **réécrire l'historique** au format `StoredMessage[]` chiffré par `CK`. | Conversion par le client à la bascule (03 §6.4) ; la conversion depuis le format d'affichage du régime `client` est à valider par L11. L'historique `server` a déjà été vu en clair par l'API : le rechiffrer protège la suite, pas le passé. |
| Q9 | Doc vs code : `02_architecture.md` et `03_securite.md` décrivent l'AAD des champs `gcm1:` comme `session|message|champ`. Le code utilise `:` (`crypto.rs:64-66`, `synco_app/src/assets/utils/crypto.ts:963`). | La spec suit le **code** (`:`). Les documents du dossier de projet sont à corriger. |
| Q10 | Le runtime doit-il apparaître dans la liste des appareils de l'utilisateur (paramètres E2EE v4) ? | Non en v1 (ce n'est pas un `UserDevice`) ; il apparaît dans *Paramètres → Synco AI → Runtime* avec l'état de la délégation. À confirmer côté produit. |

### Questions ouvertes après la vague B (ajoutées le 2026-11-19, **non tranchées**)

| # | Point | Options et impact (aucune n'est choisie ici) |
|---|---|---|
| Q11 | **Signature `rt1` d'un salon créé par le runtime** (03 §10, 04 §4.3). L'enveloppe `rt1` signe `ctx = thread:<threadId>`, mais l'id du salon est tiré par l'API pendant `POST /e2ee/threads` : le runtime ne peut pas le signer d'avance. Aujourd'hui la route accepte `commitment` / `signature` (ensemble ou absents) mais le runtime ne peut pas les produire pour le bon `ctx` : le salon est accepté en **TOFU** par tous les clients, comme les salons créés par l'IA dans l'app actuelle (`CreateNewThread.vue`, `OrgAI.vue` n'envoient pas de `commitment`). L'invariant « clé créée par le runtime vérifiable par les clients à jour » (§4) n'est donc pas tenu pour ce cas. | **A. Le runtime propose l'id, validé par l'API** (recommandée par l'orchestrateur) : `POST /e2ee/threads` reçoit un champ `id` (conforme à 00 §3.2, de la forme des ids de salon) tiré par le runtime ; l'API refuse un id mal formé ou déjà pris (`409`) et crée le salon sous cet id ; le runtime signe `thread:<id>` avant l'appel ; une seule requête, aucune fenêtre sans signature. Impact : le service partagé `createThread` doit accepter un id injecté (réservé au canal, la route HTTP reste inchangée) ; nouveau champ et nouveau code dans 04 §4.3 ; vecteur `rt1` sur un id choisi (L01) ; L07 tire l'id. **B. Route de pose a posteriori** : nouvelle route S+A (bail exigé), par exemple `POST /e2ee/threads/:threadId/key-envelope { commitment, signature }`, qui pose l'enveloppe sur les `ThreadKey` de `creatorId = rt1:<délégation de l'autorisation>` encore sans `commitment`, sans jamais en écraser une. Impact : une route de plus dans la liste fermée ; deux requêtes, donc un état intermédiaire (salon créé non signé) en cas d'échec ; entre les deux, un client peut charger la clé et l'épingler en TOFU sans vérification, puis voir apparaître une enveloppe qu'il n'a pas vérifiée à la première vue. |
| Q12 | **URL canonique : la règle de l'API diffère de celle de la crate** (01 §3). `canonicalRuntimeUrl` (`synco_api/src/services/aiRuntime/runtimeFormats.ts:41-54`) accepte des URL que `canonical_runtime_url` refuse (IPv6, `_` dans l'hôte, `//` et ponctuation dans le chemin) et refuse tout `http`, même sous drapeau de développement. | A. Porter la règle de la crate dans l'API (même algorithme, vecteurs d'URL partagés), avec `http://localhost|127.0.0.1:<port>` admis seulement derrière une variable de développement de l'API. Impact : une validation de plus dans `runtimeRegistry.ts`, vecteurs à ajouter (L01/L02). B. Laisser l'écart : l'API n'est pas une autorité, le client refuse ; coût : un certificat accepté par l'API puis refusé par tous les clients (runtime inutilisable jusqu'à recertification), et pas d'appairage `http` de développement de bout en bout. |
| Q13 | **`user.revoked` n'est jamais émis** (02 §8, 04 §6) : la liste de révocation des tickets du runtime n'est alimentée que par `conversation.revoked`. | A. Émettre `user.revoked` `{ userId, until = maintenant }` à chaque révocation de toutes les délégations d'un utilisateur (départ, membre non autorisé, révocation par l'utilisateur ou l'admin) : un ticket `srt1` émis avant est refusé même pour une conversation encore inconnue du runtime. Impact : appels à ajouter dans `delegationService.ts`, aucun changement de format. B. Retirer `user.revoked` de la spec : `delegation.revoked` + `conversation.revoked` suffisent, puisque le runtime exige à la connexion une autorisation connue (05 §1 étape 4) et que l'autorisation est révoquée avec la délégation. Impact : 02 §8 et 04 §6 à simplifier ; le runtime doit alors garantir qu'il n'accepte aucun WebSocket sans autorisation active connue. |
| Q14 | **Limites de la politique de l'org non appliquées** : (a) les délais `awaiting_*` sont fixes à 7 jours, alors que 09 §3 les dit réglables par l'org ; (b) baisser `maxDelegationDays` n'écourte pas une délégation existante ; (c) le bannissement d'un **utilisateur** (et non de l'org) : voir Q17. | (a) A : ajouter un champ de délai à `aiConfig.runtime.limits` (07 §6), lu par la maintenance ; B : retirer « (org) » de 09 §3. (b) A : à l'enregistrement de la politique, révoquer (raison à créer, par exemple `policy_shortened`) les délégations dont `exp − iat` dépasse le nouveau maximum ; B : laisser courir jusqu'à `exp` (≤ 30 j) et le documenter dans l'écran admin. (c) : Q17. |
| Q15 | **Journal `tool_unknown_outcome` et `lease_lost`** (07 §5, 08 §5) : aucune route du canal ne permet au runtime d'écrire un `AiChatSessionEvent`. | A. Champ facultatif `events: [{ type, code? }]` (types limités à `tool_unknown_outcome`, `lease_lost`) dans `PUT …/transcript` et `POST …/status`. B. L'API déduit `tool_unknown_outcome` du clair de l'historique (`toolCalls[i].status` passé d'`executing` à `error` sous un autre `leaseEpoch`) et journalise `lease_lost` quand elle reprend un bail expiré. C. Retirer ces deux types de 07 §5 (journal tenu par l'API seule). |
| Q16 | **Écarts mineurs reportés tels quels, à ratifier** : (a) le désappairage clôt le bail sans incrémenter `leaseEpoch` (01 §9 ; protection équivalente, mais contraire à la règle commune de 08 §2) ; (b) `awaitingKey` n'admet que `thread` et `space`, pas `conv` (04 §4.2) ; (c) ajout d'entrées par le client limité à 3 / 15 s au lieu de 1 / 5 s (09 §4.1) ; (d) le dépôt dans la boîte prend la trame **sans `v`** (05 §5.4, §6.2) ; (e) `POST /register` ne compare pas l'URL envoyée à celle du certificat (01 §7). | Proposition : ratifier (a) à (e) tels que décrits ; sinon, chaque point est une modification locale du code de L02/L03 sans changement de format chiffré. |
| Q17 | **Utilisateur banni de la plateforme** (`User.bannedAt`, `POST /api/admin/users/:id/ban`, `synco_api/src/routes/admin.ts:440`) : ses requêtes à lui sont refusées par `banMiddleware`, mais le canal interne n'y passe pas (requêtes du runtime) et ni le second verrou (`runtimeAuth.ts:392-394`) ni `loadAuthorizedConversation` ne lisent `User.bannedAt` ; ses délégations ne sont pas révoquées (hors périmètre de M2, `SYNCOAI_REFONTE_FEATURE.md` §12.3). Le runtime peut donc continuer d'agir pour lui jusqu'à `exp` (≤ 30 j). | A. Révoquer ses délégations au bannissement (`revokeDelegations(ctx, { userId }, <raison à créer, par exemple user_banned>)`, appel dans `admin.ts`) et passe de maintenance en filet. B. Ajouter `User.bannedAt` à l'étape 4 du second verrou (`auth_invalid`) sans révoquer (accès rétabli à la levée du bannissement). C. A + B. Impact commun : test qui échoue sans la protection ; pour A, nouvelle valeur de `revokedReason` (07 §3). |
