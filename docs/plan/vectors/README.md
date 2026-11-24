# Vecteurs de test à produire (L01, L02) et vecteurs figés par L00f et L00g

Ce dossier liste les vecteurs que L01 et L02 doivent produire (§1 à §3), sur le
modèle de `synco_cdn/tests/vectors/` (`generate.mjs` + `tickets.json` : un générateur TypeScript ou
JavaScript, le fichier JSON commité, la même suite rejouée des deux côtés).

Les exemples de [../exemples/](../exemples/) illustrent la spec avec `node:crypto` ; ils ne
remplacent pas ces vecteurs, qui doivent être produits **avec le code réel** (fonctions de
`synco_app/src/assets/utils/` pour les formats E2EE, `synco_api/src` pour les tickets et la signature
interne).

**Exception (L00f, 2026-11-21)** : `mandate-v2.json` et `action-plan.json` sont des vecteurs **figés
par la spécification**, avant tout code (§4). Ils sont commités ici, et les lots L01c, L03g, L08d et
L10 les rejouent sans les modifier.

## 1. Règles communes

- **Source** : le générateur vit dans le dépôt TypeScript qui détient l'implémentation de référence ;
  il importe le code réel, sans le dupliquer. Les fichiers JSON produits sont copiés dans le dépôt
  `synco_ai_runtime` (emplacement selon D2 : par défaut `crates/synco-e2ee/tests/vectors/` et
  `crates/runtime-protocol/tests/vectors/`) et rejoués par `cargo test`.
- **Sens Rust → TS** : la crate produit à son tour des valeurs (enveloppes, entrées, champs `gcm1:`,
  enveloppes `rt1`, signatures de requêtes) que les tests TS ouvrent ou vérifient (`bun test`).
- **Clés fixes** : graines et scalaires constants (`0x11` × 32, etc.) pour la reproductibilité ;
  Ed25519 est déterministe ; **ECDSA ne l'est pas** en WebCrypto : les vecteurs ECDSA sont
  « vérification seulement » (on enregistre une signature valide, on ne compare pas une signature
  recalculée). AES-GCM : le générateur fixe les IV pour obtenir des vecteurs exacts.
- **Nonces et IV fixes uniquement dans les vecteurs** : jamais dans le code de production.
- **Format de chaque fichier** : `{ "description", "keys" | "publicKeys", "policy"?, "cases": [ { "name", …entrées…, "expect": "ok" | "<code d'erreur>" } ] }`, un `name` en français et unique.
- **Dépôt public et hook `pre-commit`** (`scripts/lib/secrets.mjs`) : les vecteurs contiennent des
  clés de test, il faut donc éviter ce que le hook prend pour des secrets :
  - jamais de bloc PEM : clés en hexadécimal ou `b64u` brut, PKCS#8 en hexadécimal si besoin ;
  - noms de champs JSON sans `token`, `secret`, `password`, `api_key` / `apiKey` (le motif
    `affectation-de-secret` les détecte devant une chaîne de 16 caractères ou plus) : écrire
    `ticket`, `seedHex`, `keyHex`, `linkBytesHex`… ;
  - aucun nom d'hôte interne ni adresse IP privée : `runtime.example.com`, `gateway.example.com`.
- Chaque cas négatif doit échouer **proprement** (erreur typée, pas de panique) avec le code attendu.

## 2. L02 — synco_api (générateur TS dans `synco_api`)

### 2.1 `tickets-runtime.json` (`srt1`, 02)

Clé Ed25519 de test, `kid` `vec-1`. Politique : `clock_skew_secs` 30, `max_lifetime_secs` 600.
Entrées d'un cas : `ticket`, `now`, `runtimeId`, `orgId` (org appairée), `conv` (chemin), `expect`.

| Cas | `expect` |
|---|---|
| valide | `ok` |
| expiré (`exp + 31`) / dans la tolérance (`exp + 29`) | `ticket_expired` / `ok` |
| pas encore valide (`iat − 31`) | `ticket_invalid` |
| signature altérée (1 bit) | `ticket_invalid` |
| `kid` inconnu | `ticket_unknown_key` |
| préfixe `srt9` | `ticket_invalid` |
| **ticket `sct1` du CDN valide** (même clé, domaine CDN) | `ticket_invalid` |
| **ticket `sgt1` valide** présenté au runtime | `ticket_invalid` |
| préfixe `srt1` mais signé avec le domaine de la passerelle | `ticket_invalid` |
| préfixe `srt1` mais signé avec le domaine du CDN | `ticket_invalid` |
| `rt` d'un autre runtime | `ticket_wrong_audience` |
| `org` d'une autre org | `ticket_wrong_org` |
| `conv` différente du chemin | `ticket_wrong_conversation` |
| `op` = `llm` | `ticket_wrong_operation` |
| champ inconnu signé (`admin: true`) | `ticket_invalid` |
| `sub` non conforme (`../x`, `a|b`, 65 caractères) | `ticket_invalid` |
| durée de vie 601 s | `ticket_invalid` |
| contenu signé non JSON | `ticket_invalid` |
| segment supplémentaire | `ticket_invalid` |
| 2 049 octets | `ticket_invalid` |
| vide | `ticket_missing` |

### 2.2 `tickets-gateway.json` (`sgt1`, 02)

Mêmes cas, transposés (`gw` au lieu de `rt`, `conv` absent), plus : `org` absente de
`SYNCO_ALLOWED_ORGS` → `ticket_wrong_org` ; `gw` = autre URL → `ticket_wrong_audience` ; `rt`
présent et valide → `ok` ; ticket `srt1` présenté à la passerelle → `ticket_invalid` ; durée de vie
901 s → `ticket_invalid`.

### 2.3 `internal-requests.json` (signature des requêtes, 04 §2)

Clé `sig` de test (graine `0x11` × 32). Entrées d'un cas : `method`, `path` (avec requête),
`headers`, `bodyB64`, `now`, `expect`. Un cas « rejeu » contient deux requêtes successives.

| Cas | `expect` |
|---|---|
| `POST` avec corps et `x-synco-auth` | `ok` |
| `GET` sans corps, sans `x-synco-auth` (`AUTH` = `-`) | `ok` |
| `GET` avec chaîne de requête | `ok` |
| corps modifié d'un octet | `rt_sig_invalid` |
| chemin modifié / chaîne de requête modifiée | `rt_sig_invalid` |
| méthode modifiée | `rt_sig_invalid` |
| `x-synco-auth` ajouté, retiré ou modifié après signature | `rt_sig_invalid` |
| `x-synco-runtime` d'un autre runtime | `rt_sig_invalid` (ou `rt_unknown`) |
| horodatage à +61 s / −61 s / +60 s | `rt_clock_skew` / `rt_clock_skew` / `ok` |
| nonce rejoué (deuxième requête identique) | `rt_replay` |
| en-tête de signature absent ou non `b64u` de 64 octets | `rt_sig_missing` |
| signature produite sans le préfixe de domaine | `rt_sig_invalid` |

## 3. L01 — crate `synco-e2ee` (générateur TS dans `synco_app`)

Fonctions de référence TS écrites par L01 dans `synco_app/src/assets/utils/` (par exemple
`runtimeDelegation.ts`, `runtimeCert.ts`), pures, réutilisées par L10.

### 3.1 `runtime-identity.json` (01 §2, §3)

- Empreinte : entrées `runtimeId`, `sig`, `kex`, `csk` → `fprInput`, `fprHex`, affichage groupé.
- Code d'appairage : `fprHex` → code ; lecture : minuscules, espaces, `O`/`I`/`L` → `ok` ; somme de
  contrôle fausse → `pair_code_invalid` ; longueur fausse → `pair_code_invalid`.
- URL canonique : `HTTPS://Runtime.Example.com:443/` → `https://runtime.example.com` ; refus :
  `http://` (hors drapeau de développement), identifiants, requête, fragment, `|` dans le chemin,
  plus de 255 caractères.
- JWK : JWK avec champs en plus (`d`, `ext`, `key_ops`) ou dans un autre ordre → forme canonique ;
  point hors courbe → refus.

### 3.2 `runtime-cert.json` (01 §6)

Clé de signature d'identité de l'admin (scalaire fixe). Cas : certificat valide → `ok` ; puis chaque
champ de `certBytes` modifié tour à tour (`orgId`, `runtimeId`, `url`, `sig`, `kex`, `csk`,
`adminId`, `issuedAt`, `serial`) → `cert_bad_signature` ; signé par une autre clé →
`cert_bad_signature` ; signature DER au lieu de P1363 → `cert_bad_signature`.

### 3.3 `challenge.json` (01 §5)

Clés `kex`, `csk` et éphémère client fixes, `nonce` fixe. Valeurs attendues : `transcript`, `shared`,
`K_ch`, `mac` (exactes) ; `sig` (vérification seulement). Négatifs : `mac` calculé avec une autre
`kex` → `challenge_failed` ; `sig` d'une autre clé → `challenge_failed` ; `purpose`, `orgId`,
`userId`, `nonce` ou `fprHex` différents dans le transcript du vérificateur → `challenge_failed`.

### 3.4 `delegation.json` (03 §3–§5)

Clés fixes (`kex` du runtime, `epk`, clé de signature de l'utilisateur), `DK`, IV fixes.

Enveloppe de tête : valeurs exactes de `ctx`, `shared`, `KEK`, `blob`, `wrap`. Négatifs (ouverture par
le runtime) :

| Cas | `expect` |
|---|---|
| ouverte par un **autre runtime** (autre `kex_priv`) | `delegation_unusable` |
| `kex` du contexte = celle d'un autre runtime | `delegation_unusable` |
| `userId`, `orgId`, `runtimeId`, `delegationId`, `scope`, `iat` ou `exp` différents à l'ouverture (un cas par champ) | `delegation_unusable` |
| enveloppe tronquée, préfixe `srd2`, quatre parties, `epk` hors courbe, `epk` non canonique | `delegation_unusable` |
| clair de 31 ou 33 octets | `delegation_unusable` |

Mandat : `mandateBytes` exact ; signature valide → `ok` ; `wrap` d'une autre délégation (hash
différent) → `delegation_unusable` ; `fprHex` d'un autre runtime → `delegation_unusable` ; signé par
une autre clé → `delegation_unusable`.

Entrées : valeurs exactes pour `thread`, `space` (version 3) et `conv`. Négatifs : entrée d'une autre
délégation (autre `DK`) ; métadonnées `kind`, `ref` ou `version` changées ; AAD avec un autre
`userId` ; `kind` = `dm`, `support`, `ai`, `org`, `account` → `entry_unusable` (refus **avant**
déchiffrement pour les `kind` hors liste).

Sens Rust → TS : la crate produit une délégation complète (mandat signé avec une clé de test,
enveloppe, entrées) que le TS ouvre.

### 3.5 `conversation-fields.json` (03 §6.3, 05 §4)

Doit inclure, **à l'identique**, le vecteur historique de `Synco_AI_Gateway/src/crypto.rs:174-188`
(clé `d82f2646…7911`, session `sess_test0000000000000000000001`, message
`msg_test00000000000000000000001`, champ `content`) : la crate doit l'ouvrir.

Cas, avec `CK` et avec une `AiSessionKey` de test : `content`, `thinking`, `tool_result` (JSON),
`tool_call_arguments:<toolCallId>`, `__pending__`/`pending_tool_call_args`,
`__session_title__`/`title`, `ws:text:<epoch>:<seq>`, `ws:thinking:…`, `snapshot:<epoch>:<seq>`,
`answer:<toolCallId>`. Négatifs : AAD avec un autre `sessionId`, `messageId` ou `fieldName` ; delta
`seq` différent ; mauvaise clé ; tag altéré ; base64 invalide ; préfixe `gcm2:` ; longueur < 28
octets ; clair non UTF-8 → erreurs typées (comme `CryptoError`, `crypto.rs:24-37`). Comportement
« déjà en clair » (`decrypt_field_if_encrypted`, `crypto.rs:116-122`) : une valeur sans préfixe est
rendue telle quelle **uniquement** dans les fonctions de lecture tolérante, jamais par la fonction
stricte.

### 3.6 `rt1-envelope.json` (03 §10)

Clé `csk` fixe, `ThreadKey` fixe. Valeurs exactes de `commitment` (identique à `keyCommitment`,
`keyPinning.ts:42-51`) et des octets signés ; signature (vérification seulement). Négatifs :
`ctx`, `version` ou `delegationId` différents ; commitment d'une autre clé ; signé par `kex` (mauvaise
clé) ; mandat vérifié avec une autre clé d'utilisateur.

Plus un **vecteur de compatibilité** pour L10 : une `ThreadKey` dont `creatorId` = `rt1:…`, passée à
la fonction actuelle `verifyKeyEnvelopeIfPresent` avec un annuaire qui ne connaît pas ce créateur :
le résultat attendu est « accepté sans vérification » (comportement des clients non mis à jour).

### 3.7 Formats existants (rétrocompatibilité, P8)

L01 couvre aussi les formats E2EE v4 existants que la crate réimplémente (enveloppe d'appareil,
certificat d'appareil, enveloppes FC4 `synco-key-envelope-v1`, commitments, transitions d'identité)
avec leurs particularités d'encodage, notamment l'ordre `{"kty","crv","x","y"}` de
`canonicalJwk` (`e2eeV4.ts:322-327`) dans `createDeviceEnvelope` et `deviceCertBytes`, différent de
l'ordre RFC 7638 des nouveaux formats (00 §3.1).

## 4. L00f — vecteurs figés (mandat v2, plan d'action)

Produits par du code jetable hors du dépôt (supprimé après usage) : les signatures et les chiffrés
viennent de la crate `synco-e2ee` (signature ECDSA déterministe RFC 6979, `primitives::seal` avec une
source d'aléa figée) ; le texte des octets signés et le JSON canonique viennent d'un script TypeScript
qui importe `mandateBytes`, `verifyMandateOfflineFromWrapHash` (`runtimeDelegation.ts`) et
`decryptAiField` (`crypto.ts`) de `synco_app`. Contrôle croisé fait à la génération :

- **TS** : chaque signature v2 vérifiée en WebCrypto ; le mandat v1 livré vérifié par
  `verifyMandateOfflineFromWrapHash` (et `mandateBytes` v1 de l'app identique au vecteur livré) ; plan et
  `plan_result` déchiffrés par `decryptAiField` ; chaque cas de chiffrement rejoué ; condensat recalculé ;
  cas de validation, de cascade et d'échec rejoués par un validateur de référence jetable (règles de 12 §5
  à §7).
- **Rust** : le fichier final relu ; chaque cas de mandat rejoué (v1 par
  `verify_mandate_offline_from_wrap_hash`, v2 par `EcPublicKey::verify` sur les octets de 03 §4.1) ;
  chaque cas de chiffrement rejoué par `session::decrypt_field` ; condensats recalculés ;
  `serde_json::to_string` (clés triées, forme compacte) identique au JSON canonique du TS.

Toutes les clés sont des **clés de test** créées pour ces vecteurs (scalaires `0x44` × 32 et `0x45` × 32,
`CK` = `0x5c` × 32, deux clés RSA-2048 publiques dont seule la SPKI est gardée) ; le contexte, `wrap`,
`wrapHash` et le mandat v1 viennent de `crates/synco-e2ee/tests/vectors/delegation.json`.

### 4.1 `mandate-v2.json` (03 §4.1)

- `mandateBytesPlan` / `signaturePlan`, `mandateBytesAuto` / `signatureAuto` : octets exacts du mandat v2,
  signature à **vérifier** (ECDSA non déterministe en WebCrypto : ne pas comparer une signature recalculée
  en TS ; la crate, déterministe, la retrouve à l'octet près).
- `mandateCases` : entrées d'un cas = `context`, `fprHex`, `wrapHash`, `userSignKey`, `signature`, et les
  champs servis `mandateVersion` (absent = 1), `mode`, `ownerRsaSpkiHex` ; `expect` = `ok` (avec
  `expectMode`) ou `delegation_unusable`. Couvre : v2 `plan` et `auto`, **v1 livré relu comme `plan`**
  (version 1 ou absente, `mode: "auto"` servi ignoré), confusions v1/v2, mode échangé, empreinte RSA
  remplacée ou mal formée, mode inconnu, version 3, autre clé, autre runtime, autre enveloppe, `exp`
  prolongé.
- `rt1Policy` : règle d'acceptation d'une enveloppe `rt1` par un client à jour (12 §10.2) : `verified`,
  `rejected` ou `tofu_warning` selon la version et le mode du mandat vérifié.

Rejoués par L01c (`synco-e2ee` et fonctions pures TS), puis par L10 et L08d (superviseur).

### 4.2 `action-plan.json` (12 §3 à §9 ; amendé le 2026-11-21 par PC44, PC47, PC54 et PC58)

- `plan`, `planCanonical` (RFC 8785, entiers seulement), `aadPlan`, `ivPlanHex`, `planValue` : plan de
  référence et sa valeur `gcm1:` exacte sous `CK` ; `planExecutors` et `planLevels` : exécutant et niveau
  de chaque action (12 §8.1) ; `pendingToolCall` : forme stockée (12 §3.4).
- `planResult`, `planResultCanonical`, `aadPlanResult`, `planResultValue` : `plan_result` **partiel** de
  la phase d'appareil 1 (AAD `sessionId:planId:plan_result:1`, 12 §9).
- `mixedPlan` : plan appareil / agent avec ses niveaux et ses valeurs chiffrées : le plan,
  `plan_result:1`, `plan_agent_result:1` et `plan_result:2` (phases numérotées **par exécutant**).
- `categoryPlan` : cas de l'utilisateur (PC58) : 3 `category.create` puis 9 `thread.create` (3 par
  catégorie, `categoryId` par `argsRefs`, `groups`), chiffré ; `expectLevels`, `wavesUnbounded`
  (parallélisme maximal), `scheduleConcurrency4` (ordre d'exécution valide avec 4 actions en cours au
  plus) et `failureOfCategory2` (seuls ses 3 salons sont ignorés, PC54).
- `toolManifest` : extrait du manifeste utilisé par la validation (outils `server` et `mutating`).
- `serverDigests` : SHA-256 (`hex`) de `JCS({tool, args, argsRefs})`, `argsRefs` omis s'il est absent
  (PC47). `executeCases` : verrou de 12 §8.4 (condensat de l'appel, puis `refs` contre les sorties
  **enregistrées par l'API**) ; `expect` = `ok` (avec `effectiveArgs`) ou `action_not_accepted`.
- `encryptionCases` : mêmes champs que `conversation-fields.json` et mêmes codes d'erreur ; couvrent
  l'échange de phase, l'absence de numéro de phase, le rejeu sur un autre plan et la confusion
  `plan_result` / `plan_agent_result`.
- `validationCases` : `plan` → `ok` ou `plan_invalid` (worker L08d, appareil L10, et pour la forme vue
  par l'API, L03g) ; groupes, `category.create`, `categoryId` ; bornes de PC61 : 100 actions (passe), 101
  (échoue), 2 000 dépendances (passe), 2 001 (échoue), clair de 65 Kio (passe), > 256 Kio (échoue) ;
  `detail: "plan_too_large"` indique le motif rendu au modèle.
- `levelCases` : graphe → niveaux ; `cascadeCases` : actions décochées → `skipped` (PC37) ;
  `failureCases` : échec → seules les dépendantes transitives `skipped` (PC54) ; `runCases` : simulation
  par pas unitaires (chaque exécutant démarre ses actions prêtes, plus petite `n` d'abord, dans la limite
  de `concurrency` ; toutes finissent en fin de pas ; échec → dépendantes `skipped` ; aucune action ne
  démarre à partir de `expiresBeforeTick`) → `expectTicks` (`{ device, agent }` démarrées à chaque pas),
  états, statut. C'est **un** ordre valide parmi d'autres : les implémentations ne doivent pas en
  dépendre au pas près, mais respecter dépendances, concurrence et règle d'échec.

Revérification après le second amendement (code jetable sous `~/.cache`, supprimé) : chiffrés produits
par `primitives::seal` de la crate avec un IV figé ; **Rust** : le fichier final relu, 66 vérifications
(`session::decrypt_field`, `serde_json::to_string` = JCS, condensats, verrou et `refs`, niveaux,
cascade, simulation) ; **TS** : 104 vérifications (`decryptAiField` de `synco_app`, WebCrypto pour les
condensats, validateur de référence pour validation, niveaux, cascade, échec et simulation).

Revérification après PC61 (code jetable sous `~/.cache`, supprimé) : **Rust** 71 vérifications (dont la
taille JCS et les bornes des cas PC61), **TS** 107 vérifications (validateur de référence à 100 actions,
2 000 dépendances, 256 Kio).

## 5. L00g — vecteurs figés (artefacts de conversation, 13)

`artifacts.json` est figé par la spécification, comme ceux du §4, et rejoué sans modification par le
runtime (outil `send_file`), l'API (forme et bornes du dépôt) et l'app (`ArtifactSource`). Produit par
un script jetable hors du dépôt : WebCrypto (AES-256-GCM avec IV fixes, SHA-256) sous `bun`, clair
canonique en JCS (12 §3.3). Contrôle croisé fait à la génération :

- **TS** : chaque cas de `encryptionCases` rejoué par `decryptAiField` (`synco_app/src/assets/utils/crypto.ts`) ;
  empreinte du contenu vérifiée par `artifactMatches`, nom assaini par `sanitizeArtifactName`
  (`artifactModel.ts`).
- **Rust** : `session::decrypt_field` de `synco-e2ee` sur chaque cas de `encryptionCases` et sur les deux
  valeurs de chaque cas de `verifyCases` ; `plan::jcs` et `serde_json::to_string` identiques à
  `metaCanonical`, `storedArgsCanonical` et `toolResultCanonical` ; SHA-256 et tailles de `contentCases`
  recalculés par `primitives::sha256`.

Clés de test : `CK` = `0x5c` × 32 (celle d'`action-plan.json`), autre clé `0x5d` × 32 ; IV `0x8a` × 12
(`meta`) et `0x9b` × 12 (`value`).

- `meta`, `metaCanonical`, `aadMeta`, `metaValue` ; `content`, `size`, `sha256`, `aadContent`,
  `contentValue` : artefact de référence (13 §3).
- `toolCall` : arguments du modèle, **forme réduite** enregistrée (13 §2.4) et résultat d'outil.
- `deposit`, `listItem`, `frame` : corps du dépôt (13 §5.1), élément de liste (§5.2), trame (§6.1).
- `nameCases` (`expect` = `ok` avec `finalName`, `artifact_name` ou `artifact_format`) et
  `contentCases` (`ok` avec `expectSize` et `expectSha256`, `artifact_too_large`, `artifact_not_text`) :
  validation du worker (13 §2.2). Un cas `fill` / `fillLength` se construit en répétant `fill`.
- `encryptionCases` : mêmes champs et codes que `conversation-fields.json` ; échange `meta` / `value`,
  autre `artifactId`, autre conversation, autre `CK`.
- `verifyCases` : `ref`, `meta`, `value` → `ok` (avec `expectMeta`, la forme `ArtifactMeta` de l'app) ou
  `artifact_unreadable` (13 §7.1) : empreinte, taille, message, appel, `id`, version, champ inconnu,
  extension, empreinte en majuscules.
- `boundCases` (API, 13 §4.2) et `quotaCases` (`existing` : API ; `sentThisTurn` : worker ; `replay`).

## 6. L00i — vecteurs figés (types d'action, messages de l'agent, web)

Figés par la spécification comme ceux des §4 et §5, mais **sans cryptographie** : ils fixent des règles
(validation, exécutants, politiques, garde de fuite, contrôles d'URL) et des octets exacts à signer. Produits
par un script Python jetable hors du dépôt (supprimé après usage), sur une implémentation de référence des
règles de 12 §4.1 à §4.3, §8.4 et 10 §4.2 à §4.4 ; le JSON canonique est celui de `json.dumps(sort_keys,
separators=(",", ":"))`, identique à JCS pour ces valeurs (clés et chaînes ASCII là où l'ordre compte).

### 6.1 `plan-kinds.json` (12 §4.1, §4.2, §8.4 point 6, §9)

- `validationCases` : plan aux neuf nouveaux `kind` → `ok` ou `plan_invalid` (champ inconnu, bornes de
  texte, 8 000 / 8 001, transfert à 2 000, mentions et fichiers, doublons, 100 / 101 membres, `kind`
  inconnu `space.create`, `threadId` par `argsRefs`).
- `kindRisk` : risque fixe de chaque `kind`, sensibilité, précochage et « toujours accepter ».
- `toolManifest`, `effectivePolicyCases` : politique effective (§2 amendé) selon `toolPolicy`,
  `defaultPolicy` et `risk` ; `auto` lu `ask` pour un outil sensible, sauf la liste fermée
  `sensitiveAutoAllowed` ; manifeste sans `risk` : l'appareil traite l'action comme sensible.
- `policyWriteCases` : écriture de `toolPolicy` → `ok` ou `tool_policy_sensitive_auto`.
- `executorCases` : exécutants conditionnels du mode autonome (`fileIds`, `forwardOf`, auteur du message
  visé, entrée `thread:<id>` déléguée, `argsRefs` vers une action d'agent) ; mêmes résultats attendus du
  worker et de l'appareil (§5, règle 8).
- `targetDigests`, `targetLockCases` : `SHA-256(JCS({ kind, target, argsRefs }))` et verrou de l'API
  (cible de la route, `refs` contre les sorties enregistrées) → `ok` ou `action_not_accepted`.
- `failureCases` : codes d'échec d'une action du §4.2 et cascade PC54 ; formes interdites d'`outcome`.

Rejoués par L15-0 (registre et politiques), L15f (validateur de l'app, exécutants), L15-rt (worker et API).

### 6.2 `message-v3.json` (12 §4.3)

- `parseCases`, `dmParseCases` : analyse du champ `iv` (`m3`, `m2`, ancien) et `nonce` (`d3`) →
  `ok` (avec `parsed`), `ok_m2`, `ok_legacy`, `invalid_format`, `invalid`.
- `bytesCases` : chaînes **exactes** de l'AAD (`synco-msg-v3`, `synco-dm-v3`) et des octets signés
  (`synco-sig-v2`).
- `verifyPolicy` : état attendu (`verified`, `unsigned`, `invalid`) et mention affichée selon l'auteur et
  le mandat.
- `apiCases` : contrôle du préfixe et de l'auteur par l'API (canal du runtime, sockets de l'utilisateur). Depuis
  L00j (PC94), un `m3` `rt1:` sans septième partie `td` est refusé sur le canal du runtime
  (`action_not_accepted`) ; le cas `ok` porte la déclaration de `text-declaration.json`.

**À compléter par L15f** : un générateur TypeScript (`synco_app`, `messageAuth.ts`) produit les chiffrés et
signatures réels (ECDSA de l'utilisateur pour `ai`, `csk` du certificat de test de `mandate-v2.json` pour
`rt1:`), « vérification seulement » pour ECDSA comme au §1, rejoués par la crate (L15-rt). Les valeurs
`iv`, chiffré et signature de ce fichier ne sont que des formes.

### 6.3 `web-guard.json` (10 §4.2, §4.4 ; PC93)

- `normalization` : `N(t)` et découpage en mots.
- `guardContext`, `guardCases` : textes E2EE lus et noms des membres, puis requêtes → `ok` ou `confirm`
  avec la liste **ordonnée** des motifs (`e2ee_passage`, `e2ee_token`, `member_name`, `guard_saturated`).
- `fetchGuardCases` : même garde sur le chemin et la requête décodés d'une URL.
- `provenance` : forme canonique `C(u)` et décision (`ok` ou `confirm`, `url_provenance`).
- `ssrfCases` (adresses résolues données en entrée, redirections), `responseCases` (types, compression,
  taille), `searchBodyCases` (corps de `POST /search`) → `ok` ou le code `web_*` attendu.

Les cas de `ssrfCases` qui portent volontairement une adresse privée ou un nom interne sont écrits sur une
seule ligne avec une `note` contenant le marqueur du hook `pre-commit` (cas de refus attendus, pas des
hôtes réels).

Rejoués par L15-web : la garde et la provenance dans le worker, le reste dans le superviseur (résolveur
simulé : les cas donnent les adresses résolues).

### 6.4 `text-declaration.json` (12 §10.7 ; L00j, PC94)

Déclaration signée par l'utilisateur du texte d'un message autonome. Contrairement à `message-v3.json`, les
signatures sont **réelles** (ECDSA P-256, WebCrypto, scalaires de test `0x11` × 32 pour l'utilisateur et `0x33` × 32
pour un autre membre ; « vérification seulement », §1) et les valeurs dérivées sont exactes. Produit par un
générateur jetable hors dépôt (bun, `node:crypto`) ; L15f le remplace par un générateur qui importe le code réel
de `synco_app` et doit retrouver les mêmes sels, empreintes, octets signés et décisions.

- `saltCases` : sel HKDF-SHA256 depuis `CK` (`ckHex`), `info` exacte.
- `commitCases` : `textCommit` du texte exact ; NFC et NFD, CRLF, espace final, caractère hors BMP donnent des
  empreintes distinctes (aucune normalisation).
- `declarationCases` : déclaration, JCS, octets signés, signature, segment `td`, et préimage du condensat de cible
  (`targetDigestHex` = `serverDigests[n]`, mêmes valeurs que `plan-kinds.json` `targetDigests` pour les objets communs).
- `plaintextCases` : enveloppe `{ salt, text }` stricte et canonique → `ok` ou `invalid_envelope`.
- `cskBytesCases` : octets signés par la `csk` avec le suffixe `|td`, AAD inchangée.
- `parseCases` : `iv` à sept parties (`ok` avec `td`, ou `invalid_format`) ; six parties `rt1:` → `ok`, `td` nul.
- `readerCases` : message déjà valide au sens `m3`, puis `text_verified` ou `text_unverified` avec la raison
  (`absent`, `invalid_declaration`, `signer_mismatch`, `signer_unavailable`, `kind_mismatch`, `target_mismatch`,
  `bad_signature`, `invalid_envelope`, `text_mismatch`) et le texte affiché (`display`) : jamais masqué.
- `apiDecisionCases` : `textDeclarations` de la décision → `ok`, `invalid_body`, `plan_digest_mismatch` (l'API ne
  vérifie pas la signature).
- `apiExecuteCases` : `td` du `iv` contre la déclaration rangée → `ok` ou `action_not_accepted` (égalité octet à
  octet).
- `executorCases` : `argsRefs` hors champs de cible (`text`) → exécutant `device` (s'ajoute à `plan-kinds.json`).

Rejoués par L15f (app : écriture de la déclaration, lecture ; API : contrôles) et L15-rt (worker : sel, contrôle
avant envoi, `iv` ; API côté canal).
