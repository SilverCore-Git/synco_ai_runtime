# Vecteurs de test à produire (L01, L02)

Ce dossier ne contient **pas** de vecteurs : il liste ceux que L01 et L02 doivent produire, sur le
modèle de `synco_cdn/tests/vectors/` (`generate.mjs` + `tickets.json` : un générateur TypeScript ou
JavaScript, le fichier JSON commité, la même suite rejouée des deux côtés).

Les exemples de [../exemples/](../exemples/) illustrent la spec avec `node:crypto` ; ils ne
remplacent pas ces vecteurs, qui doivent être produits **avec le code réel** (fonctions de
`synco_app/src/assets/utils/` pour les formats E2EE, `synco_api/src` pour les tickets et la signature
interne).

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
