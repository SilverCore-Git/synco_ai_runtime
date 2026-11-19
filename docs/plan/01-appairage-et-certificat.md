# 01 — Appairage et certificat du runtime

Couvre les mesures 1 (certificat), 2 (preuve de possession), 3 (épinglage TOFU), 4 (empreinte) et
la partie « génération » de la mesure 8 (`03_securite.md §3`). Conventions : [00 §3](00-vue-ensemble.md).

## 1. Clés du runtime

Le superviseur génère au **premier démarrage** :

| Nom | Algorithme | Rôle | Vérifiée par |
|---|---|---|---|
| `sig` | Ed25519 | Signe chaque requête du canal interne (04) et la connexion du flux de notifications | synco_api (`node:crypto`, comme `cdnTickets.ts`) |
| `kex` | ECDH P-256 | Clé publique vers laquelle les clients chiffrent l'enveloppe de tête des délégations (03) ; entre dans le défi de possession | le runtime seul (ouverture) ; les clients la certifient |
| `csk` | ECDSA P-256 / SHA-256 | Signe la réponse au défi de possession (§5) et les enveloppes FC4 des clés créées par le runtime (03 §10) | les clients (WebCrypto) |

Pourquoi trois paires :

- `sig` en Ed25519 suit le modèle du CDN (déterministe, vecteurs reproductibles, vérifiée par l'API).
- `csk` en ECDSA P-256 parce que **tout ce que vérifie le navigateur** dans la famille E2EE existante
  est en ECDSA P-256 (signatures FC4 `keyEnvelope.ts:40-44`, certificats d'appareil
  `e2eeV4.ts:423-457`) : même primitive, mêmes encodages, aucune dépendance au support d'Ed25519
  par les WebView mobiles et Tauri.
- `kex` est séparée de `csk` : une clé ne sert jamais à deux primitives.

Chaque clé publique est exposée sous la forme :

| Clé | Encodage |
|---|---|
| `sig` | `b64u` des 32 octets bruts |
| `kex`, `csk` | `JWK-EC` canonique (00 §3.1) |

`runtimeId` : UUID v4 en minuscules, tiré au premier démarrage, conservé dans l'état du runtime avec
les clés. Les clés privées sont **scellées au repos** (mesure 8 : `systemd-creds` ou TPM, sinon
phrase de passe au démarrage, L05) et ne sont jamais écrites en clair sur disque.

Une rotation des clés du runtime = un **nouvel appairage** (nouveau certificat, nouvelle empreinte,
alerte TOFU chez les clients, §8). Il n'y a pas de rotation silencieuse.

## 2. Empreinte et code d'appairage

### 2.1 Empreinte

```
fprInput = "synco-rt-fpr-v1|" runtimeId "|" sig "|" kex "|" csk
fpr      = SHA-256(utf8(fprInput))              (32 octets)
fprHex   = hex(fpr)                               (64 caractères, minuscules)
```

Affichage (dashboard du runtime, Synco) : `fprHex` en **majuscules**, groupes de 4 séparés par une
espace, comme `computeKeyFingerprint` (`synco_app/src/assets/utils/keyTrust.ts:41-45`) :

```
F605 B872 8814 87A9 B37F 903D 997F F879 B94C 5718 856A 5E72 9587 B0E3 9F8F AF2B
```

### 2.2 Code d'appairage

Le code que l'admin recopie depuis le terminal ou le dashboard du runtime dans Synco. Il engage les
**128 premiers bits** de l'empreinte, ce qui suffit contre une seconde préimage. Format identique à
`formatLinkSecret` (`e2eeV4.ts:303-307`) :

```
head  = fpr[0..16]                                   (16 octets)
body  = base32Crockford(head)[0..26]                  (alphabet de e2eeV4.ts:192)
check = base32Crockford(SHA-256(head)[0..3])[0..2]
code  = groupes de 4 de (body ‖ check), séparés par "-"  → 7 groupes, 28 caractères
```

Lecture : insensible à la casse, aux espaces et aux tirets ; `O→0`, `I/L→1` ; somme de contrôle
vérifiée avant toute comparaison (comme `parseLinkSecret`, `e2eeV4.ts:310-318`).

Exemple : `YR2V-GWM8-2J3T-KCVZ-J0YS-JZZR-F459` (empreinte ci-dessus).

## 3. URL canonique du runtime (révisé après la vague B, 2026-11-19)

L'URL entre dans le certificat. Forme canonique (même esprit que `canonicalGatewayUrl`,
`synco_api/src/services/ai/orgAiConfig.ts:43-50`), fixée par L01 dans
`canonical_runtime_url` (`crates/synco-e2ee/src/runtime_cert.rs:224-274`), qui fait foi :

- entrée de 2 048 caractères au plus, sans `?`, `#`, `@`, `\` ni blanc (donc ni identifiants, ni
  requête, ni fragment) ;
- schéma `https` (insensible à la casse en entrée, écrit en minuscules) ; aucune exception en
  production. `http` n'est admis que pour `http://localhost:<port>` et `http://127.0.0.1:<port>`,
  **port explicite obligatoire**, et seulement si l'appelant le demande par un drapeau de
  développement (`UrlPolicy::DevelopmentHttp`, `runtime_cert.rs:276-285` ; défaut `Production`) ;
- hôte en minuscules, ≤ 253 caractères, labels de 1 à 63 caractères `[a-z0-9-]` sans `-` en tête ni
  en fin (pas de `_`, pas d'IDN non encodé, pas de point final) ; **IPv6 refusé** (crochets) ;
- dernier label numérique (`2130706433`, `1.2.3.4.5`) ou hexadécimal (`0x…`) refusé, sauf IPv4
  décimal pointé canonique (quatre octets sans zéro de tête) : un navigateur lirait ces formes comme
  une adresse IPv4 sous plusieurs écritures (`is_unambiguous_host`, `runtime_cert.rs:209-217`) ;
- port de 1 à 5 chiffres, non nul ; 443 omis en `https` ;
- chemin limité à `[A-Za-z0-9-._~/]` (donc ni `%`, ni `|`, ni espace), un seul `/` final retiré,
  ni `//`, ni segment `.` ou `..` ;
- longueur du résultat ≤ 255.

Une URL est **canonique** si `canonical_runtime_url(url) == url` (`check_canonical_url`,
`runtime_cert.rs:287-290`) ; le certificat n'accepte que des URL canoniques (`cert_invalid` sinon).
Code de refus côté client : `url_invalid`.

Exemple : `https://runtime.example.com`. Toutes les routes publiques du runtime sont relatives à
cette URL (`<url>/v1/identity`, etc.).

**Écart connu (00 §6 Q12)** : l'API valide l'URL du certificat avec sa propre règle,
`canonicalRuntimeUrl` (`synco_api/src/services/aiRuntime/runtimeFormats.ts:41-54`, appelée par
`runtimeRegistry.ts:58`), plus permissive (analyse WHATWG) : elle accepte des URL que la crate
refuse (hôte IPv6 `https://[::1]`, `_` dans l'hôte, `//` dans le chemin, caractères `!$&'()*+,;=:@`
dans le chemin) et refuse tout `http`, même sous drapeau de développement. Un tel certificat serait
déposé par l'API puis refusé par chaque client. Les formes ambiguës (numériques, `.`/`..`, `%`) sont
en revanche refusées par l'API aussi, car l'analyse WHATWG les normalise et la forme reçue doit
être déjà canonique.

## 4. Fiche publique du runtime

`GET <url>/v1/identity` — sans authentification, CORS ouvert aux origines configurées (origine de
l'app), cache `no-store`.

```json
{
  "v": 1,
  "runtimeId": "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f",
  "url": "https://runtime.example.com",
  "keys": {
    "sig": "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc",
    "kex": {"crv":"P-256","kty":"EC","x":"1lqTl3yqPRsIGFL_V6eeRl8WYFdzBLrq1QXdOkhYnPM","y":"UBheiVNy32Ih6joTdVfkc_3bZ1XwW9UHw8Uz_OnJEoU"},
    "csk": {"crv":"P-256","kty":"EC","x":"UadYCDOJjqGxg8vXNQpAmQeMbvHB4Y6XDNdoMDXyXn0","y":"ARBSJxKwtafP8IFoVIaYSpTmgx7axG5zYPqdg0p6gaE"}
  },
  "fingerprint": "f605b872881487a9b37f903d997ff879b94c5718856a5e729587b0e39f8faf2b",
  "orgId": null,
  "software": { "name": "synco-ai-runtime", "version": "0.1.0" }
}
```

`orgId` vaut l'org appairée, ou `null` avant appairage. Le client **recalcule** l'empreinte à partir
de `runtimeId` et des clés reçues ; le champ `fingerprint` n'est qu'une aide au diagnostic.

## 5. Défi de possession (mesure 2)

`POST <url>/v1/challenge` — sans authentification, limité en débit par adresse (09 §4), corps ≤ 4 Kio.

Requête :

```json
{
  "v": 1,
  "purpose": "delegate",
  "orgId": "cm3orgexample0000000000001",
  "userId": "66666666-7777-4888-9999-aaaaaaaaaaaa",
  "nonce": "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c",
  "clientEph": {"crv":"P-256","kty":"EC","x":"C7vF6LyEvTPR084D_6yadH9MGZP92y7JOkEWqG8CKnc","y":"w8FxkVWaTCoapX55uNGXfaLJWRcvR440HicCjWn_-3s"}
}
```

| Champ | Contrainte |
|---|---|
| `purpose` | `pair` (appairage par un admin) ou `delegate` (avant une délégation) |
| `orgId`, `userId` | identifiants de l'appelant, tels qu'il les connaît (non vérifiés par le runtime : ils lient seulement la réponse à leur contexte) |
| `nonce` | `b64u` de 32 octets aléatoires tirés par le client |
| `clientEph` | `JWK-EC` d'une paire ECDH éphémère tirée par le client pour ce seul défi |

Le runtime calcule :

```
transcript = "synco-rt-challenge-v1|" purpose "|" runtimeId "|" orgId "|" userId "|" nonce "|" clientEph "|" fprHex
shared     = ECDH(kex_priv, clientEph)                         (coordonnée x, 32 octets, comme WebCrypto deriveBits(256))
K_ch       = HKDF-SHA256(ikm = shared, salt = utf8("synco-rt-challenge-v1"), info = utf8(transcript), L = 32)
mac        = HMAC-SHA256(K_ch, utf8(transcript))
sig        = ECDSA-P256-SHA256(csk_priv, utf8(transcript))     (P1363, 64 octets)
```

Réponse :

```json
{ "v": 1, "runtimeId": "7d3f2c1e-…", "mac": "<b64u 32 o>", "sig": "<b64u 64 o>" }
```

Le client, qui connaît `fprHex` (calculée depuis les clés qu'il a vérifiées), recalcule
`transcript`, `shared` (avec sa clé privée éphémère et `kex`), `K_ch`, et vérifie **les deux** :
`mac` (preuve de détention de `kex_priv`) et `sig` avec `csk` (preuve de détention de `csk_priv`).
Il efface ensuite sa clé éphémère. Le défi ne prouve pas la détention de `sig` : c'est l'API qui la
vérifie, à chaque requête interne signée (04).

Exemple complet : [exemples/exemples.json](exemples/exemples.json), clé `challenge`.

Codes d'erreur (HTTP 400) : `challenge_invalid` (corps, champ ou clé invalide), `challenge_rate_limited`
(429).

## 6. Certificat (mesure 1)

### 6.1 Octets signés

```
certBytes = "synco-rt-cert-v1|" orgId "|" runtimeId "|" url "|" sig "|" kex "|" csk "|" adminId "|" issuedAt "|" serial
```

- `adminId` : identifiant de l'utilisateur qui signe ; `issuedAt` : secondes Unix ; `serial` : entier
  ≥ 1, augmenté de 1 à chaque recertification (changement d'URL par exemple) pour le même
  `runtimeId`.
- Signature : ECDSA P-256 / SHA-256 avec la **clé de signature d'identité** de l'admin
  (`User.publicSignKey`, `synco_api/prisma/schema.prisma:39`), c'est-à-dire la clé des enveloppes FC4.
  Encodage `b64` (64 octets P1363), comme `signKeyEnvelope` (`keyEnvelope.ts:45`).
- L'admin signe **côté client** ; l'API ne signe rien au nom de l'admin (piège de L02).

### 6.2 Forme stockée et servie par l'API

```json
{
  "v": 1,
  "orgId": "cm3orgexample0000000000001",
  "runtimeId": "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f",
  "url": "https://runtime.example.com",
  "keys": { "sig": "0Eqy…hzc", "kex": { "crv": "P-256", "kty": "EC", "x": "…", "y": "…" }, "csk": { "crv": "P-256", "kty": "EC", "x": "…", "y": "…" } },
  "adminId": "11111111-2222-4333-8444-555555555555",
  "issuedAt": 1795000000,
  "serial": 1,
  "signature": "/eMOm477yLCqLufcecivj8XHQ367JVSHsiDxOc5vMCm0Ligt5ohioXhmXxYTN4qOP1VQ3UURMK/qIFef6bxH7w=="
}
```

L'API valide la forme (types, contraintes 00 §3.2, `orgId` = org de la route, `adminId` = appelant)
mais ne vérifie pas la signature comme une preuve : elle n'a pas d'autorité sur la clé de l'admin.
Elle peut la vérifier pour rejeter tôt une erreur de bonne foi.

Contrôles de forme réels de l'API (révisé après la vague B, 2026-11-19 ;
`validateRuntimeCertificate`, `synco_api/src/services/aiRuntime/runtimeRegistry.ts:48-78`) :
exactement les neuf champs ci-dessus et exactement `sig`, `kex`, `csk` dans `keys` ; `v = 1` ;
`runtimeId` UUID en minuscules ; URL canonique (§3, règle de l'API) ; `issuedAt ≤ maintenant + 300`
(`CERT_MAX_FUTURE_SECS`, `:40`) ; `1 ≤ serial ≤ 2³¹ − 1` (colonne `Int`) ; `signature` `b64` canonique
de 64 octets ; `sig` `b64u` canonique de 32 octets ; `kex` et `csk` JWK-EC valides (point sur la
courbe) et **différentes** (une clé, une primitive). Échec : `400 cert_invalid`. La crate applique
les mêmes contraintes côté client (`RuntimeCertificate::validate` et `from_json`,
`crates/synco-e2ee/src/runtime_cert.rs:326-335`, `:382-411`), avec `serial ≤ 2⁵³ − 1`.

Il n'y a pas d'expiration : un certificat vaut jusqu'au désappairage ou au certificat suivant
(`serial` plus grand, mêmes clés).

### 6.3 Vérification par un client (L10)

Dans l'ordre, chaque échec arrête la délégation avec le code indiqué :

1. Forme et contraintes ; `orgId` = org courante ; `runtimeId` = runtime annoncé par l'API pour
   l'org → `cert_invalid`.
2. L'API indique que `adminId` est **actuellement** propriétaire de l'org ou détient la permission
   `ORG_AI` (même règle que `synco_api/src/routes/orgs.ts:244`) → `cert_signer_not_admin`. Ce contrôle
   repose sur la parole de l'API (cf. 00 §6 Q2).
3. Signature vérifiée par `verifyWithSignKeys(adminId, clé servie, …)` (`keyTrust.ts:294`) avec
   résultat **`trusted`** uniquement (`history`, `unknown`, `none` refusés) → `cert_bad_signature`.
4. `GET <url>/v1/identity` en direct : `runtimeId` et les trois clés identiques au certificat →
   `cert_runtime_mismatch`.
5. Épinglage TOFU (§8) → `runtime_key_changed`.
6. Défi de possession (§5) avec `purpose = "delegate"` → `challenge_failed`.

## 7. Parcours d'appairage

1. Premier démarrage : le superviseur génère ses clés (§1). `synco-ai-runtime pair` (ou le dashboard)
   affiche l'URL publique configurée, l'empreinte (§2.1) et le code d'appairage (§2.2).
2. L'admin ouvre *Paramètres de l'org → Synco AI → Runtime* (L11), saisit l'URL et le code.
3. Son client canonise l'URL (§3), appelle `GET <url>/v1/identity` **directement**, recalcule
   l'empreinte et compare ses 128 premiers bits au code saisi → sinon `pair_code_mismatch`. Il refuse
   aussi un runtime dont `orgId` n'est pas `null` ni l'org courante → `runtime_already_paired`.
4. Défi de possession (§5) avec `purpose = "pair"`.
5. Le client signe le certificat (§6.1) avec la clé de signature d'identité déverrouillée et le dépose :
   `POST /api/orgs/:orgId/ai/runtime` (L02, garde : propriétaire ou `ORG_AI`). L'API refuse s'il
   existe déjà un runtime actif pour l'org (`runtime_exists`, 409 ; v1 : un runtime par org). Règles
   exactes de l'API au §7.1.
6. Le client épingle l'empreinte (§8) : l'admin est le premier « témoin ».
7. Le runtime, tant qu'il n'est pas appairé, appelle toutes les 15 s la route signée
   `POST /api/runtime/v1/register` (04 §4). L'API répond `404 rt_unknown` tant qu'aucun certificat ne
   le désigne, puis renvoie `{ orgId, certificate }`. Le runtime vérifie que le certificat porte
   **ses** clés, son `runtimeId` et son URL configurée (sinon il refuse et l'affiche dans le
   dashboard), enregistre l'org, et ouvre son flux de notifications (04 §6). L'API ne compare
   **pas** l'`url` du corps au certificat : c'est le runtime qui le fait
   (`synco_api/src/routes/runtimeInternal/runtime.ts:43-64`).
8. Le runtime récupère la clé publique des tickets (02 §7).

Le runtime refuse un second appairage tant qu'il est appairé (v1 : une seule org).

### 7.1 Registre côté API (révisé après la vague B, 2026-11-19)

Routes utilisateur (`synco_api/src/routes/aiRuntimeAdmin.ts:24-29`), réponses d'erreur
`{ "error": "<code>" }`, toutes `503 runtime_disabled` si les clés de tickets IA ne sont pas
configurées (02 §2) :

| Route | Garde | Succès | Erreurs |
|---|---|---|---|
| `GET /api/orgs/:orgId/ai/runtime` | membre | `{ runtime: null \| RuntimeView, policy, allowedForMe }` | `403 forbidden` |
| `POST /api/orgs/:orgId/ai/runtime` corps `{ certificate }` | propriétaire ou `ORG_AI` | `201 { runtime, recertified: false }` ; `200 { runtime, recertified: true }` | `400 cert_invalid`, `403 forbidden`, `403 ai_disabled`, `409 runtime_exists`, `409 runtime_already_paired`, `409 runtime_id_conflict` |
| `DELETE /api/orgs/:orgId/ai/runtime` | propriétaire ou `ORG_AI` | `{ ok: true, runtimeId, sessions: <nombre de conversations repassées en local> }` | `403 forbidden`, `404 runtime_not_found` |

`RuntimeView` (`aiRuntimeAdmin.ts:37-60`) : `{ runtimeId, url, fingerprint, certificate, certSerial,
online, lastSeenAt, registeredAt, pairedAt, pairedById, softwareVersion, signer: { adminId, isAdmin },
workers, metrics }`. `signer.isAdmin` dit si le signataire du certificat est **actuellement**
propriétaire ou détient `ORG_AI` : c'est la réponse de l'API à l'étape 2 de §6.3 (parole de l'API,
00 §6 Q2). `allowedForMe` = module IA actif et politique runtime de l'org qui autorise l'appelant
(07 §6).

Règles du dépôt (`pairRuntimeUncached`, `synco_api/src/services/aiRuntime/runtimeStore.ts:255-307`) :

| Situation | Résultat |
|---|---|
| L'org a un runtime actif, même `runtimeId`, mêmes trois clés, `serial` **plus grand** | **Recertification** : URL, certificat et `serial` remplacés → `200`, `recertified: true` (`:266-275`). Le changement d'URL passe donc par un `POST`, pas par une route dédiée. |
| L'org a un runtime actif, autre runtime, autres clés ou `serial` non supérieur | `409 runtime_exists` (`:270`) |
| Le `runtimeId` est actif dans une **autre** org | `409 runtime_already_paired` (`:279`) |
| Le `runtimeId` existe désappairé (`revoked`), même org **et** mêmes trois clés | Ligne réutilisée et réactivée (nouveau `pairedById`, `pairedAt`, présence remise à zéro) ; ses anciennes délégations et autorisations **restent révoquées** (`:286-299`) |
| Le `runtimeId` existe désappairé, mais autre org ou autres clés | `409 runtime_id_conflict` : un nouveau `runtimeId` est obligatoire (`reset-keys`, §9) ; une ligne n'est jamais rattachée à une autre org ni à une autre identité (`:280-285`) |
| Sinon | Nouvelle ligne → `201` |

Évènement socket `ai:runtime-changed` `{ orgId, runtimeId, change, online }` vers l'org, `change` ∈
`paired` | `recertified` | `unpaired` | `presence` (`runtimeRegistry.ts:123-141`).

## 8. Épinglage TOFU côté client (mesure 3)

Magasin local existant de l'app (IndexedDB via `idb-keyval`, comme `keyPinning.ts:56-61`) :

```
clé     : "rt-pin:" <utilisateur local> ":" <orgId>
valeur  : { "v": 1, "runtimeId": "…", "fpr": "<fprHex>", "firstSeen": <s>, "previous": [ { "runtimeId": "…", "fpr": "…", "until": <s> } ] }
```

- **Première vue** (pas d'entrée) : le client affiche l'empreinte et le signataire du certificat
  (« Runtime certifié par <nom de l'admin> ») et demande une confirmation explicite avant la première
  délégation ; puis il épingle. L'admin qui appaire épingle à l'étape 6 de §7.
- **Vue suivante** : `runtimeId` et `fpr` doivent être identiques à l'épingle. Sinon : refus
  (`runtime_key_changed`), alerte persistante, **aucune délégation**. Une recertification (nouvelle
  URL, `serial` plus grand) avec la **même** empreinte est acceptée sans alerte.
- **Accepter une nouvelle clé** : uniquement par une action explicite de l'utilisateur, après
  affichage de l'ancienne et de la nouvelle empreinte (comme `repinKey`, `keyPinning.ts:65-67`).
  L'ancienne épingle passe dans `previous`.
- L'épingle n'est **jamais** effacée sur la seule parole de l'API : après un désappairage (§9), elle
  passe dans `previous` et le runtime suivant est traité comme une **première vue avec alerte**
  (« le runtime de l'organisation a changé »), jamais silencieusement.

## 9. Désappairage

Déclencheurs : un admin (propriétaire ou `ORG_AI`) dans les paramètres, ou l'opérateur du runtime
(`synco-ai-runtime unpair`, qui appelle la route signée `POST /api/runtime/v1/unpair`).

Côté API (L02/L03), dans une même transaction :

1. `AiRuntime.status = "revoked"`, `revokedAt`, `revokedById` ; `activeOrgId = null` (07 §2).
2. Toutes les délégations du runtime passent `revoked` (raison `runtime_unpaired`) ; toutes les
   autorisations de session passent `revoked` ; les conversations en régime `runtime` repassent en
   régime local avec le statut `idle` (08 §3).
3. Évènement `runtime.unpaired` sur le flux du runtime (04 §6) et évènement socket `ai:runtime-changed`
   vers les membres de l'org.

Précisions (révisé après la vague B, 2026-11-19 ; `unpairRuntimeUncached`,
`synco_api/src/services/aiRuntime/runtimeStore.ts:310-355`, `unpairAndNotify`,
`runtimeRegistry.ts:123-137`) :

- **toutes** les entrées (`thread`, `space`, `conv`) de **toutes** les délégations du runtime sont
  supprimées dans la transaction (`:335`) : rien de chiffré pour ce runtime ne survit au
  désappairage ;
- chaque conversation repassée en local reçoit un `AiChatSessionEvent` `switch_to_local` (code
  `runtime_unpaired`) et son propriétaire l'évènement socket `ai:session-status` ;
- le bail est clos par `leaseHolder = null`, `leaseExpiresAt = null` et le passage en régime
  `client` (`:345`), **sans** incrément de `leaseEpoch`, contrairement à la règle commune de 08 §2 :
  aucune écriture n'est plus possible (elles exigent le régime `runtime` et `leaseHolder` = runtime,
  07 §4.3) et le runtime révoqué est refusé dès l'étape 3 de 04 §2.3 ; une bascule ultérieure
  incrémente `leaseEpoch` (04 §5) ;
- le flux reçoit `runtime.unpaired` puis est fermé (`4401 rt_revoked`) ;
- réponses : route admin, §7.1 ; route du runtime `POST /api/runtime/v1/unpair` → `{ ok: true }`,
  ou `401 rt_revoked` si plus rien à désappairer (`runtime.ts:66-79`).

Côté runtime (L05) : à réception de `runtime.unpaired`, ou si l'API répond `rt_revoked` : arrêt des
workers de l'org (sans attendre la fin de l'étape), effacement en mémoire de toutes les clés
déléguées, oubli de l'org ; il redevient « non appairé » avec les **mêmes** clés. Pour changer de
clés : commande explicite `synco-ai-runtime reset-keys` (nouvel appairage obligatoire).

Côté client : §8 (épingle archivée, jamais effacée silencieusement).

## 10. Codes d'erreur de ce document (révisé après la vague B, 2026-11-19)

| Code | Où | Sens |
|---|---|---|
| `url_invalid` | client | URL non canonisable (§3 ; `Error::UrlInvalid`, `crates/synco-e2ee/src/error.rs:85`) |
| `pair_code_invalid` | client | Code saisi illisible (longueur, caractère, somme de contrôle) |
| `pair_code_mismatch` | client | L'empreinte des clés servies par l'URL ne correspond pas au code saisi |
| `runtime_already_paired` | client, API 409 | Le runtime est déjà appairé à une autre org (côté API : `runtimeId` actif ailleurs, §7.1) |
| `runtime_exists` | API 409 | L'org a déjà un runtime actif (ou recertification sans clés identiques ni `serial` plus grand) |
| `runtime_id_conflict` | API 409 | `runtimeId` désappairé présenté avec une autre org ou d'autres clés (§7.1) |
| `runtime_not_found` | API 404 | Désappairage demandé sans runtime actif |
| `runtime_disabled` | API 503 | Module runtime de l'API non configuré (clés de tickets IA absentes, 02 §2) |
| `ai_disabled` | API 403 | Module IA désactivé ou org bannie (dépôt du certificat) |
| `forbidden` | API 403 | Appelant non membre, ou non admin pour `POST`/`DELETE` |
| `cert_invalid` | client, API 400 | Forme ou contrainte invalide |
| `cert_signer_not_admin` | client | Le signataire n'est pas (ou plus) admin selon l'API |
| `cert_bad_signature` | client | Signature non vérifiée par une clé de confiance de l'admin |
| `cert_runtime_mismatch` | client | Les clés servies par le runtime diffèrent du certificat |
| `runtime_key_changed` | client | Empreinte différente de l'épingle TOFU |
| `challenge_invalid` / `challenge_rate_limited` | runtime 400 / 429 | Défi mal formé / trop de défis |
| `challenge_failed` | client | `mac` ou `sig` invalide |
| `rt_unknown` / `rt_revoked` | API 404 / 401 | Runtime inconnu / désappairé (04 §8) |

## 11. Risques connus, non corrigés en v1 (révisé après la vague B, 2026-11-19)

Relevés à la relecture de L02 (`synco_api/vibe/features/SYNCOAI_REFONTE_FEATURE.md` §10.4) et acceptés :

- **État d'un `runtimeId` révélé** : `409 runtime_already_paired` / `runtime_id_conflict` dit à un
  admin d'une org quelconque qu'un `runtimeId` est (ou a été) appairé ailleurs. Le `runtimeId` n'est
  pas secret (servi aux membres de son org, publié par `GET <url>/v1/identity`) ; l'information est
  jugée faible.
- **Pas de preuve de possession de `sig` à l'appairage** : le défi (§5) porte sur `kex` et `csk` et
  c'est le client de l'admin qui le vérifie ; l'API ne reçoit aucune preuve que le runtime détient
  la clé privée `sig` du certificat. Un certificat portant la clé `sig` d'un autre runtime ne donne
  rien sans sa clé privée (aucune requête signée possible, 04 §2), mais il occupe l'emplacement
  « runtime actif » de l'org jusqu'au désappairage par un admin (déni de service par un admin de
  l'org, qui peut de toute façon désappairer).
- **État propre à l'instance** : cache anti-rejeu (04 §2.3), présence et métriques (04 §6), cache de
  `findRuntime` et de l'état IA de l'org (5 s, `synco_api/src/services/aiRuntime/runtimeStore.ts:135-148`)
  ne sont pas partagés : un déploiement multi-instance de l'API devra les partager.
