# 13 — Fichiers envoyés par l'agent dans la conversation (artefacts, figé par L00g, 2026-11-23)

Source : décisions PC71, PC72, PC77, PC81 et PC82 à PC85 (00 §5), conception C3 (§1.5 et annexe A,
`.claude/prompts/syncoai_refonte/conception/C3_front.md`), interface `ArtifactSource` déjà posée par L12
(`synco_app/src/services/aiRuntime/artifacts/artifactModel.ts`). Ce document fige ce dont le runtime
(outil), l'API (stockage, routes) et l'app (source, affichage, enregistrement) ont besoin pour travailler
en parallèle. Il ne change aucun format existant : il **ajoute** un outil, un modèle, trois routes et une
trame.

Conventions : 00 §3. Colonne « Auth » : **S+A**, **U-prop** comme en 12 (en-tête). Erreurs :
`{ "error": "<code>" }`, codes au §10. Les choix du §13 sont tranchés (PC82 à PC85, 2026-11-23).

## 1. Principe

- L'agent peut **envoyer un fichier texte dans la conversation**, comme une pièce jointe en message
  privé (PC72). Ce n'est pas un effet sur l'org : l'outil est **hors plan d'action** (12 §2) et sans
  confirmation.
- v1 : **texte UTF-8 seulement**, extensions de `textFileFormats.ts` (PC71) ; aucun binaire.
- Tout est **chiffré de bout en bout sous `CK`** (03 §6) : le nom, l'extension, la taille exacte,
  l'empreinte et le contenu. L'API ne voit qu'un identifiant, la conversation, la longueur du chiffré et
  une date (§4).
- L'artefact vit **avec la conversation** et disparaît avec elle (§4.3). « Enregistrer dans un espace »
  en fait une **copie** indépendante, par une action d'appareil faite avec la clé de l'utilisateur (§8).
- Affichage par le **même composant** que les pièces jointes des messages, `MessageAttachments.vue`
  (PC77) ; Markdown rendu **sans HTML**, tout autre format montré en texte brut ; **aucun HTML n'est
  exécuté** (§7).
- PC81 : rien ne change pour la délégation. Le worker chiffre avec la `CK` qu'il détient déjà ; le
  durcissement de l'enveloppe FC4 (L00h) ne touche pas ce format.

## 2. Outil du worker : `send_file`

### 2.1 Appel du modèle

```json
{ "name": "budget-lancement", "ext": "csv", "content": "poste;montant €\n…" }
```

| Champ | Règle (worker, §2.2) |
|---|---|
| `name` | chaîne, nom affiché du fichier, avec ou sans extension |
| `ext` | chaîne, extension de la liste `TEXT_FILE_FORMATS` de `synco_app/src/assets/utils/textFileFormats.ts` (25 valeurs, recopiées dans le vecteur `formats`) : `txt md log csv json xml yml ini sql html css scss js ts vue py sh java c cpp cs php go rs rb` |
| `content` | chaîne, texte du fichier |

L'outil est **propre au worker**, comme `propose_actions` (12 §3.1) : il n'est pas dans le manifeste
de l'API (`GET …/tools`), le worker l'ajoute lui-même à la liste donnée au modèle. Dans le transcript,
l'appel porte `category: "client"`, `mutating: false`, `interactive: false` (valeurs déjà connues de
l'app ; aucune nouvelle catégorie).

**Description de l'outil donnée au modèle**, à reprendre telle quelle :

> Envoie un fichier texte dans la conversation, comme une pièce jointe : l'utilisateur pourra l'ouvrir,
> le télécharger ou l'enregistrer dans un de ses espaces. Utilise-le quand le résultat est un document à
> garder (code, tableau CSV, note Markdown, configuration…), plutôt que de le recopier dans ta réponse.
> `ext` est l'une des extensions permises ; `content` est le texte complet, **256 Kio au plus**. Au plus
> 5 fichiers par réponse et 20 par conversation. Tu ne pourras pas relire le fichier après l'envoi :
> résume dans ta réponse ce qu'il contient. Pour créer un fichier directement dans un espace, propose
> plutôt un plan d'action (`file.create_text`).

### 2.2 Validation par le worker (référence : vecteurs `nameCases`, `contentCases`)

Dans cet ordre ; le premier refus rend au modèle `{"error":"<code>"}` (§10), rien n'est écrit, le tour
continue.

1. **`ext`** : un `.` initial retiré, minuscules ASCII ; absente de la liste → `artifact_format`.
2. **`name`** : espaces retirés aux deux bouts ; refus (`artifact_name`) s'il est vide, s'il contient
   `/ \ : * ? " < > |`, un caractère de contrôle (U+0000–U+001F, U+007F–U+009F), une marque bidi ou
   invisible (U+200B–U+200F, U+202A–U+202E, U+2060–U+2069, U+FEFF), s'il commence ou finit par `.`.
3. **Nom final** (règle de `buildFileName`) : si la dernière extension de `name` (comparée sans casse)
   vaut `ext`, `name` tel quel ; sinon `name + "." + ext` (`notes.txt` + `md` → `notes.txt.md`). Plus
   de **120 points de code** → `artifact_name`.
4. **`content`** : vide ou contenant U+0000 → `artifact_not_text` ; plus de **262 144 octets UTF-8**
   (256 Kio) → `artifact_too_large` (la borne compte des octets, pas des caractères).
5. **Bornes de nombre** : 5 artefacts **déposés** dans le tour en cours (du message de l'utilisateur à
   l'état suivant hors `running`) → `artifact_turn_limit` ; 20 dans la conversation → `artifact_quota`
   (le worker le sait par la réponse de l'API, §5.1).

### 2.3 Exécution

1. Le worker tire `id` (UUID v4), calcule `size` = longueur UTF-8 de `content` et `sha256` =
   SHA-256 de ces octets en hexadécimal **minuscule**.
2. Il chiffre les métadonnées et le contenu (§3) et dépose l'artefact (`POST …/artifacts`, §5.1).
   Réponse `201` ou `200` (rejeu) : succès. `409 artifact_quota` : résultat `artifact_quota`.
   Erreur de transport : **un** nouvel essai avec le même `id` et les mêmes valeurs (idempotent) ;
   sinon `artifact_not_sent`. Aucun état « issue inconnue » : l'outil ne touche pas l'org.
3. Il émet la trame `artifact` (§6.1).
4. Résultat d'outil donné au modèle (champ `toolResult`, chiffré comme tout résultat, 03 §6.3) :
   `{ "artifactId": "<id>", "name": "<nom final>", "size": <octets> }`.

### 2.4 Ce que le transcript garde de l'appel

Le contenu **n'est pas** recopié dans l'historique (il est déjà dans l'artefact ; 20 × 256 Kio
alourdiraient chaque `PUT …/transcript` et chaque appel au modèle). Les arguments enregistrés
(`toolCalls[i].arguments`, AAD `tool_call_arguments:<toolCallId>`, inchangée) et rejoués au modèle aux
tours suivants sont la **forme réduite** :

```json
{ "artifactId": "8e9f0a1b-2c3d-4e5f-8a6b-7c8d9e0f1a2b", "ext": "csv", "name": "budget-lancement.csv" }
```

La trame `tool_call` (05 §5.3) porte la même forme réduite. Le statut de l'appel passe `done` (succès)
ou `error` (refus du §2.2, dépôt impossible).

### 2.5 Politique d'outil et plan

- Politique D5 (`toolPolicy`, 06 §3) : `deny` retire l'outil de la liste donnée au modèle ; toute autre
  valeur vaut `auto` (outil non mutant, sans effet sur l'org). Défaut : `auto`.
- Disponible en mode plan comme en mode autonome, et **jamais** comme action d'un plan (12 §4 inchangé).
  Pendant un plan accepté, l'agent peut envoyer un fichier dans sa réponse de bilan.
- Régime local ou `server` : l'outil n'existe pas (v1 : runtime seulement). Les artefacts déjà reçus
  restent lisibles après le retour de la conversation en local (§5.2).

## 3. Format et chiffrement

Deux valeurs `gcm1:` (03 §6.3) sous la `CK` de la conversation, **même `artifactId` en position de
`messageId` de l'AAD** :

| Valeur | Clair | AAD |
|---|---|---|
| `meta` | `JCS(meta)` (12 §3.3 : RFC 8785, entiers seulement), **≤ 1 024 octets** | `utf8(sessionId ":" artifactId ":artifact_meta")` |
| `value` | les octets UTF-8 de `content`, tels quels, **≤ 262 144 octets** | `utf8(sessionId ":" artifactId ":artifact")` |

```json
{ "v": 1, "id": "<artifactId>", "sessionId": "<conversation>", "messageId": "<message assistant porteur>",
  "toolCallId": "call_3", "name": "budget-lancement.csv", "ext": "csv", "size": 49, "sha256": "<64 hex>" }
```

| Champ de `meta` | Règle |
|---|---|
| `v` | `1` ; toute autre valeur : illisible |
| `id`, `sessionId`, `messageId`, `toolCallId` | identifiants 00 §3.2 ; lient l'artefact à **sa** conversation, **son** message et **son** appel (§6.2) |
| `name` | nom final du §2.2 (≤ 120 points de code) ; l'app l'assainit encore (§7.1) |
| `ext` | élément de la liste du §2.1 ; le type MIME n'est **pas** stocké, l'app le déduit de `ext` (`findTextFormat`) |
| `size` | entier, octets UTF-8 du contenu |
| `sha256` | `^[0-9a-f]{64}$`, SHA-256 des octets du contenu |

Objet **strict** : un champ inconnu rend l'artefact illisible (v1). Lecture future d'un `v: 2` : à
définir avec lui (règle maison : lire l'ancien, écrire le nouveau).

Le nom de champ distinct (`artifact_meta` / `artifact`) empêche d'ouvrir l'un pour l'autre ;
`artifactId` et `sessionId` dans l'AAD empêchent de rejouer un artefact sous un autre identifiant ou
dans une autre conversation ; le contenu est lié aux métadonnées par `sha256` et `size`, les
métadonnées au message par `messageId` et `toolCallId` (vecteurs `encryptionCases`, `verifyCases`).

## 4. Stockage (API)

### 4.1 Modèle

```prisma
model AiChatArtifact {
  pk         String        @id @default(cuid())
  sessionId  String
  session    AiChatSession @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  artifactId String        // UUID v4 tiré par le worker
  meta       String        /// @encrypted   (gcm1: sous CK, ≤ 1 409 caractères)
  value      String        /// @encrypted   (gcm1: sous CK, ≤ 349 569 caractères)
  size       Int           // longueur de `value` en caractères (pas la taille claire)
  createdAt  DateTime      @default(now())

  @@unique([sessionId, artifactId])
  @@index([sessionId, createdAt])
}
```

Et sur `AiChatSession` : `artifactCount Int @default(0)` et la relation `artifacts AiChatArtifact[]`.

- **Aucune colonne en clair** ne porte le nom, l'extension, la taille exacte, l'empreinte, le message
  ou l'appel. L'API ne connaît que `artifactId`, la conversation, la longueur du chiffré et la date.
- `artifactId` est unique **dans la conversation** (`@@unique`), pas globalement : un runtime ne peut
  pas sonder l'existence d'un identifiant d'une autre conversation.
- `/// @encrypted` : double couche, comme `ThreadKey.encryptedKey` (07, en-tête).

### 4.2 Bornes appliquées par l'API (§5.1)

- `meta` et `value` commencent par `gcm1:` ; `meta` ≤ **1 409** caractères (5 + 4·⌈(12 + 1 024 + 16)/3⌉),
  sinon `400 invalid_body` ; `value` ≤ **349 569** caractères (5 + 4·⌈(12 + 262 144 + 16)/3⌉), sinon
  `413 artifact_too_large`. Le corps complet (≈ 350 Ko) **dépasse** le plafond de 256 Kio du canal : la route de dépôt a son propre plafond de **1 Mio** (04 §1, comme `POST …/plans`).
- Au plus **20 artefacts par conversation** : `updateMany` conditionné sur `AiChatSession`
  (`where: { id, artifactCount: { lt: 20 } }`, `data: { artifactCount: { increment: 1 } }`) dans la
  transaction qui crée la ligne ; `count = 0` → `409 artifact_quota`. Aucun SQL brut ; le compteur ne
  redescend jamais (un artefact orphelin, §6.3, compte).

### 4.3 Cycle de vie et purge

- **Créé** par le worker, jamais modifié (un rejeu identique ne réécrit rien).
- **Supprimé avec la conversation** (`onDelete: Cascade`) : suppression par l'utilisateur, purge de
  rétention, suppression du compte ou de l'org, tous passent par la suppression de `AiChatSession`.
  Aucune route ne supprime un artefact seul en v1.
- « Télécharger » produit un fichier local, hors de Synco ; « Enregistrer dans un espace » crée un
  **nouveau** fichier qui suit la vie de l'espace (§8).

### 4.4 Catalogue RGPD

Ligne ajoutée au catalogue de 07 §11 :

| Donnée | Où | Personne concernée | Finalité | Conservation |
|---|---|---|---|---|
| Fichier remis par l'agent : métadonnées et contenu chiffrés sous `CK` ; en clair, identifiant, longueur du chiffré, date | `AiChatArtifact` | propriétaire de la conversation | remettre à l'utilisateur le fichier produit à sa demande (PC72) | **vie de la conversation** ; visible dans « Mes données » avec les conversations |

## 5. Routes

### 5.1 Canal du runtime (ajout à 04 §4.2)

| Méthode et chemin | Auth | Corps | Succès | Refus |
|---|---|---|---|---|
| `POST /api/runtime/v1/conversations/:sessionId/artifacts` | S+A, bail | `{ "leaseEpoch", "id", "meta": "gcm1:…", "value": "gcm1:…" }` (strict) | `201 { "id" }` ; même `id`, mêmes `meta` et `value` : `200 { "id" }` | `400 invalid_body` (forme, `id` non UUID, préfixe, `meta` trop long), `413 artifact_too_large`, `409 artifact_exists` (même `id`, autre valeur), `409 artifact_quota`, `409 lease_conflict`, `409 not_runtime`, `429 rt_rate_limited` |

Ordre des contrôles : signature et autorisation (04 §2, §3) ; bail courant ; régime `runtime` et
`encryptionScheme = conv-gcm1-v1` ; forme du corps ; existence de `(sessionId, id)` (rejeu ou
`artifact_exists`) ; quota et création dans une transaction. Débit : 10 dépôts / min par conversation
(en plus du limiteur du canal). Le worker ne relit pas les artefacts : **aucune** route de lecture
côté runtime.

### 5.2 Utilisateur (montées sous `/api/orgs/:orgId/ai/sessions/:sessionId`)

| Méthode et chemin | Auth | Succès | Refus |
|---|---|---|---|
| `GET /artifacts` | U-prop | `200 { "items": [{ "id", "meta": "gcm1:…", "size", "createdAt" }] }`, 20 au plus, par `createdAt` croissant, sans pagination | `404 not_found` |
| `GET /artifacts/:artifactId` | U-prop | `200 { "id", "meta": "gcm1:…", "value": "gcm1:…" }` | `404 not_found` (inconnu, autre conversation, autre propriétaire : même réponse) |

- U-prop : propriétaire de la conversation seulement, module IA actif, org non bannie ; limiteur des
  routes `/ai` existant. Lisibles **quel que soit le régime** (y compris après retour en local).
- `Cache-Control: no-store`. Aucun journal ne porte `meta` ni `value`.
- L'app tire la liste des métadonnées (nom, taille, type, empreinte) en déchiffrant `meta` de chaque
  élément : l'API n'en connaît aucune.

## 6. Trame et message porteur

### 6.1 Trame WebSocket `artifact` (ajout à 05 §5.3)

```json
{ "v": 1, "t": "artifact", "epoch": 2, "seq": 43, "messageId": "<message assistant>",
  "toolCallId": "call_3", "artifactId": "<id>" }
```

Émise par le runtime **après** le `201` / `200` du dépôt : l'artefact est lisible par la route du §5.2.
Identifiants seulement, en clair comme les autres identifiants des trames (05 §4) ; aucun nom, aucune
extension, aucune taille. Rejouée comme les autres évènements (05 §3). Un client qui ne la connaît pas
l'ignore (05 §2).

### 6.2 Message porteur

- L'artefact est rattaché au **message assistant qui porte l'appel** `send_file` (`messageId`,
  `toolCallId`), et s'affiche sous ce message.
- **Référence** = `{ sessionId, messageId, toolCallId, artifactId }`. En direct : lue dans la trame
  `artifact`. Au rechargement : lue dans le transcript, pour chaque `toolCalls[i]` de nom `send_file`
  et de statut `done`, dans les arguments déchiffrés (forme réduite du §2.4). Le format de
  `StoredMessage` ne change pas.
- L'app vérifie que `meta` déchiffré porte exactement cette référence (§7.1) : un artefact déplacé
  vers un autre message, un autre appel ou une autre conversation est illisible.

### 6.3 Artefact orphelin

Si l'écriture du transcript échoue après le dépôt (bail perdu, plantage), la ligne existe sans appel
qui la référence. L'app n'affiche **que** les artefacts référencés par un appel `send_file` `done` ; un
orphelin reste invisible, compte dans le quota et disparaît avec la conversation. Le worker suivant ne
le réutilise pas.

## 7. Affichage dans l'app

### 7.1 `ArtifactSource` et contrôles (référence : vecteurs `verifyCases`)

L'interface posée par L12 reste : `ArtifactSource.read(id)` rend le contenu clair déchiffré sous `CK`.
Implémentation (`…/artifacts/:artifactId` puis déchiffrement), dans cet ordre ; tout écart rend
l'artefact **illisible** (`ArtifactUnreadableError`, carte grise « Fichier illisible sur cet appareil ») :

1. `meta` ouvert sous `CK` (AAD du §3), JSON strict ; `v = 1` ; `id`, `sessionId`, `messageId`,
   `toolCallId` = la référence (§6.2) ; `ext` dans la liste ; `size` entier de 1 à 262 144 ; `sha256`
   conforme à `^[0-9a-f]{64}$` (pas de majuscules : plus strict que `artifactMatches`, qui met en
   minuscules) ; `name` chaîne non vide.
2. `value` ouvert sous `CK` ; longueur des octets = `size` ; SHA-256 = `sha256` (`readVerified`).
3. `ArtifactMeta` construit par l'app : `name` = `sanitizeArtifactName(meta.name)` avec l'extension
   forcée à `ext`, `mimeType` = celui de `findTextFormat(ext)`, `size`, `sha256`.

Le clair n'est gardé **qu'en mémoire** le temps de la vue (aucun cache persistant, ni IndexedDB ni
stockage local) ; la suppression de la conversation ferme la visionneuse et vide ce cache.

### 7.2 Carte et visionneuse (C3 §1.5, PC77)

- **Carte** : `MessageAttachments.vue`, sans variante, avec `download` fourni par l'appelant (source
  `ArtifactSource`), l'action optionnelle `saveToSpace` et `open` (visionneuse).
- **Markdown** (`md`) : rendu par `parseMarkdown` (blocs, **interpolation de texte**), sans HTML : aucune
  balise interprétée, aucun lien actif, aucune image chargée.
- **Tout autre format**, `html`, `vue`, `js`, `sh`, `php`, `xml` compris : texte brut dans un `<pre>`
  (interpolation de texte ; une éventuelle coloration ne produit que des nœuds texte). **Aucun `v-html`,
  aucun `iframe`, aucune URL `blob:` ouverte dans un onglet**, aucun lien suivi automatiquement.
- **Télécharger** : `Blob` de type `application/octet-stream` et nom assaini ; jamais d'ouverture dans
  le navigateur. **Copier** : `navigator.clipboard.writeText`.
- **Fichier long** : déchiffré en entier (≤ 256 Kio), affiché progressivement par la visionneuse.

## 8. « Enregistrer dans un espace » (action d'appareil)

- Faite par **l'utilisateur**, sur son appareil, avec **sa** clé : c'est la création de fichier texte
  existante, celle de `file.create_text` (12 §4 : chiffrement du fichier par l'appareil sous la clé de
  l'espace, `createTextFile`), appelée **hors plan** : pas d'en-tête `X-Synco-Plan`, pas de
  `AiActionPlan`, aucun passage par le runtime.
- Entrées : espace et dossier choisis dans la liste cherchable (C3 §1.5) ; `name` = nom assaini du §7.1
  (≤ 120, donc dans la borne de 255 de `file.create_text`) ; `content` = le clair **vérifié** du §7.1 ;
  type MIME de `findTextFormat(ext)`. Droits : ceux de l'utilisateur sur l'espace (refus de l'API
  existants, affichés tels quels).
- Hors ligne : bouton désactivé (C3 §1.5). Aucun lien n'est gardé entre la copie et la conversation :
  la copie suit les règles de l'espace (pied de la visionneuse).

## 9. Bornes

| Élément | Borne |
|---|---|
| Contenu d'un artefact | 1 à **262 144 octets** UTF-8 (256 Kio), sans U+0000 (PC85) |
| Nom final | 1 à **120** points de code, extension comprise |
| Formats | les 25 extensions de `textFileFormats.ts` (PC71) |
| Par tour | **5** artefacts déposés (worker, PC82) |
| Par conversation | **20** artefacts, orphelins compris (API, PC82) |
| Clair de `meta` | ≤ 1 024 octets ; `gcm1:` ≤ 1 409 caractères |
| `value` | `gcm1:` ≤ 349 569 caractères |
| Dépôt | corps ≤ **1 Mio** (plafond propre à la route, ≈ 350 Ko au plus en pratique) ; 10 / min par conversation |
| Liste | 20 éléments, sans pagination |

## 10. Codes d'erreur

| Code | Où | Sens |
|---|---|---|
| `artifact_format` | résultat d'outil | `ext` hors liste |
| `artifact_name` | résultat d'outil | nom vide, interdit ou trop long (§2.2) |
| `artifact_not_text` | résultat d'outil | contenu vide ou contenant U+0000 |
| `artifact_too_large` | résultat d'outil (champ `max`), API `413` | contenu > 256 Kio / `value` trop longue |
| `artifact_turn_limit` | résultat d'outil | 6e artefact du tour |
| `artifact_quota` | résultat d'outil, API `409` | 21e artefact de la conversation |
| `artifact_exists` | API `409` | même `id`, autre valeur |
| `artifact_not_sent` | résultat d'outil | dépôt impossible après un nouvel essai (transport, `5xx`) |
| `artifact_unreadable` | app | contrôle du §7.1 en échec (carte grise) |

## 11. Menaces et parades

| Menace | Parade | Test |
|---|---|---|
| L'API ou un tiers lit le nom ou le contenu | tout sous `CK` ; aucune colonne en clair (§4.1) | `encryptionCases` ; revue du schéma |
| L'API déplace un artefact vers une autre conversation, un autre message, un autre appel | AAD (`sessionId`, `artifactId`) ; `messageId`, `toolCallId` dans `meta` (§7.1) | `encryptionCases`, `verifyCases` |
| L'API échange `meta` et `value`, ou le contenu de deux artefacts | nom de champ dans l'AAD ; `sha256`, `size` | `encryptionCases`, `verifyCases` |
| Un modèle manipulé envoie du HTML ou du script | jamais interprété (§7.2) ; téléchargement en `octet-stream` | test de rendu de l'app (`<script>`, `onerror`) |
| Nom piégé (chemin, bidi, contrôle) | refus du worker (§2.2), assainissement de l'app (§7.1) | `nameCases` |
| Saturation du stockage par un worker | 256 Kio × 20 par conversation, débit du dépôt | `quotaCases`, `boundCases` |
| Sonde d'identifiants entre conversations | unicité par conversation, `404` uniforme | test API |
| Fichier qui survit à la conversation | `onDelete: Cascade`, aucun cache persistant de l'app | test API de suppression |

## 12. Vecteurs

[`vectors/artifacts.json`](vectors/artifacts.json), figés par la spécification comme `action-plan.json`
(vectors/README.md §5) et rejoués sans modification : métadonnées et contenu chiffrés exacts (IV fixes),
forme réduite des arguments et résultat d'outil, corps de dépôt, élément de liste, trame, puis
`nameCases`, `contentCases`, `encryptionCases`, `verifyCases`, `boundCases`, `quotaCases`.

## 13. Choix tranchés (2026-11-23)

| # | Choix | Décision |
|---|---|---|
| A1 | Taille d'un fichier | **PC85** : **256 Kio** (262 144 octets). Les fichiers plus gros relèvent de l'atelier d'exécution (PC73). Le corps de dépôt (≈ 350 Ko) dépasse le plafond de 256 Kio du canal : plafond propre à la route, 1 Mio |
| A2 | Nombre par conversation | **PC82** : **20**, orphelins compris (5,0 Mio de stockage au plus, en clair) |
| A3 | Nombre par tour | **PC82** : **5** |
| A4 | Relecture par le modèle | **PC83** : **non** en v1 ; l'historique garde la forme réduite (§2.4) |
| A5 | Formats à risque (`html`, `js`, `sh`, `php`) | permis, affichés comme source, téléchargés en `octet-stream` (PC71) |
| A6 | Politique d'outil | **PC84** : **`auto`** par défaut ; l'org peut mettre `deny` |

Écart avec l'annexe A de C3 : la trame `artifact` ne porte plus `ext` ni `size` (métadonnées
minimales) ; le quota rend `409 artifact_quota` (limite durable, pas un débit) au lieu de `429` ; la
référence vit dans les arguments chiffrés de l'appel, pas dans un nouveau champ du message.

## 14. Répartition par lot

| Lot | Prend dans ce document |
|---|---|
| Runtime (worker, lot à ouvrir, proposé **L08e**) | §2 (outil, validation, forme réduite, politique), §3 (chiffrement), §6.1 (trame), §10 ; rejoue `nameCases`, `contentCases`, `encryptionCases`, `quotaCases` (tour) |
| API (proposé **L03i**) | §4 (modèle, compteur, cascade, catalogue), §5 (routes), §10 ; rejoue `boundCases`, `quotaCases` (conversation), forme de `deposit` |
| App (**L12b**, branchement de l'`ArtifactSource` de L12) | §6.2, §7, §8 ; rejoue `encryptionCases`, `verifyCases` |
