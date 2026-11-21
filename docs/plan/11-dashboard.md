# 11 — Dashboard du superviseur (L08)

Interface web servie par le superviseur à l'admin qui héberge le runtime (P9). Elle montre l'état du
runtime, l'usage (tokens, coût estimé) et la consommation (CPU, RAM) de chaque session, **jamais le
contenu des conversations**. Code : `crates/supervisor/src/dashboard/`.

## 1. Authentification : choix et justification

| | A. Mot de passe local haché | B. Connexion par ticket Synco (admins de l'org) |
|---|---|---|
| Nouvelle route `synco_api` | non | oui (émission d'un ticket « dashboard ») |
| Nouveau rôle / contrat | non | oui (opération de ticket, vérification côté runtime, liste d'admins) |
| Dépend de l'API et de Synco | non : fonctionne hors ligne, runtime non appairé compris | oui : indisponible tant que le runtime n'est pas appairé ou si l'API est coupée |
| Cohérence avec l'auto-hébergement | forte : l'opérateur du serveur est maître de l'accès | moyenne : l'accès passe par le compte Synco |
| Surface contre le serveur Synco malveillant (03 §2) | aucune : Synco ne peut pas ouvrir le dashboard | un serveur compromis pourrait émettre un ticket « admin » et lire l'usage et l'empreinte |
| Brute force | à traiter (§3) | délégué à Synco, mais ticket rejouable à traiter |

**Choix : A, mot de passe local haché.** Raisons : (1) l'option B demande une nouvelle route API et un
nouveau rôle, donc engage le produit au-delà du lot (consigne : prendre l'option qui n'en demande pas
et remonter l'autre) ; (2) le dashboard affiche l'empreinte de clé (mesure 4), qui sert justement à
détecter une substitution de clé par le serveur Synco : son accès ne doit pas dépendre de ce serveur ;
(3) il doit être utilisable avant l'appairage (on y lit l'empreinte à recopier). **B est remontée à
l'orchestrateur** comme évolution possible (connexion « admin de l'org » en plus, jamais à la place).

Mise en place : `synco-ai-runtime dashboard-password` demande le mot de passe deux fois sur le
terminal (sans écho, 12 caractères minimum) et écrit `<state_dir>/dashboard.pass` (0600) : JSON avec
Argon2id (64 Mio, 3 passes, 1 voie, sel de 16 octets) et l'empreinte résultante. Sans ce fichier, le
dashboard **ne démarre pas** (journal `dashboard_disabled`, avec la commande pour le créer ; fichier illisible ou invalide : `dashboard_password_unreadable`) : **question ouverte** (§7, Q29 c). Un mot de passe défini après le démarrage n'est pris en compte qu'au redémarrage suivant (un changement ultérieur l'est à chaud). Le fichier est relu si sa date change ; un
changement de mot de passe ferme toutes les sessions.

## 2. Sessions et cookies

- Jeton de 32 octets aléatoires (`OsRandom`) tiré **à chaque connexion** (pas de session avant la
  connexion : aucune fixation possible) ; le serveur ne garde que son SHA-256. Cookie `synco_dash` :
  `HttpOnly; SameSite=Strict; Path=/`, plus `Secure` quand la requête est arrivée en HTTPS
  (`X-Forwarded-Proto: https` lu seulement si `dashboard.trust_proxy_hops > 0`).
- Durée : 30 min d'inactivité, 12 h au maximum ; 16 sessions simultanées au plus. Déconnexion =
  suppression côté serveur.
- **CSRF** : `SameSite=Strict`, plus contrôle de `Origin` (doit correspondre à `Host`) sur toute
  requête non `GET`, plus jeton CSRF par session (en-tête `x-csrf-token`) pour les requêtes
  authentifiées non `GET` (déconnexion). Les routes de données sont toutes en `GET` et sans effet.
- **DNS rebinding** : l'en-tête `Host` doit être l'adresse d'écoute, `localhost`/`127.0.0.1`/`[::1]`
  avec le port, ou figurer dans `dashboard.allowed_hosts` (mandataire inverse) ; sinon `403`.

## 3. Force brute

Connexion : corps JSON ≤ 1 Kio. Une vérification Argon2 à la fois (sémaphore). Avant chaque
vérification :

- **limite stricte par adresse réelle** : 5 échecs / 15 min, au-delà `429` + `Retry-After` sans
  vérifier le mot de passe (même le bon). Les adresses IPv6 comptent par préfixe /64. L'adresse est
  celle de la connexion TCP ; `X-Forwarded-For` n'est lu que si `dashboard.trust_proxy_hops > 0`
  (défaut **0**, réglage distinct de `listen.trust_proxy_hops`, prévu pour le mandataire de
  `public`), de même pour `X-Forwarded-Proto` ;
- **ralentissement global, pas un refus** : à partir de 20 échecs en 15 min toutes adresses
  confondues, une adresse *inconnue* ne peut déclencher qu'une vérification toutes les 5 s (les
  autres reçoivent `429`). Les 8 dernières adresses qui ont ouvert une session sont **exemptées**
  de ce ralentissement (jamais de la limite par adresse) : une attaque distribuée ne peut donc pas
  enfermer l'admin dehors, elle ne fait que le ralentir de 5 s s'il se connecte d'une nouvelle
  adresse.

Un échec ne dit rien de plus qu'un autre (`invalid_credentials`). Limite assumée : un attaquant qui
dispose de beaucoup d'adresses réelles garde un débit d'au plus une tentative toutes les 5 s une fois
le seuil atteint (≈ 700 / h), contre un mot de passe Argon2id de 12 caractères minimum.

## 4. En-têtes et interface

CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self';
form-action 'self'; base-uri 'none'; frame-ancestors 'none'` (aucun script ni style en ligne),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`, `Cross-Origin-Resource-Policy: same-origin`. HTML/CSS/JS embarqués
(`include_str!`), sans CDN, rendu par `textContent` (jamais `innerHTML`).

Routes publiques (seules sans session) : `GET /login`, `GET /assets/login.js`, `GET /assets/style.css`,
`POST /api/login`. Tout le reste, y compris un chemin inconnu, répond `401` sans session.

## 5. Données : ce que le dashboard connaît

Uniquement ce que le superviseur reçoit déjà : `metrics` du pipe (06 §5 : compteurs, tokens, coût en
µ€ calculé par le worker depuis `pricing`, latences), `status` (liste fermée d'états de 08 §1 et de
codes de 08 §6, sinon `other`), `done`, code de sortie, consommation du cgroup (`memory.current`,
`memory.peak`, `cpu.stat`, lue toutes les 5 s), identifiant d'utilisateur et de conversation tels que
l'API les a donnés au superviseur, fournisseur et modèle de la configuration. **Noms d'affichage (PC17,
L03d, 2026-11-21)** : l'API fournit désormais au runtime `displayName` (`string | null`) dans
`GET /delegations` et `GET /authorizations` (04 §4.1) : `User.name`, sinon `User.pseudo`, en écartant toute
valeur qui contient `@` ou égale l'e-mail, 128 caractères au plus, sinon `null` ; **jamais l'e-mail**. Le
dashboard doit afficher ce nom, et l'**identifiant quand `displayName` est `null`**. **Non réalisé à ce
jour** : le superviseur ne lit pas encore `displayName` (`DelegationRecord` ne le porte pas) et le
dashboard affiche l'identifiant seul ; adoption **ouverte** (PC17 : « L03d + dashboard »). Tout nom reçu
reste une donnée de l'API, jamais du texte de conversation. Le stockage est **typé** : aucun champ libre, donc aucune voie pour du
texte de conversation. Ni `event`, ni `log`, ni `signed_request` ne sont lus par le dashboard.

**Ajout L05b (2026-11-21, Q25)** : la vue d'ensemble liste aussi les **clés RSA de membres refusées**
(identifiant du membre, empreintes RFC 7638 de la clé épinglée et de la clé proposée, date), tirées
de `member-rsa-pins.json` (empreintes seulement, jamais la clé). L'app ne montrant pas encore au
membre l'empreinte de sa propre clé, la page ne promet aucune comparaison : elle demande à l'admin
de vérifier auprès du membre, hors de Synco, qu'il a bien réinitialisé ou renouvelé son chiffrement
(06 §4.3, revue I4). Seule action d'administration du
dashboard : `POST /api/member-keys/accept { userId, fingerprint }` (session, origine et CSRF exigés
par le garde ; confirmation en deux temps dans la page), qui accepte la clé en attente dont
l'empreinte SPKI est celle affichée (06 §4.3).

**Écart avec le cahier des charges** : la chronologie ne peut pas nommer l'outil appelé ni donner le
type d'une étape, car les `metrics` du pipe ne portent que des compteurs globaux (06 §5 prévoyait
un « compteur par outil » que le worker n'émet pas). La chronologie montre donc : lancement, états,
mesures (écarts d'étapes, d'appels d'outils, de tokens, de coût, durée du tour) et fin. Un compteur
par outil demanderait une évolution du worker (hors lot, remontée).

## 6. Stockage et rétention

Fichiers JSONL, sans dépendance : `<state_dir>/dashboard/history-AAAA-MM-JJ.jsonl` (0600, dossier
0700), un enregistrement par **exécution de worker** (une session = une conversation peut en avoir
plusieurs, agrégées à l'affichage). Écriture : un point de reprise (totaux, sans chronologie) toutes
les 60 s par exécution active, et l'enregistrement final avec chronologie (≤ 500 entrées) à la fin.
Au chargement, le dernier enregistrement d'un identifiant gagne ; une exécution sans fin devient
« interrompue » ; une exécution encore en cours lors d'un arrêt brutal garde ses totaux au dernier point de reprise (≤ 60 s de retard) mais perd sa chronologie. Au plus **`MAX_RUNS` = 50 000** exécutions en mémoire : plafond appliqué dès le chargement, puis élagage amorti des terminées les plus anciennes jusqu'à 90 % (une passe tous les 5 000 ajouts, pas à chaque ajout). Pas de SQL. Rétention `dashboard.retention_days` (1 à 3650, défaut 90) : fichiers
plus vieux supprimés au démarrage puis toutes les heures. Coût du jour / 7 jours / 30 jours : jours
UTC, le coût étant attribué au jour où la mesure est arrivée.

## 7. Questions ouvertes (L08, reportées le 2026-11-20 ; non tranchées, 00 §6, Q29)

**Décisions du 2026-11-21 (porte C, PC13 à PC15), reportées sans changement de code** : (a) **PC13** : mot de
passe local seul en v1, pas de connexion par ticket Synco ; (b) **PC14** : pas de compteur par outil ; l'usage
est présenté comme des analytics de ressources par session et par utilisateur ; **PC15** : mot de passe créé par
la commande `dashboard-password`, comme prévu (l'idée d'un `.env` est abandonnée). Le point (c) reste non
tranché. Les puces ci-dessous gardent leur texte d'origine pour mémoire. **PC28** : le dashboard affichera une
alerte à 80 % du plafond d'épingles RSA (lot L05c, non réalisé).

- **(a) Connexion par ticket Synco** des admins de l'org, **en complément** du mot de passe local
  (jamais à sa place, §1) : demande une nouvelle route de `synco_api` et un rôle.
- **(b) Compteur d'appels par outil** dans `metrics` (06 §5) : évolution du protocole et de
  `crates/worker`, nécessaire pour nommer l'outil dans la chronologie (§5). L'affichage d'un
  nom d'utilisateur à la place de l'identifiant n'est plus bloqué par l'API (`displayName`, §5, L03d) ;
  reste l'adoption par le superviseur et le dashboard.
- **(c) Dashboard désactivé tant qu'aucun mot de passe n'existe** (aujourd'hui : pas de page « aucun
  mot de passe », §1) : à confirmer ou à remplacer.

Autres limites déclarées (pas des questions) : coût **estimé** par le worker depuis `pricing` (absent :
0), jours UTC ; durée d'une exécution = vie du process worker (une conversation relancée = plusieurs
exécutions agrégées) ; CPU et RAM « non mesurés » avec le lanceur de test ou `--insecure-no-sandbox`
sans cgroup. Rendu réel dans Firefox, mesures cgroup réelles et comportement derrière un vrai
mandataire TLS : **non vérifiés** (recette manuelle, `docs/journal.md`, L08).
