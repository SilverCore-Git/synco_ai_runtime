# Recette manuelle de la porte C (démo)

Parcours de bout en bout à dérouler **à la main**, de l'installation au dashboard, avec Podman. Cases à cocher : ce
document est la preuve de recette (noter la date, l'hôte, la version, les écarts). Contexte : lot L09, [`deploiement.md`](deploiement.md).

**Prérequis de la recette** : une API Synco de développement joignable en HTTPS depuis l'hôte du runtime, une organisation
de test avec un compte administrateur et deux membres, l'app Synco (Firefox) pointant sur cette API, un nom DNS et un
certificat reconnus pour le runtime (mandataire nginx ou Caddy de `deploy/`), un fournisseur LLM de test configuré dans
l'organisation (par exemple la passerelle Synco AI + Ollama, ou une clé de test).

Hôte : ____________  noyau : ______  Podman : ______  Version du runtime (commit) : ______  Date : ______

## A. Installation (Podman, Quadlet)

- [ ] `podman build --format docker -t localhost/synco-ai-runtime:latest .` réussit ; image sans `root` (`podman run --rm --entrypoint id … -u` → `10001`).
- [ ] `deploy/config.container.example.toml` copié et adapté (`public_url`, `api_url`, `allowed_origins`, `allowed_hosts`) ; `--check-config` répond « configuration valide ».
- [ ] Secret de phrase de passe créé ; **phrase notée dans le coffre**.
- [ ] `sandbox-check` (conteneur jetable, [`deploiement.md §2.3`](deploiement.md)) : huit `ok`, code 0. Noter la sortie.
- [ ] Quadlet installé, `systemctl --user start synco-ai-runtime.service`, `podman ps` : `healthy` en moins d'une minute.
- [ ] `podman top synco-ai-runtime` : un seul processus (le superviseur, PID 1).
- [ ] Mandataire TLS en place : `curl -s https://runtime.example.com/v1/identity` renvoie la fiche (JSON avec `fingerprint`) ; `curl -I http://runtime.example.com/` redirige vers HTTPS ; `https://runtime.example.com/` (hors `/v1/`) → 404 ; `localhost:8790` non joignable depuis une autre machine.

## B. Appairage contre l'API de dev

- [ ] `podman exec synco-ai-runtime synco-ai-runtime pair` affiche URL, identifiant, **empreinte**, code.
- [ ] Synco → Paramètres de l'organisation → Synco AI → Runtime : saisir URL et code ; l'appairage aboutit.
- [ ] **L'empreinte affichée par Synco est identique** à celle du terminal (comparer caractère par caractère).
- [ ] Le journal du runtime (`podman logs`) ne contient ni clé, ni ticket, ni contenu de conversation.
- [ ] Après appairage : le runtime apparaît « en ligne » dans Synco ; `podman logs` ne montre plus « enregistrement impossible ».
- [ ] Redémarrer le service : même identifiant, même empreinte, toujours appairé (état conservé dans le volume).

## C. Mot de passe du dashboard

- [ ] `podman exec -it synco-ai-runtime synco-ai-runtime dashboard-password` : saisie masquée ; refus de moins de 12 caractères.
- [ ] Redémarrage ; journal `dashboard_started` ; `https://runtime-admin.example.com/login` s'affiche (Firefox).

## D. Bascule d'une conversation, fermeture, retour

- [ ] Fournisseur LLM autorisé par la politique de l'organisation ; clé du fournisseur (ou passerelle) configurée dans le runtime.
- [ ] Délégation : l'utilisateur A autorise le runtime (durée par défaut) ; dans une conversation Synco AI, **basculer en mode runtime**.
- [ ] La conversation est prise en charge : l'état passe à « en cours » ; le suivi en direct (WebSocket) s'affiche dans Firefox (console : aucune erreur de contenu mixte ni de CORS).
- [ ] Envoyer une consigne longue (plusieurs étapes d'outils) puis **fermer l'onglet / l'application Synco**.
- [ ] Pendant ce temps : `podman logs` montre un worker lancé ; `systemd-cgls` / cgroups : un cgroup `w-…` par worker, 512 Mio max.
- [ ] **Revenir** dans Synco (nouvel onglet) : l'historique contient le travail effectué hors ligne ; le suivi reprend en direct sans trou ni doublon ; la conversation peut être **rebasculée en local**.
- [ ] Mode dégradé (D10) : couper le mandataire ou le nom DNS du runtime, ouvrir la conversation : message clair (historique lisible via l'API, suivi indisponible) ; rétablir : le suivi reprend.
- [ ] Mobile (si prévu pour la démo) : depuis un téléphone **sur le réseau** puis **hors du réseau** (4G, sans VPN) : noter le comportement (voir `deploiement.md §8`).

## E. Dashboard

- [ ] Connexion avec le mot de passe ; mauvais mot de passe refusé ; 6ᵉ essai → message de patience (429).
- [ ] Vue d'ensemble : **empreinte identique** à Synco et à `pair` ; état d'appairage, « API Synco connectée ».
- [ ] Sessions : la conversation de la partie D apparaît avec tokens, coût estimé, CPU et RAM du worker non nuls ; état final « Terminé ».
- [ ] Détail de la session : chronologie **sans aucun contenu de conversation** (ni consigne, ni arguments, ni résultats).
- [ ] Totaux par utilisateur et par fournisseur cohérents.
- [ ] Derrière le mandataire : cookie `synco_dash` avec `Secure` ; `Host` inconnu (`curl -H 'Host: x'`) → 403.
- [ ] Console du navigateur : aucune violation de CSP, aucune requête externe.
- [ ] Redémarrer le runtime : l'historique du dashboard est conservé.

## F. Fin de recette : désappairage et sauvegarde

- [ ] `podman volume export synco-ai-runtime-state > ~/sauvegardes/etat.tar` réussit ; la restauration ([`deploiement.md §2.5`](deploiement.md)) sur un volume neuf redonne la même empreinte.
- [ ] `podman exec synco-ai-runtime synco-ai-runtime unpair` : Synco montre le runtime « désappairé » ; les conversations repassent en local ; les workers s'arrêtent.
- [ ] Réappairage possible avec le même identifiant (mêmes clés) ; `reset-keys --yes` donne une nouvelle empreinte et impose un nouvel appairage.

## Non couvert par cette recette (à traiter à part)

Docker (variante avancée), AppArmor, unité systemd **système** (`LoadCredentialEncrypted=`, `sandbox-check` dans l'unité), hôte SELinux avec
`container_manage_cgroup` au lieu de `label=disable`, clé scellée par TPM2.
