# Synco AI Runtime

Service auto-hébergé qui fait tourner les conversations Synco AI en arrière-plan, chez le client : chaque conversation basculée en mode runtime s'exécute dans un worker isolé, et continue même quand l'utilisateur a fermé Synco.

Projet en cours de conception (refonte Synco AI).

## Hook git (secrets)

Le dépôt est public : `git config core.hooksPath .githooks` active le hook `pre-commit` qui exécute `scripts/check-secrets.mjs` (Node ou Bun requis) sur chaque commit. `node scripts/check-secrets.mjs --all` contrôle tout le dépôt.
