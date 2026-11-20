# synco-ai-runtime (superviseur)

Process principal du Synco AI Runtime : seul détenteur des clés privées du runtime, appairage,
canal signé vers l'API, ouverture des délégations (en mémoire), WebSocket des clients, lancement
des workers. Spécification : `docs/plan/` du dépôt.

```sh
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml --check-config
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml pair     # URL, empreinte, code d'appairage
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml run
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml unpair
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml reset-keys --yes
```

Configuration commentée : [`synco-ai-runtime.example.toml`](synco-ai-runtime.example.toml).
Unité systemd d'exemple : [`systemd/synco-ai-runtime.service`](systemd/synco-ai-runtime.service).

## TLS : mandataire inverse obligatoire

Le runtime ne termine pas TLS (décision v1). Les navigateurs des membres le joignent en `wss://`
sur `public_url`, avec un certificat **reconnu** (un certificat auto-signé ne fonctionne pas) ; un
mandataire inverse sur la même machine relaie vers `listen.public` en HTTP **local**.

- `listen.public` doit être une adresse de boucle locale ; une autre adresse est refusée sauf
  `listen.allow_non_loopback_plain_http = true` (mandataire sur une autre machine d'un réseau de
  confiance, à vos risques : le trafic HTTP n'y est pas chiffré).
- `listen.trust_proxy_hops` = nombre de mandataires qui ajoutent `X-Forwarded-For` (1 pour un seul
  mandataire). Il sert aux limites de débit par adresse.

Caddy :

```
runtime.example.com {
    reverse_proxy 127.0.0.1:8790
}
```

nginx :

```
server {
    listen 443 ssl;
    server_name runtime.example.com;
    ssl_certificate     /etc/letsencrypt/live/runtime.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/runtime.example.com/privkey.pem;

    location /v1/ {
        proxy_pass http://127.0.0.1:8790;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

Le mandataire ne doit pas journaliser les corps ; les tickets ne sont jamais dans l'URL.

## Clé privée du runtime (mesure 8)

- Scellée au repos : `systemd-creds` (TPM2 et/ou clé de l'hôte) ou phrase de passe (Argon2id +
  AES-256-GCM). Jamais en clair sur disque.
- Au démarrage, **avant** de charger les clés : `PR_SET_DUMPABLE=0` (pas de vidage mémoire ni de
  lecture de la mémoire du processus par un autre processus du même utilisateur) et
  `RLIMIT_CORE=0`. L'unité d'exemple ajoute `LimitCORE=0`.
- Les pages de clés ne sont **pas** verrouillées en mémoire (`mlock` exige du code non sûr, interdit
  dans ce dépôt ; `mlockall` ferait échouer les allocations). Désactiver l'espace d'échange pour le
  service (`MemorySwapMax=0`) ou utiliser un swap chiffré.
- `passphrase_file` doit appartenir à l'utilisateur du service, droits `0600` ou `0400`.
- Une clé LLM lue par `api_key_env` **reste** dans l'environnement du processus : la retirer
  (`std::env::remove_var`) exige du code non sûr en Rust 2024, interdit ici. Préférer
  `api_key_file` avec un identifiant systemd. Le lanceur des workers (L06) doit vider leur
  environnement (`env_clear`) : un worker ne doit jamais hériter de cette variable.

## Workers : bac à sable (L06)

Un processus isolé par conversation active, lancé par `fork` + `exec` du binaire du superviseur
(`__sandbox-helper` puis `__sandbox-worker`), environnement vidé, pipe seul sur le descripteur 3 :
espaces de noms user, pid, mount (racine vide en lecture seule), net (aucune interface), ipc, uts,
cgroup ; capacités retirées, `no_new_privs`, landlock, seccomp en liste blanche ; un cgroup v2 par
worker (`memory.max`, pas d'espace d'échange, `pids.max`, `cpu.max`). Seul accès réseau : le
mandataire LLM du superviseur (socket Unix), qui ajoute lui-même la clé du fournisseur (D1).
Conception, coût mesuré, systemd et Docker : [`docs/plan/10-bac-a-sable.md`](../../docs/plan/10-bac-a-sable.md).

- Démarrage **refusé** si une fonction noyau manque (le message donne le code et la cause), avant
  le descellement des clés. Développement seulement : `run --insecure-no-sandbox`.
- Vérifier l'environnement réel : `synco-ai-runtime --config … sandbox-check`.
- systemd : `Delegate=yes` et `ProtectControlGroups=private` (unité d'exemple).
- Tests sur l'hôte : `host-spawn sh crates/supervisor/tests/sandbox-host.sh`.

## Dashboard (L08)

Interface web de l'administrateur du runtime : état, empreinte de la clé, sessions (tokens, coût
estimé, CPU et RAM des workers), totaux par utilisateur et par fournisseur. **Jamais de contenu de
conversation.** Conception et choix d'authentification : `docs/plan/11-dashboard.md`.

```text
synco-ai-runtime --config /etc/synco-ai-runtime/config.toml dashboard-password   # définit le mot de passe
```

Sans mot de passe, le dashboard ne démarre pas (le journal l'indique). Il écoute sur
`listen.dashboard` (défaut `127.0.0.1:8791`) ; derrière un mandataire TLS, déclarer le nom d'hôte
dans `dashboard.allowed_hosts`. L'historique est dans `<state_dir>/dashboard/` (JSONL) et conservé
`dashboard.retention_days` jours (défaut 90). Redémarrer le runtime après avoir défini le mot de
passe la première fois ; un changement ultérieur est pris en compte à chaud (sessions fermées).

### Derrière nginx ou Caddy

Par défaut (`dashboard.trust_proxy_hops = 0`) le dashboard ignore `X-Forwarded-For` et
`X-Forwarded-Proto` : sur une connexion directe, ils sont forgeables. Derrière **un** mandataire
TLS, mettre `trust_proxy_hops = 1`, déclarer le nom dans `allowed_hosts`, et faire que le mandataire
**écrase** ces en-têtes (jamais de transmission de ceux du client).

```nginx
server {
    listen 443 ssl;
    server_name runtime-admin.example.com;
    location / {
        proxy_pass http://127.0.0.1:8791;
        proxy_set_header Host $host;                      # contrôlé par allowed_hosts
        proxy_set_header X-Forwarded-For $remote_addr;    # écrase, n'ajoute pas
        proxy_set_header X-Forwarded-Proto $scheme;       # cookie Secure
    }
}
```

```caddy
runtime-admin.example.com {
    reverse_proxy 127.0.0.1:8791 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

```toml
[dashboard]
allowed_hosts = ["runtime-admin.example.com"]
trust_proxy_hops = 1
```
