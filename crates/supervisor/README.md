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

## Workers

Lancés derrière le trait `launcher::WorkerLauncher`. En L05, un bouchon tourne dans le superviseur
sans isolation (`InProcessStubLauncher`) ; le bac à sable (L06) lance chaque worker par
`fork` + `exec` (jamais un `fork` seul d'un processus tokio qui détient des clés).
