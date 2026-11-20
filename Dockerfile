# syntax=docker/dockerfile:1
#
# Image OCI unique du Synco AI Runtime (superviseur + worker : le même binaire, qui se relance
# lui-même pour créer les workers isolés). Chemin officiel : Podman (rootless). Docker : variante
# avancée, voir docs/deploiement.md. Une construction : `podman build -t synco-ai-runtime .`
#
# Images de base épinglées par DIGEST (index multi-architectures, `sha256:`), jamais par tag seul ;
# le tag est conservé en commentaire pour la lisibilité. Pour monter de version : choisir un tag
# stable publié depuis plus de 7 jours, relever le digest de l'index
# (`skopeo inspect --raw docker://docker.io/library/<image>:<tag> | sha256sum`), remplacer ci-dessous.
# La toolchain Rust est celle de l'image (1.98.1, comme rust-toolchain.toml, non copié ici).

# --- Compilation --------------------------------------------------------------
# docker.io/library/rust:1.98.1-slim-bookworm (publié le 2026-09-19)
FROM docker.io/library/rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS builder

# cmake + gcc : requis pour compiler aws-lc-sys (backend crypto de rustls).
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    gcc \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p synco-ai-runtime --bin synco-ai-runtime \
    && strip target/release/synco-ai-runtime

# --- Image finale ---------------------------------------------------------------
# docker.io/library/debian:bookworm-20261027-slim (publié le 2026-10-28)
FROM docker.io/library/debian@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

# ca-certificates : le superviseur vérifie le HTTPS de l'API Synco et des fournisseurs LLM.
# bash : HEALTHCHECK (/dev/tcp), l'image n'a ni curl ni wget. Rien d'autre : pas de shell
# interactif utile, pas de gestionnaire de paquets exposé au worker (sa racine est un tmpfs vide).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur sans privilèges (uid fixe, pour les droits du volume et des secrets).
# /tmp doit exister (point de montage de la racine du worker, docs/plan/10 §10) : il l'est déjà
# dans l'image de base, la ligne le garantit. /var/lib/synco-ai-runtime = volume d'état
# (clé scellée, historique du dashboard, dashboard.pass) ; son chemin (+ /workers) tient dans les
# 72 octets de `run_dir`.
RUN groupadd --system --gid 10001 synco \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin synco \
    && mkdir -p /tmp /etc/synco-ai-runtime /var/lib/synco-ai-runtime \
    && chmod 1777 /tmp \
    && chown synco:synco /var/lib/synco-ai-runtime \
    && chmod 0700 /var/lib/synco-ai-runtime

COPY --from=builder /src/target/release/synco-ai-runtime /usr/local/bin/synco-ai-runtime

USER 10001:10001
ENV SYNCO_AI_RUNTIME_CONFIG=/etc/synco-ai-runtime/config.toml
VOLUME ["/var/lib/synco-ai-runtime"]
# 8790 : WebSocket et fiche publique (derrière le mandataire TLS) ; 8791 : dashboard.
EXPOSE 8790 8791

# Podman n'exécute pas HEALTHCHECK pour une image au format OCI (il l'ignore sans le dire) :
# fournir `--health-cmd` au `podman run` (voir docs/deploiement.md). Docker l'exécute.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD bash -c 'echo > /dev/tcp/127.0.0.1/8790' || exit 1

# Forme exec, PAS de script d'entrée : le superviseur est le processus 1 du conteneur, seul dans
# son cgroup (il y crée <cgroup>/supervisor et un cgroup par worker : règle « pas de processus
# dans un nœud interne », docs/plan/10 §5).
ENTRYPOINT ["/usr/local/bin/synco-ai-runtime"]
CMD ["run"]
