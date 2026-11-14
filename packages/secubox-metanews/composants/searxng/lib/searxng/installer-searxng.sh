#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: secubox-metanews :: composant searxng (#3581) — installation de SearXNG DANS le conteneur.
#
# Exécuté en root DANS le conteneur par « searxngctl install » (lxc-attach … env … bash -s < ce fichier). Idempotent :
# un second passage ne retélécharge rien (marque .commit), ne réécrit l'unité que si elle change, ne redémarre rien.
#   SEARXNG_DEPOT   dépôt git (https://github.com/searxng/searxng)
#   SEARXNG_COMMIT  commit FIGÉ (40 caractères hexadécimaux), vérifié après récupération
#   SEARXNG_IP      adresse du conteneur : SearXNG n'écoute que là
#   SEARXNG_PORT    port d'écoute
#   SEARXNG_EXIGENCES         dépendances Python FIGÉES avec empreintes (/etc/searxng/exigences.txt, root, posé par
#                             searxngctl depuis /usr/share/secubox/lib/searxng/exigences-searxng.txt)
#   SEARXNG_EXIGENCES_SHA256  empreinte attendue de ce fichier, revérifiée ici avant pip
# Le secret n'arrive jamais ici : searxngctl écrit /etc/searxng/searxng.env (0600) par l'entrée standard.
#
# Droits : $RACINE est root:root 0755 ; seuls searxng-src et venv appartiennent à searxng. Les marques .commit et .serveur
# sont écrites par root (temporaire puis mv) : le compte searxng ne peut ni les modifier ni les remplacer.

set -euo pipefail

: "${SEARXNG_DEPOT:?}" "${SEARXNG_COMMIT:?}" "${SEARXNG_IP:?}" "${SEARXNG_PORT:?}"
: "${SEARXNG_EXIGENCES:?}" "${SEARXNG_EXIGENCES_SHA256:?}"
[[ "$SEARXNG_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "commit refusé : $SEARXNG_COMMIT" >&2; exit 2; }
[[ "$SEARXNG_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "adresse refusée" >&2; exit 2; }
[[ "$SEARXNG_PORT" =~ ^[0-9]{4,5}$ ]] || { echo "port refusé" >&2; exit 2; }
[[ "$SEARXNG_DEPOT" =~ ^https://[A-Za-z0-9./_-]+$ ]] || { echo "dépôt refusé" >&2; exit 2; }
[[ "$SEARXNG_EXIGENCES_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "empreinte des exigences refusée" >&2; exit 2; }
[[ -f "$SEARXNG_EXIGENCES" && ! -L "$SEARXNG_EXIGENCES" ]] || { echo "exigences absentes : $SEARXNG_EXIGENCES" >&2; exit 2; }
obtenue="$(sha256sum < "$SEARXNG_EXIGENCES")"
[[ "${obtenue%% *}" == "$SEARXNG_EXIGENCES_SHA256" ]] || { echo "exigences altérées (empreinte inattendue)" >&2; exit 2; }

readonly RACINE=/usr/local/searxng
readonly SRC="$RACINE/searxng-src"
readonly VENV="$RACINE/venv"
readonly UNITE=/etc/systemd/system/searxng.service
export DEBIAN_FRONTEND=noninteractive

log() { printf '[searxng-conteneur] %s\n' "$*"; }
# Marque écrite par root : temporaire dans $RACINE (root), puis mv (nouvel inode root, jamais à travers un fichier existant).
marque() { local t; t="$(mktemp "$RACINE/.marque.XXXXXX")"; printf '%s\n' "$2" > "$t"; chmod 0644 "$t"; mv -f -- "$t" "$RACINE/$1"; }
comme_searxng() { runuser -u searxng -- env HOME="$RACINE" PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 "$@"; }

# Paquets : Python et son venv, git. Aucune chaîne de compilation : les dépendances ne s'installent qu'en roues
# (--only-binary), dont les empreintes couvrent arm64 et amd64 (exigences-searxng.txt).
paquets=(python3 python3-venv git ca-certificates)
manquants=()
for p in "${paquets[@]}"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || manquants+=("$p")
done
if [[ ${#manquants[@]} -gt 0 ]]; then
    log "paquets : ${manquants[*]}"
    apt-get update -q
    apt-get install -y -q --no-install-recommends "${manquants[@]}"
fi

# Utilisateur dédié, sans shell.
if ! id -u searxng >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$RACINE" --no-create-home --shell /usr/sbin/nologin searxng
fi
install -d -m 0755 -o root -g root "$RACINE"
install -d -m 0755 -o root -g root /etc/searxng

# Sources au commit figé, puis environnement Python. Rien n'est refait si la marque porte déjà ce commit ET ces exigences.
attendu="$SEARXNG_COMMIT $SEARXNG_EXIGENCES_SHA256"
if [[ "$(cat "$RACINE/.commit" 2>/dev/null || true)" != "$attendu" ]]; then
    log "récupération de SearXNG ${SEARXNG_COMMIT:0:12} …"
    rm -rf "$SRC.nouveau"
    install -d -m 0755 -o searxng -g searxng "$SRC.nouveau"
    comme_searxng git -C "$SRC.nouveau" init -q
    comme_searxng git -C "$SRC.nouveau" fetch -q --depth 1 "$SEARXNG_DEPOT" "$SEARXNG_COMMIT"
    comme_searxng git -C "$SRC.nouveau" checkout -q --detach FETCH_HEAD
    obtenu="$(comme_searxng git -C "$SRC.nouveau" rev-parse HEAD)"
    [[ "$obtenu" == "$SEARXNG_COMMIT" ]] || { echo "commit obtenu $obtenu, attendu $SEARXNG_COMMIT" >&2; exit 1; }
    rm -rf "$SRC" "$VENV" "$RACINE/.commit"
    mv "$SRC.nouveau" "$SRC"
    log "environnement Python (dépendances figées avec empreintes) …"
    install -d -m 0755 -o searxng -g searxng "$VENV"
    comme_searxng python3 -m venv "$VENV"
    # pip, setuptools, wheel : ceux du venv Debian (python3-venv), jamais mis à jour ici. Roues seulement (aucune
    # compilation, donc aucune dépendance de construction hors empreintes), chaque fichier vérifié par son empreinte.
    comme_searxng "$VENV/bin/pip" install -q --require-hashes --only-binary :all: -r "$SEARXNG_EXIGENCES"
    # Les exigences du commit doivent être couvertes par le fichier figé : sans index, rien ne peut être ajouté ici.
    exigences=(-r "$SRC/requirements.txt")
    [[ -f "$SRC/requirements-server.txt" ]] && exigences+=(-r "$SRC/requirements-server.txt")
    comme_searxng "$VENV/bin/pip" install -q --no-index "${exigences[@]}"
    marque .commit "$attendu"
fi

# Serveur d'application : celui que fournit requirements-server.txt (granian, sinon uwsgi), sinon le serveur intégré.
# SearXNG n'écoute que sur l'adresse du conteneur (jamais 0.0.0.0).
if [[ -x "$VENV/bin/granian" ]]; then
    serveur=granian
    lancer="$VENV/bin/granian --interface wsgi --host $SEARXNG_IP --port $SEARXNG_PORT --workers 1 --blocking-threads 4 searx.webapp:app"
elif [[ -x "$VENV/bin/uwsgi" ]]; then
    serveur=uwsgi
    lancer="$VENV/bin/uwsgi --http-socket $SEARXNG_IP:$SEARXNG_PORT --module searx.webapp --callable app --master --processes 1 --threads 4 --enable-threads --die-on-term"
else
    serveur=searx.webapp
    lancer="$VENV/bin/python -m searx.webapp"
fi
marque .serveur "$serveur"

# Unité du conteneur. Pas d'options à espace de noms de montage (ProtectSystem, PrivateTmp…) : en LXC non privilégié elles
# échouent en 226/NAMESPACE. Le confinement est celui du conteneur (idmap, AppArmor « generated », cgroup mémoire).
nouvelle="$(cat <<UNIT
# SecuBox — composant searxng de secubox-metanews (#3581). Écrit par searxngctl install.
[Unit]
Description=SearXNG (SecuBox, interne)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/searxng/settings.yml
ConditionPathExists=/etc/searxng/searxng.env

[Service]
Type=simple
User=searxng
Group=searxng
WorkingDirectory=$SRC
Environment=SEARXNG_SETTINGS_PATH=/etc/searxng/settings.yml
Environment=PYTHONPATH=$SRC
Environment=PYTHONDONTWRITEBYTECODE=1
# SEARXNG_SECRET (server.secret_key) : fichier root 0600, lu par systemd avant le changement d'utilisateur.
EnvironmentFile=/etc/searxng/searxng.env
ExecStart=$lancer
Restart=on-failure
RestartSec=5
# granian tardait plus de 90 s à s'arrêter (banc gk6, #3581) : la relance du contrôleur expirait.
TimeoutStopSec=15
NoNewPrivileges=yes
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT
)"
if [[ "$(cat "$UNITE" 2>/dev/null || true)" != "$nouvelle" ]]; then
    printf '%s\n' "$nouvelle" > "$UNITE"
    systemctl daemon-reload
    log "unité searxng.service écrite (serveur : $serveur)"
fi
log "prêt (serveur : $serveur)"
