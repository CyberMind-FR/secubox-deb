#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: purger_secrets <rootfs> — aucune image ne sort avec un secret (#3518).
# Les paquets génèrent clés et jetons dans le chroot ; une image publiée les partagerait entre toutes ses box,
# et n'importe qui pourrait les en extraire. secubox-secrets-premier.service les crée au premier démarrage.

purger_secrets() {
    local r="${1:?rootfs requis}" f
    [[ -d "$r/etc" && "$r" != / ]] || { echo "purger_secrets : racine refusée : $r" >&2; return 2; }
    rm -f -- "$r"/etc/ssh/ssh_host_*
    rm -f -- "$r/etc/secubox/secrets/oidc/signing.pem" "$r"/etc/secubox/tls/cert.pem "$r"/etc/secubox/tls/key.pem
    rm -rf -- "${r:?}/etc/secubox/secrets/p2p" "${r:?}/etc/nginx/secubox-p2p-pair.conf"
    rm -f -- "$r/etc/secubox/secrets/console.key" "$r/etc/nginx/secubox-console/secret.conf"
    rm -f -- "$r"/etc/haproxy/certs/000-defaut.pem "$r"/data/haproxy/certs/000-defaut.pem
    # Vide et non absent : systemd en génère un au premier démarrage, et /var/lib/dbus le suit.
    if [[ -e "$r/etc/machine-id" ]]; then : > "$r/etc/machine-id"; fi
    rm -f -- "$r/var/lib/dbus/machine-id"
    f="$r/etc/secubox/users.json"
    if [[ -f "$f" ]]; then
        python3 -I - "$f" <<'PY'
import json, os, re, stat, sys
p = sys.argv[1]
d = json.load(open(p))
liste = d.get("users") if isinstance(d, dict) else d
garder = [u for u in liste if not (isinstance(u, dict) and re.fullmatch(r"runner[a-z0-9-]*|fv-az[a-z0-9-]*", str(u.get("username", ""))))]
if len(garder) != len(liste):
    if isinstance(d, dict):
        d["users"] = garder
    else:
        d = garder
    st = os.stat(p)
    with open(p + ".tmp", "w") as s:
        json.dump(d, s, indent=2)
    os.chmod(p + ".tmp", stat.S_IMODE(st.st_mode))
    os.chown(p + ".tmp", st.st_uid, st.st_gid)
    os.replace(p + ".tmp", p)
PY
    fi
    if grep -rlsE 'runnervm|fv-az' "$r/etc/secubox/users.json" >/dev/null; then
        echo "purger_secrets : compte de construction encore présent" >&2; return 1
    fi
    if compgen -G "$r/etc/ssh/ssh_host_*" >/dev/null; then
        echo "purger_secrets : clé d'hôte encore présente" >&2; return 1
    fi
    return 0
}
