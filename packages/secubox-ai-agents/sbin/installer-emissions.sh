#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# Installe l'atelier des émissions sur gk0 (#4058), SANS root, idempotent. Lancé à la main par le propriétaire.
#
#   installer-emissions.sh <dossier-du-paquet secubox-ai-agents> [interpréteur python du venv]
#
# 1. code `emissions/` copié dans ~/.local/lib/secubox-ai-emissions/src (instantané, pas le dépôt vivant) ;
#    lien `python` vers l'interpréteur (défaut : venv du dépôt, celui du relais : fastapi, httpx, uvicorn, playwright) ;
# 2. unités utilisateur : service, hebdo (service + minuterie lundi 06:00) ; drop-in réseau = adresses de
#    admin.gk2 et billets.gk2 résolues maintenant (à relancer si elles changent) ;
# 3. relais : emissions_relais.py + emissions.html copiés dans ~/poc-secubox-ai/relais/ ; DEUX lignes ajoutées en fin
#    de relais.py (si absentes) ; onglet « Émissions » ajouté à index.html après « Filtres WAF » (si absent).
#    Sauvegardes .avant-emissions ; le relais EN MARCHE n'est pas redémarré : à faire par le propriétaire.
# 4. ~/.config/secubox-ai-emissions/noms-internes.txt créé s'il manque (jamais écrasé).
# N'active ni ne démarre rien : les commandes à lancer sont affichées à la fin.
set -euo pipefail

paquet="$(cd "${1:?dossier du paquet requis}" && pwd)"
python="${2:-$HOME/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python}"
[[ -d "$paquet/emissions" && -f "$paquet/relais/emissions_relais.py" ]] || { echo "paquet invalide : $paquet" >&2; exit 2; }
[[ $EUID -ne 0 ]] || { echo "à lancer SANS root (unités utilisateur)" >&2; exit 2; }
"$python" -I -c 'import fastapi, httpx, uvicorn' || { echo "interpréteur sans fastapi/httpx/uvicorn : $python" >&2; exit 2; }

lib="$HOME/.local/lib/secubox-ai-emissions"
unites="$HOME/.config/systemd/user"
relais="$HOME/poc-secubox-ai/relais"
conf="$HOME/.config/secubox-ai-emissions"
install -d -m 0700 "$lib" "$conf" "$unites"

# 1. code : copie à côté puis bascule atomique
neuf="$lib/src.neuf"
rm -rf "$neuf"
install -d -m 0700 "$neuf"
cp -r "$paquet/emissions" "$neuf/"
find "$neuf" -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf "$lib/src.avant"
[[ -d "$lib/src" ]] && mv -T "$lib/src" "$lib/src.avant"
mv -T "$neuf" "$lib/src"
ln -sfn "$python" "$lib/python"

# 2. unités
install -m 0644 "$paquet/systemd/secubox-ai-emissions-gk0.service" "$unites/secubox-ai-emissions.service"
for u in service timer; do
  f="$paquet/systemd/secubox-ai-emissions-hebdo-gk0.$u"
  [[ -f "$f" ]] && install -m 0644 "$f" "$unites/secubox-ai-emissions-hebdo.$u"
done
install -d -m 0755 "$unites/secubox-ai-emissions.service.d"
{
  echo "# Écrit par installer-emissions.sh le $(date -u +%FT%TZ) : adresses résolues à l'installation."
  echo "[Service]"
  for h in admin.gk2.secubox.in billets.gk2.secubox.in; do
    for a in $(getent ahosts "$h" | awk '{print $1}' | sort -u); do echo "IPAddressAllow=$a"; done
  done
} > "$unites/secubox-ai-emissions.service.d/reseau.conf.tmp"
mv -f "$unites/secubox-ai-emissions.service.d/reseau.conf.tmp" "$unites/secubox-ai-emissions.service.d/reseau.conf"

# 3. relais : fichiers + deux lignes + onglet (idempotent)
install -m 0644 "$paquet/relais/emissions_relais.py" "$relais/emissions_relais.py"
install -m 0644 "$paquet/relais/emissions.html" "$relais/emissions.html"
if ! grep -q '^import emissions_relais' "$relais/relais.py"; then
  cp -p "$relais/relais.py" "$relais/relais.py.avant-emissions"
  printf '\nimport emissions_relais  # noqa: E402\nemissions_relais.brancher(app, _local)\n' >> "$relais/relais.py"
  "$python" -I -m py_compile "$relais/relais.py" || { cp -p "$relais/relais.py.avant-emissions" "$relais/relais.py"; echo "relais.py invalide : restauré" >&2; exit 3; }
fi
"$python" -I - "$relais/index.html" <<'PY'
import shutil, sys
from pathlib import Path
f = Path(sys.argv[1])
s = f.read_text(encoding="utf-8")
if "['emissions', 'Émissions']" in s:
    sys.exit(0)
a = "['filtres', 'Filtres WAF'], "
b = '  <section data-o="essai"'
if s.count(a) != 1 or s.count(b) != 1:
    sys.exit("index.html : repères introuvables (liste ONGLETS ou section essai) — onglet non ajouté")
section = ('  <section data-o="emissions" hidden><iframe src="/emissions" title="Atelier des émissions" '
           'style="width:100%;height:calc(100vh - 140px);min-height:720px;border:0;border-radius:10px"></iframe>'
           '</section>\n')
shutil.copy2(f, f.with_name(f.name + ".avant-emissions"))
s = s.replace(a, a + "['emissions', 'Émissions'], ").replace(b, section + b)
tmp = f.with_name(f.name + ".tmp")
tmp.write_text(s, encoding="utf-8")
tmp.replace(f)
PY

# 4. noms internes (balayage final) : jamais écrasés
[[ -f "$conf/noms-internes.txt" ]] || printf '# un nom par ligne ; « .suffixe » = domaine local\n%s\n' \
  gk0 gk1 gk2 gk3 gk4 gk5 gk6 gk7 .lan .local .internal .home.arpa > "$conf/noms-internes.txt"
chmod 0600 "$conf/noms-internes.txt"

systemctl --user daemon-reload
cat <<FIN
Installé (rien démarré). À faire :
  systemctl --user enable --now secubox-ai-emissions.service
  systemctl --user enable --now secubox-ai-emissions-hebdo.timer
  ~/poc-secubox-ai/relancer-poc.sh        # le relais charge emissions_relais (onglet « Émissions »)
Prérequis : ~/.config/secubox-ai-jeton/lecture-gk2 (0600, lecture des dossiers de gk2),
            ~/.config/secubox-ai-jeton/billets-emissions (0600, publication).
FIN
