# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3000 — smbctl : partages manuels et comptes depuis le panneau, avec les gardes dans le ctl.

Ce ctl recoit des noms et des chemins venus d'une requete HTTP. Quatre choses tiennent quoi qu'il arrive :
  - un chemin hors des racines declarees est REFUSE, lien symbolique compris ;
  - un partage genere par sync-shares ne se redefinit ni ne se retire ici ;
  - le mot de passe ne passe JAMAIS en argument ;
  - chaque decision laisse une ligne d'audit, sans secret.
Les outils ksmbd sont remplaces par des doublures qui ecrivent dans la configuration de test.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "composants" / "smb" / "sbin" / "smbctl"

CONF = """[global]
\tnetbios name = SECUBOX
\tinterfaces = eth2
\tserver min protocol = SMB3_00

[data]
\tcomment = Donnees SecuBox
\tpath = /data
\tread only = no

; >>> SECUBOX-SMB AUTO-SHARES >>>

[CLE-USB]
\tcomment = Support externe (lecture seule)
\tpath = {root}/media/secubox-media/CLE-USB
\tread only = yes
\tguest ok = no
; <<< SECUBOX-SMB AUTO-SHARES <<<
"""

ADDSHARE = r'''#!/usr/bin/env bash
# doublure de ksmbd.addshare : -a/-u/-d, -C conf, -P db, -o "k = v"..., NOM
mode=""; conf=""; opts=(); name=""
while [ $# -gt 0 ]; do case "$1" in
  -a|-u|-d) mode="$1"; shift;; -C) conf="$2"; shift 2;; -P) shift 2;; -o) opts+=("$2"); shift 2;; *) name="$1"; shift;; esac; done
echo "$mode $name" >> "$conf.appels"
if [ "$mode" = -d ]; then python3 - "$conf" "$name" <<'PY'
import re,sys; c,n=sys.argv[1],sys.argv[2]; s=open(c).read()
s=re.sub(r'\n\['+re.escape(n)+r'\]\n(?:\t[^\n]*\n)*', '\n', s); open(c,'w').write(s)
PY
else { printf '\n[%s]\n' "$name"; for o in "${opts[@]}"; do printf '\t%s\n' "$o"; done; } >> "$conf"; fi
'''
ADDUSER = r'''#!/usr/bin/env bash
# doublure de ksmbd.adduser : -a/-u/-d, -P db, NOM ; le mot de passe arrive sur stdin (deux fois)
mode=""; db=""; name=""
while [ $# -gt 0 ]; do case "$1" in -a|-u|-d) mode="$1"; shift;; -P) db="$2"; shift 2;; -p) echo "MOT DE PASSE EN ARGUMENT" >&2; exit 9;; *) name="$1"; shift;; esac; done
echo "$mode $name" >> "$db.appels"
if [ "$mode" = -d ]; then grep -v "^$name:" "$db" > "$db.n"; mv "$db.n" "$db"; exit 0; fi
read -r pw; read -r pw2; [ "$pw" = "$pw2" ] || exit 1
grep -v "^$name:" "$db" > "$db.n" 2>/dev/null; mv "$db.n" "$db"; echo "$name:$(printf '%s' "$pw" | sha256sum | cut -c1-16)" >> "$db"
'''


@pytest.fixture
def env(tmp_path):
    (tmp_path / "data" / "partage").mkdir(parents=True)
    (tmp_path / "media" / "secubox-media" / "CLE-USB").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    os.symlink(tmp_path / "etc", tmp_path / "data" / "vers-etc")
    conf = tmp_path / "ksmbd.conf"
    conf.write_text(CONF.format(root=tmp_path))
    db = tmp_path / "ksmbdpwd.db"
    db.write_text("admin:abc\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    # lsmod et ss doubles : sorties longues, comme sur la box, pour attraper le piege pipefail + grep -q.
    LSMOD = "#!/usr/bin/env bash\nfor i in $(seq 1 200); do echo \"module$i 12288 0\"; done; echo 'ksmbd                 299008  0'; for i in $(seq 1 200); do echo \"autre$i 12288 0\"; done\n"
    SS = "#!/usr/bin/env bash\nfor i in $(seq 1 300); do echo \"LISTEN 0 128 127.0.0.1:$((10000+i)) *:*\"; done; echo 'LISTEN 0 16 *%eth2:445 *:*'\n"
    SYSTEMCTL = "#!/usr/bin/env bash\necho active\n"
    for n, src in (("ksmbd.addshare", ADDSHARE), ("ksmbd.adduser", ADDUSER), ("lsmod", LSMOD), ("ss", SS), ("systemctl", SYSTEMCTL)):
        p = bin_ / n
        p.write_text(src)
        p.chmod(0o755)
    return {
        "PATH": f"{bin_}:" + os.environ.get("PATH", "/usr/bin:/bin"),
        "SECUBOX_SMB_CONF": str(conf), "SECUBOX_SMB_USERDB": str(db),
        "SECUBOX_SMB_AUDIT": str(tmp_path / "audit.log"),
        "SECUBOX_SMB_ROOTS": f"{tmp_path}/data:{tmp_path}/media", "SUDO_USER": "gk2", "HOME": str(tmp_path),
    }


def run(env, *args, stdin=None):
    p = subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, env=env, input=stdin, timeout=60)
    return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])


def audit(env):
    p = Path(env["SECUBOX_SMB_AUDIT"])
    return [json.loads(ligne) for ligne in p.read_text().splitlines()] if p.exists() else []


def test_status_distingue_partages_manuels_et_generes_et_lit_le_global(env):
    for _ in range(20):      # le piege pipefail + grep -q etait aleatoire : on insiste
        rc, d = run(env, "status")
        assert d["module_loaded"] is True and d["listening"] is True and d["service"] == "active" and d["usable"] is True
    assert rc == 0 and d["ok"] and d["netbios"] == "SECUBOX" and d["interfaces"] == "eth2" and d["min_protocol"] == "SMB3_00"
    assert d["roots"] == env["SECUBOX_SMB_ROOTS"].split(":")
    noms = {s["name"]: s for s in d["shares"]}
    assert noms["data"]["auto"] is False and noms["data"]["comment"] == "Donnees SecuBox" and noms["data"]["readonly"] is False
    assert noms["CLE-USB"]["auto"] is True and noms["CLE-USB"]["readonly"] is True and noms["CLE-USB"]["exists"] is True


def test_share_add_ecrit_un_partage_manuel_sous_une_racine(env):
    rc, d = run(env, "share-add", "Partage", f"{env['HOME']}/data/partage", "--ro", "--users", "admin", "--comment", "Essai [x]")
    assert rc == 0 and d["ok"] and d["created"] and d["readonly"] and d["users"] == ["admin"]
    conf = Path(env["SECUBOX_SMB_CONF"]).read_text()
    assert "[Partage]" in conf and "read only = yes" in conf and "valid users = admin" in conf and "guest ok = no" in conf
    assert "comment = Essai x" in conf                              # crochets retires : ils ouvriraient une section
    assert conf.index("[Partage]") > conf.index("AUTO-SHARES <<<")  # hors du bloc genere
    rc, d = run(env, "status")
    p = [s for s in d["shares"] if s["name"] == "Partage"][0]
    assert p["auto"] is False and p["users"] == ["admin"]
    assert audit(env)[-1]["action"] == "partage-cree" and audit(env)[-1]["par"] == "gk2" and audit(env)[-1]["partage"] == "Partage"
    # un second appel sur le meme nom met a jour (-u)
    rc, d = run(env, "share-add", "Partage", f"{env['HOME']}/data/partage", "--rw")
    assert rc == 0 and d["ok"] and d["created"] is False and d["readonly"] is False
    assert "-u Partage" in Path(env["SECUBOX_SMB_CONF"] + ".appels").read_text()


@pytest.mark.parametrize("nom,chemin,motif", [
    ("global", "{h}/data/partage", "reserve"),
    ("ipc$", "{h}/data/partage", "invalide"),
    ("a b", "{h}/data/partage", "invalide"),
    ("x" * 41, "{h}/data/partage", "invalide"),
    ("CLE-USB", "{h}/media/secubox-media/CLE-USB", "sync-shares"),
    ("Hors", "{h}/etc", "hors des racines"),
    ("Lien", "{h}/data/vers-etc", "hors des racines"),      # lien symbolique resolu AVANT la verification
    ("Relatif", "data/partage", "absolu"),
    ("Absent", "{h}/data/nexiste-pas", "existe pas"),
])
def test_share_add_refuse(env, nom, chemin, motif):
    rc, d = run(env, "share-add", nom, chemin.format(h=env["HOME"]))
    assert rc != 0 and d["ok"] is False and motif in d["error"]
    assert "[Hors]" not in Path(env["SECUBOX_SMB_CONF"]).read_text() and audit(env) == []


def test_share_add_refuse_un_compte_inconnu(env):
    rc, d = run(env, "share-add", "P", f"{env['HOME']}/data/partage", "--users", "admin,inconnu")
    assert rc != 0 and "inconnu" in d["error"]


def test_share_del_retire_un_manuel_jamais_un_genere(env):
    run(env, "share-add", "P", f"{env['HOME']}/data/partage")
    rc, d = run(env, "share-del", "P")
    assert rc == 0 and d["ok"] and "[P]" not in Path(env["SECUBOX_SMB_CONF"]).read_text()
    assert audit(env)[-1]["action"] == "partage-retire"
    rc, d = run(env, "share-del", "CLE-USB")
    assert rc != 0 and "sync-shares" in d["error"] and "[CLE-USB]" in Path(env["SECUBOX_SMB_CONF"]).read_text()
    rc, d = run(env, "share-del", "inconnu")
    assert rc != 0 and "inconnu" in d["error"]
    rc, d = run(env, "share-del", "global")
    assert rc != 0 and "[global]" in Path(env["SECUBOX_SMB_CONF"]).read_text()


def test_user_add_passe_le_mot_de_passe_sur_stdin_et_audite_sans_secret(env):
    rc, d = run(env, "user-add", "gk2", stdin="s3cret\n")
    assert rc == 0 and d["ok"] and d["created"] is True
    db = Path(env["SECUBOX_SMB_USERDB"]).read_text()
    assert db.startswith("admin:") and "\ngk2:" in db and "s3cret" not in db
    assert "-a gk2" in Path(env["SECUBOX_SMB_USERDB"] + ".appels").read_text()
    a = audit(env)[-1]
    assert a["action"] == "compte-cree" and a["compte"] == "gk2" and "s3cret" not in json.dumps(a)
    rc, d = run(env, "user-add", "gk2", stdin="autre\n")
    assert rc == 0 and d["created"] is False and "-u gk2" in Path(env["SECUBOX_SMB_USERDB"] + ".appels").read_text()
    rc, d = run(env, "user-add", "a:b", stdin="x\n")
    assert rc != 0 and "invalide" in d["error"]
    rc, d = run(env, "user-add", "vide", stdin="\n")
    assert rc != 0 and "vide" in d["error"]


def test_user_del(env):
    rc, d = run(env, "user-del", "admin")
    assert rc == 0 and d["ok"] and "admin:" not in Path(env["SECUBOX_SMB_USERDB"]).read_text()
    assert audit(env)[-1]["action"] == "compte-retire"
    rc, d = run(env, "user-del", "admin")
    assert rc != 0 and "inconnu" in d["error"]
    rc, d = run(env, "users")
    assert d["users"] == []


def test_le_mot_de_passe_n_est_jamais_en_argument():
    src = CTL.read_text(encoding="utf-8")
    appels = [ligne for ligne in src.splitlines()
              if "ksmbd.adduser " in ligne and not ligne.strip().startswith("#") and "command -v" not in ligne]
    assert appels and all(" -p " not in a and " -i " not in a and '-P "$USERDB"' in a for a in appels)
