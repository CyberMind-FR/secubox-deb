# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2184 : fichier de réponses du provisionnement Auto-Load — schéma strict, secrets par référence, signature détachée (vrai gpg)."""
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import profil as P, provision as V  # noqa: E402

EMPREINTE = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
CONNUS = ["full", "lite", "isp"]
BASE = f"""
[box]
nom = "client-042"
langue = "fr"
clavier = "fr"
fuseau = "Europe/Paris"
ntp = true

[admin]
mot_de_passe = "{EMPREINTE}"
totp = "enroler"

[reseau]
mode = "routeur"
domaine = "client042.secubox.in"

[services]
profil = "lite"

[maillage]
mode = "plus_tard"

[apt]
auto = true
heure = "03:00"

[provision]
mode = "auto"
jeton = "ref:/etc/secubox/secrets/autoload-jeton"
lot = "lot-2026-10"
grace_min = 15
infra = "admin.gk2.secubox.in"
"""


def ecrit(tmp_path, texte, nom="reponses.toml"):
    p = tmp_path / nom
    p.write_text(texte, encoding="utf-8")
    return p


def examen(tmp_path, texte):
    return V.examine_provision(V.lit_strict(ecrit(tmp_path, texte)), CONNUS)


def test_un_fichier_complet_est_accepte(tmp_path):
    ex = examen(tmp_path, BASE)
    assert ex.complet, (ex.manquantes, ex.erreurs)
    assert ex.profil["provision"]["grace_min"] == 15


def test_valeurs_par_defaut_de_la_section_provision(tmp_path):
    texte = BASE.split("[provision]")[0] + '[provision]\nmode = "one-shot"\njeton = "ref:/etc/secubox/secrets/j"\n'
    ex = examen(tmp_path, texte)
    assert ex.complet
    assert ex.profil["provision"]["grace_min"] == 15 and ex.profil["provision"]["infra"] == "admin.gk2.secubox.in"


@pytest.mark.parametrize("ajout", [
    "\n[inconnue]\nx = 1\n",                                  # section inconnue
    "\n[provision.sous]\nx = 1\n",                            # sous-table
])
def test_sections_inconnues_refusees(tmp_path, ajout):
    with pytest.raises(V.FichierInvalide):
        V.lit_strict(ecrit(tmp_path, BASE + ajout))


def test_cle_inconnue_refusee_dans_chaque_section(tmp_path):
    for section in ("box", "admin", "reseau", "services", "maillage", "apt", "provision"):
        texte = BASE.replace(f"[{section}]\n", f"[{section}]\nintrus = 1\n", 1)
        with pytest.raises(V.FichierInvalide, match="intrus"):
            V.lit_strict(ecrit(tmp_path, texte))


def test_mot_de_passe_en_clair_refuse(tmp_path):
    ex = examen(tmp_path, BASE.replace(EMPREINTE, "monmotdepasse"))
    assert "admin" in ex.erreurs


def test_jeton_d_invitation_en_clair_refuse_dans_le_maillage(tmp_path):
    texte = BASE.replace('mode = "plus_tard"', 'mode = "rejoindre"\nrejoindre = "10.0.0.1"\njeton = "' + "ab" * 16 + '"')
    with pytest.raises(V.FichierInvalide, match="jeton"):
        V.lit_strict(ecrit(tmp_path, texte))


@pytest.mark.parametrize("jeton", [
    "e70e1f79f9b9cd4179950117ce5f78c2",                       # jeton en clair
    "ref:/etc/passwd",                                        # hors du dossier des secrets
    "ref:/etc/secubox/secrets/../shadow",                     # remontée
    "ref:/etc/secubox/secrets/a/b",                           # sous-dossier
    "ref:/etc/secubox/secrets/",                              # vide
    "ref:/etc/secubox/secrets/x y",                           # espace
    "ref:/etc/secubox/secrets/" + "a" * 80,                   # trop long
    "",
])
def test_le_jeton_n_est_jamais_une_valeur_mais_une_reference(tmp_path, jeton):
    ex = examen(tmp_path, BASE.replace("ref:/etc/secubox/secrets/autoload-jeton", jeton))
    assert "provision" in ex.erreurs


@pytest.mark.parametrize("champ,valeur", [
    ("mode", '"maintenant"'), ("grace_min", "-1"), ("grace_min", "1441"), ("grace_min", '"15"'), ("grace_min", "true"),
    ("lot", '"Lot Majuscule"'), ("lot", '"' + "a" * 41 + '"'), ("infra", '"http://x"'), ("infra", '"a b.com"'), ("infra", '"localhost"'),
])
def test_champs_provision_invalides(tmp_path, champ, valeur):
    lignes = [l for l in BASE.splitlines() if not l.startswith(champ + " =")]
    texte = "\n".join(lignes) + f"\n{champ} = {valeur}\n"
    # le champ rajouté tombe sous [provision], dernière section du fichier
    ex = examen(tmp_path, texte)
    assert "provision" in ex.erreurs, (champ, valeur)


def test_le_mode_auto_exige_un_profil_complet(tmp_path):
    texte = BASE.replace(f'mot_de_passe = "{EMPREINTE}"', 'mot_de_passe = "demander"')
    ex = examen(tmp_path, texte)
    assert "provision" in ex.erreurs and "écran" in ex.erreurs["provision"]
    one_shot = texte.replace('mode = "auto"', 'mode = "one-shot"')
    assert "provision" not in examen(tmp_path, one_shot).erreurs                    # l'atelier a un opérateur devant l'écran


def test_la_section_provision_est_obligatoire(tmp_path):
    texte = BASE.split("[provision]")[0]
    assert "provision" in examen(tmp_path, texte).manquantes


def test_fichier_trop_gros_ou_illisible_refuse(tmp_path):
    with pytest.raises(V.FichierInvalide, match="taille"):
        V.lit_strict(ecrit(tmp_path, BASE + "#" + "x" * 70000))
    with pytest.raises(V.FichierInvalide):
        V.lit_strict(ecrit(tmp_path, "pas = du toml ["))
    with pytest.raises(V.FichierInvalide):
        V.lit_strict(tmp_path / "absent.toml")


def test_le_mode_lenient_de_premier_pas_est_inchange(tmp_path):
    p = tomllib.loads(BASE)
    ex = P.examine(p, CONNUS)                                  # l'assistant ignore [provision] et ne refuse rien de plus
    assert ex.complet


# ── signature détachée : vrai gpg dans un trousseau jetable ─────────────────────────────────────────────
def gpg(home, *args, entree=None):
    env = dict(os.environ, GNUPGHOME=str(home))
    return subprocess.run(["gpg", "--batch", "--yes", "--no-tty", *args], env=env, input=entree, capture_output=True, check=True)


@pytest.fixture
def cle(tmp_path):
    def faire(nom):
        home = tmp_path / f"gnupg-{nom}"
        home.mkdir(mode=0o700)
        gpg(home, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", f"{nom} <{nom}@test.invalid>", "ed25519", "sign", "never")
        ring = tmp_path / f"{nom}.gpg"
        ring.write_bytes(gpg(home, "--export").stdout)
        return home, ring
    return faire


def signe(home, fichier):
    sig = Path(str(fichier) + ".sig")
    gpg(home, "--pinentry-mode", "loopback", "--passphrase", "", "--output", str(sig), "--detach-sign", str(fichier))
    return sig


def test_signature_valide_acceptee(tmp_path, cle):
    home, ring = cle("provisioning")
    f = ecrit(tmp_path, BASE)
    V.verifier_signature(f, signe(home, f), ring)
    assert V.charger_signe(f, Path(str(f) + ".sig"), ring, CONNUS).complet


def test_fichier_modifie_apres_signature_refuse(tmp_path, cle):
    home, ring = cle("provisioning")
    f = ecrit(tmp_path, BASE)
    sig = signe(home, f)
    f.write_text(BASE.replace('profil = "lite"', 'profil = "full"'), encoding="utf-8")
    with pytest.raises(V.SignatureInvalide):
        V.verifier_signature(f, sig, ring)
    with pytest.raises(V.SignatureInvalide):
        V.charger_signe(f, sig, ring, CONNUS)


def test_signature_d_une_cle_non_reconnue_refusee(tmp_path, cle):
    _, ring = cle("provisioning")
    intrus_home, _ = cle("intrus")
    f = ecrit(tmp_path, BASE)
    with pytest.raises(V.SignatureInvalide):
        V.verifier_signature(f, signe(intrus_home, f), ring)


def test_absence_de_signature_ou_de_trousseau_refusee(tmp_path, cle):
    home, ring = cle("provisioning")
    f = ecrit(tmp_path, BASE)
    sig = signe(home, f)
    with pytest.raises(V.SignatureInvalide, match="signature"):
        V.verifier_signature(f, tmp_path / "absente.sig", ring)
    with pytest.raises(V.SignatureInvalide, match="trousseau"):
        V.verifier_signature(f, sig, tmp_path / "absent.gpg")
    with pytest.raises(V.SignatureInvalide):
        V.verifier_signature(f, f, ring)                       # un fichier quelconque n'est pas une signature


def test_un_nom_de_fichier_hostile_n_est_pas_interprete(tmp_path, cle):
    home, ring = cle("provisioning")
    f = ecrit(tmp_path, BASE, nom="-o;touch pwned.toml")
    V.verifier_signature(f, signe(home, f), ring)
    assert not (tmp_path / "pwned.toml").exists() and not Path("pwned.toml").exists()


def _cli(*args):
    ctl = Path(__file__).resolve().parents[1] / "sbin" / "premier-pasctl"
    return subprocess.run([sys.executable, str(ctl), *args], capture_output=True, text=True)


def test_cli_reponses_accepte_refuse_et_signale(tmp_path, cle):
    home, ring = cle("provisioning")
    f = ecrit(tmp_path, BASE)
    sig = signe(home, f)
    ok = _cli("reponses", "--fichier", str(f), "--signature", str(sig), "--trousseau", str(ring), "--json")
    assert ok.returncode == 0 and '"valide": true' in ok.stdout
    f.write_text(BASE.replace("client-042", "client-043"), encoding="utf-8")
    ko = _cli("reponses", "--fichier", str(f), "--signature", str(sig), "--trousseau", str(ring))
    assert ko.returncode == 4 and "refusé" in ko.stderr
