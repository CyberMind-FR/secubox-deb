# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Paquet VoiceStudio : ce que debian/rules installe existe, unités durcies, route nginx sûre, pages propres (#1917)."""
import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]


def lire(chemin: str) -> str:
    return (PKG / chemin).read_text()


def test_tout_ce_que_les_regles_installent_existe():
    rules = lire("debian/rules")
    sources = re.findall(r"install -(?:D )?-m \d+ (?:-D )?([\w./-]+) \$\(", rules)
    sources += re.findall(r"install -m \d+ ([\w./-]+) \$\(M\)", rules)
    sources += re.findall(r"cp -r ([\w./-]+) \$\(S\)", rules)
    assert len(sources) >= 10
    for s in sources:
        assert (PKG / s).exists(), f"debian/rules installe {s}, absent de l'arbre"


def test_les_scripts_de_maintenance_sont_posix_et_sans_podman():
    for f in ("postinst", "prerm", "postrm"):
        assert subprocess.run(["sh", "-n", str(PKG / "debian" / f)]).returncode == 0
        code = "\n".join(ligne for ligne in lire(f"debian/{f}").splitlines() if not ligne.lstrip().startswith("#"))
        assert not re.search(r"\b(podman|docker|buildah)\b", code), f"{f} pilote un runtime de conteneurs OCI"


def test_le_controle_ne_depend_ni_de_podman_ni_de_docker():
    ctl = lire("debian/control")
    assert not re.search(r"^\s*(Depends|Recommends|Suggests):.*\b(podman|docker|buildah|crun)\b", ctl, re.M)
    assert "lxc" in ctl and "Architecture: amd64" in ctl


def test_la_configuration_n_est_pas_un_conffile():
    """Livrée sous /usr/share : la mise à jour depuis l'ancien schéma ne pose aucune question dpkg."""
    rules = lire("debian/rules")
    assert "/etc/secubox/voicestudio.toml" not in re.sub(r"#.*", "", rules)
    assert "usr/share/secubox/voicestudio/voicestudio.toml" in rules.replace("$(S)/voicestudio/", "usr/share/secubox/voicestudio/")


@pytest.mark.parametrize("unite", ["api", "pub", "provision"])
def test_les_unites_systemd_existent_et_sont_installees(unite):
    f = PKG / "systemd" / f"secubox-voicestudio-{unite}.service"
    assert f.exists() and f"secubox-voicestudio-{unite}.service" in lire("debian/rules")


def test_l_unite_api_suit_les_regles_de_durcissement():
    u = lire("systemd/secubox-voicestudio-api.service")
    sans_commentaires = "\n".join(ligne for ligne in u.splitlines() if not ligne.lstrip().startswith("#"))
    assert "User=secubox" in u and "User=root" not in u
    assert "ExecStartPre=+/bin/rm -f /run/secubox/voicestudio.sock" in u          # socket périmée (§ Socket)
    assert "RuntimeDirectory=secubox" not in sans_commentaires                    # proscrit : efface les voisines
    # Le socket naît en 660 par UMask=0007 ; un chmod après coup courait contre le démarrage (#2018).
    assert "UMask=0007" in u and not re.search(r"(?m)^ExecStartPost=.*chmod", u)
    for ligne in ("ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "ProtectControlGroups=true"):
        assert ligne in u, ligne
    # NoNewPrivileges=no est la seule dérogation, et elle est justifiée par le sudoers du module.
    assert "NoNewPrivileges=no" in u and "sudoers" in u
    assert "--uds /run/secubox/voicestudio.sock" in u


def test_le_mandataire_n_ecoute_que_le_loopback_par_defaut_et_jamais_le_wan():
    s = lire("systemd/secubox-voicestudio-pub.socket")
    ecoutes = re.findall(r"^ListenStream=(.+)$", s, re.M)
    assert ecoutes == ["127.0.0.1:3900"]
    assert "0.0.0.0" not in s and "[::]" not in s
    assert "FreeBind=true" in s


def test_le_mandataire_reveille_le_lxc_avant_d_ecouter():
    p = lire("systemd/secubox-voicestudio-pub.service")
    assert "ExecStartPre=+/usr/sbin/voicestudioctl wake" in p
    assert "systemd-socket-proxyd 10.100.0.230:3900" in p
    assert "NoNewPrivileges=true" in p


def test_le_provisionnement_est_une_fois_et_hors_dpkg():
    u = lire("systemd/secubox-voicestudio-provision.service")
    assert "ConditionPathExists=!/var/lib/secubox/voicestudio/.lxc-provisioned" in u
    assert "Type=oneshot" in u and "TimeoutStartSec=3600" in u
    post = lire("debian/postinst")
    assert "start --no-block secubox-voicestudio-provision.service" in post


def test_la_postinst_ne_prend_pas_le_port_tant_que_l_ancien_moteur_le_tient():
    post = lire("debian/postinst")
    actif = "\n".join(ligne for ligne in post.splitlines() if not ligne.lstrip().startswith("#"))
    assert "restart secubox-voicestudio-pub.socket" not in actif
    assert "enable secubox-voicestudio-pub.socket" in actif
    # Le démarrage n'a lieu que si le LXC existe ET que l'ancien moteur ne tient plus le port.
    m = re.search(r"if \[ -f /var/lib/secubox/voicestudio/.lxc-provisioned \]\s*\\?\s*&& ! systemctl is-active --quiet "
                  r"secubox-voicestudio.service[^\n]*\n\s*systemctl start secubox-voicestudio-pub.socket", actif)
    assert m, "démarrage du mandataire non conditionné"
    assert actif.count("start secubox-voicestudio-pub.socket") == 1


def test_le_marqueur_du_provisionnement_est_celui_du_ctl_et_du_script():
    assert "/var/lib/secubox/voicestudio/.lxc-provisioned" in lire("systemd/secubox-voicestudio-provision.service")
    assert '".lxc-provisioned"' in lire("lxc/install-lxc.sh") or ".lxc-provisioned" in lire("lxc/install-lxc.sh")
    assert ".lxc-provisioned" in lire("sbin/voicestudioctl")


def test_la_route_nginx_n_ajoute_pas_de_timeout_en_double_et_borne_l_audio():
    n = re.sub(r"#.*", "", lire("nginx/voicestudio.conf"))
    assert "proxy_pass http://unix:/run/secubox/voicestudio.sock:/;" in n
    assert "proxy_read_timeout" not in n and "error_page" not in n and "alias" not in n
    assert re.search(r"client_max_body_size\s+12m;", n)
    assert "include /etc/nginx/snippets/secubox-proxy.conf;" in n
    rules = lire("debian/rules")
    assert "secubox-routes.d/voicestudio.conf" in rules and "secubox.d/voicestudio.conf" in rules


def test_les_entrees_de_menu_sont_valides_et_distinctes():
    menus = [json.loads(f.read_text()) for f in sorted((PKG / "menu.d").glob("*.json"))]
    assert len(menus) == 2
    assert len({m["id"] for m in menus}) == 2 and len({m["order"] for m in menus}) == 2
    assert {m["path"] for m in menus} == {"/voicestudio/", "/voicestudio/usager.html"}
    for m in menus:
        assert {"id", "name", "icon", "path", "category", "order", "description"} <= set(m)


def test_les_sources_sont_epinglees_par_commit_et_par_empreinte():
    d = tomllib.loads(lire("conf/voicestudio.toml"))
    assert re.fullmatch(r"[0-9a-f]{40}", d["source"]["commit"]) and re.fullmatch(r"[0-9a-f]{64}", d["source"]["sha256"])
    script = lire("lxc/install-lxc.sh")
    assert "sha256sum -c" in script and script.index("sha256sum -c") < script.index("tar xzf")   # vérifié AVANT d'extraire
    assert "(^/|(^|/)\\.\\.(/|$))" in script                                                     # chemins sortants refusés
    assert "--no-same-owner" in script


def test_les_contraintes_viennent_de_l_image_validee_sans_cuda():
    lignes = [ligne for ligne in lire("conf/contraintes.txt").splitlines() if ligne.strip()]
    assert len(lignes) > 150
    assert not any(re.match(r"(nvidia|triton)", ligne, re.I) for ligne in lignes)
    assert not any("+cu" in ligne or " @ " in ligne for ligne in lignes)
    assert "torch==2.8.0" in lignes and "faster-whisper==1.2.1" in lignes


def test_le_conteneur_est_non_privilegie_sans_ecoute_sur_toutes_les_interfaces():
    script = lire("lxc/install-lxc.sh")
    assert "lxc.idmap = u 0" in script and "OMNIVOICE_BIND_HOST=$LXC_IP" in script
    assert "--host $LXC_IP" in script and "0.0.0.0" not in script.replace("#", "")
    assert "lxc.mount.entry = $DONNEES app/omnivoice_data" in script         # même chemin que l'image : base SQLite
    assert "chmod 0750" in script


def test_la_cle_n_est_jamais_ecrite_par_le_script_d_installation():
    script = lire("lxc/install-lxc.sh")
    assert "OMNIVOICE_API_KEY" not in re.sub(r"#.*", "", script)


@pytest.mark.parametrize("page", ["index.html", "usager.html"])
def test_les_pages_respectent_la_charte(page):
    h = lire(f"www/voicestudio/{page}")
    assert h.lstrip().startswith("<!DOCTYPE html>") and "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in h
    assert "onclick" not in h.lower()                                      # actions par data-* et un écouteur délégué
    assert "sbx_token" in h and "function esc(" in h or page == "usager.html"
    assert "errorToast" in h and "'✕'" in h                                # erreurs persistantes, fermables
    assert "Courier Prime" in h and "#00d4ff" in h
    assert "verify=False" not in h and "eval(" not in h
    assert "@media" in h or "max-width" in h                               # adaptatif


def test_la_page_d_administration_est_dans_le_chassis_et_masque_sa_coquille_encadree():
    h = lire("www/voicestudio/index.html")
    assert '<nav class="sidebar" id="sidebar"></nav>' in h and "/shared/sidebar.js" in h
    assert "window.top !== window.self" in h and "sbx-embed" in h


def test_la_page_d_usager_est_autonome_et_ne_porte_aucune_action_d_administration():
    h = lire("www/voicestudio/usager.html")
    assert "/shared/sidebar.js" not in h
    for interdit in ("/start", "/stop", "/restart", "/config", "/publier", "/cle", "/sauvegarde", "/journal", "/installer"):
        assert f"'{interdit}'" not in h, interdit
    assert "/api/v1/voicestudio/usager" in h


def test_les_deux_facettes_offrent_les_memes_fonctions_utiles():
    """Parité (§ 7) : ce que la webui sait faire de non destructif, la page d'usager le sait aussi."""
    admin, usager = lire("www/voicestudio/index.html"), lire("www/voicestudio/usager.html")
    for fonction in ("dire", "transcrire", "voix"):
        assert f"/{fonction}" in admin or fonction in admin
    assert "/dire" in usager and "/transcrire" in usager and "/voix" in usager


def test_le_mandataire_ne_tourne_pas_en_root_mais_reveille_en_root():
    p = lire("systemd/secubox-voicestudio-pub.service")
    assert "User=nobody" in p and "ExecStartPre=+/usr/sbin/voicestudioctl wake" in p
    for ligne in ("ProtectSystem=strict", "ProtectHome=true", "PrivateDevices=true", "RestrictSUIDSGID=true", "UMask=0027"):
        assert ligne in p, ligne


def test_le_provisionnement_est_confine_sans_casser_newuidmap():
    u = lire("systemd/secubox-voicestudio-provision.service")
    assert "ProtectHome=true" in u and "LockPersonality=true" in u
    assert "RestrictSUIDSGID=true" not in re.sub(r"#.*", "", u)          # newuidmap est setuid


def test_pip_installe_torch_depuis_l_index_pytorch_seul():
    """Pas de --extra-index-url : un nom présent sur les deux index ne peut pas être « confondu »."""
    sh = re.sub(r"#.*", "", lire("lxc/install-lxc.sh"))
    assert "--extra-index-url" not in sh
    assert "--index-url https://download.pytorch.org/whl/cpu" in sh and "--no-deps" in sh
    assert "pip check" in sh


def test_les_valeurs_du_toml_ne_sont_pas_interpolees_dans_les_commandes_du_conteneur():
    sh = lire("lxc/install-lxc.sh")
    assert '_ "$DEPOT" "$COMMIT"' in sh and '_ "$SHA256"' in sh
    assert "$DEPOT/archive/$COMMIT" not in re.sub(r"#.*", "", sh).replace('"$1/archive/$2', "")


def test_la_page_d_usager_ne_charge_aucune_ressource_tierce():
    h = lire("www/voicestudio/usager.html")
    assert not re.search(r"""(src|href)=["']https?://""", re.sub(r"<!--.*?-->", "", h, flags=re.S))


def test_le_panneau_lit_le_detail_reserve_a_l_administrateur():
    h = lire("www/voicestudio/index.html")
    assert "api('/detail')" in h and "api('/status')" not in h


def test_le_port_est_ferme_a_la_desinstallation():
    assert "voicestudioctl pare-feu-ferme" in lire("debian/prerm")
    assert "/etc/nftables.d/zz-secubox-voicestudio.nft" in lire("debian/postrm")


def test_le_fichier_nft_est_charge_apres_la_base_et_n_est_pas_un_conffile():
    """zz- : trié APRÈS les fichiers qui créent les tables (leçon des fanouts) ; généré, donc hors dpkg."""
    ctl = lire("sbin/voicestudioctl")
    assert 'NFT_FICHIER = "zz-secubox-voicestudio.nft"' in ctl
    assert "nftables.d" not in re.sub(r"#.*", "", lire("debian/rules"))


IMPLIQUENT_NNP = ("ProtectKernelTunables", "RestrictSUIDSGID", "LockPersonality", "RestrictNamespaces", "SystemCallFilter",
                  "MemoryDenyWriteExecute", "RestrictRealtime", "RestrictAddressFamilies", "ProtectKernelModules",
                  "ProtectKernelLogs", "ProtectClock", "ProtectHostname", "SystemCallArchitectures")


def test_l_unite_api_n_a_aucun_reglage_qui_impose_no_new_privileges():
    """Régression (vue sur gk3) : ces réglages posent NoNewPrivileges=yes en douce et sudo — donc la seule porte
    privilégiée du module — répond « The "no new privileges" flag is set », quoi que dise NoNewPrivileges=no."""
    u = re.sub(r"#.*", "", lire("systemd/secubox-voicestudio-api.service"))
    for reglage in IMPLIQUENT_NNP:
        assert not re.search(rf"^\s*{reglage}\s*=", u, re.M), f"{reglage} neutralise sudo"
    assert "NoNewPrivileges=no" in u


def test_une_session_absente_n_est_pas_annoncee_comme_une_panne_d_api():
    h = lire("www/voicestudio/index.html")
    assert "e.message === '401'" in h and "Connexion requise" in h and "Réservé aux administrateurs" in h


CATEGORIES_STANDARD = ("wall", "mind", "mesh", "auth", "root", "boot")      # Muraille, Esprit, Maillage, Accès, Racine, Amorce


def test_les_entrees_de_menu_sont_dans_l_une_des_six_categories_standard():
    """Le Hall (liste « Système ») ne connaît que six catégories : une entrée dans « apps » ou « services » est
    INVISIBLE (vu sur gk3 : voicestudio absent des 121 modules). VoiceStudio va dans Esprit, avec zia et mood."""
    for f in sorted((PKG / "menu.d").glob("*.json")):
        cat = json.loads(f.read_text())["category"]
        assert cat in CATEGORIES_STANDARD, f"{f.name} : catégorie « {cat} » inconnue du Hall"
        assert cat == "mind", f.name


def test_les_entrees_de_menu_sont_servies_par_la_console_pas_par_un_domaine_devine():
    """Sans `same_origin`, le registre invente `<id>.gk2.secubox.in` (vu dans le Hall : voicestudio.gk2.secubox.in,
    qui n'existe pas). Le module est servi sur le domaine de la console, sous /voicestudio/ : même origine."""
    for f in sorted((PKG / "menu.d").glob("*.json")):
        d = json.loads(f.read_text())
        assert d.get("same_origin") is True, f.name
        assert "domain" not in d and d["path"].startswith("/voicestudio/"), f.name


# ── interface native ─────────────────────────────────────────────────────────────────────────────────────────────
def test_la_configuration_epingle_bun_par_version_et_empreinte():
    d = tomllib.loads(lire("conf/voicestudio.toml"))["interface"]
    assert d["activer"] is True and re.fullmatch(r"[0-9a-f]{64}", d["bun_sha256"])
    assert d["bun_version"] in d["bun_url"] and d["bun_url"].startswith("https://github.com/oven-sh/bun/releases/download/")
    assert d["domaine"] == "voicestudio"


def test_la_construction_verifie_bun_avant_de_l_executer_et_ne_laisse_que_dist():
    sh = lire("lxc/install-lxc.sh")
    corps = sh[sh.index("construire_interface_dans_le_lxc() {"):sh.index("construire_interface() {")]
    assert corps.index("sha256sum -c") < corps.index("unzip -q")                  # empreinte AVANT de déplier
    assert corps.index("unzip -q") < corps.index('"$B" install --frozen-lockfile')
    assert '"$B" install --frozen-lockfile' in corps and '"$B" run --cwd frontend build' in corps     # recette du Dockerfile amont
    assert "rm -rf /tmp/fb /opt/bun /tmp/bun.zip /root/.bun" in corps             # il ne reste que dist
    assert not re.search(r"\|\s*(sh|bash)\b", corps)                                   # jamais « curl | sh »
    assert '_ "$BUN_URL"' in corps and '_ "$BUN_SHA256"' in corps                  # valeurs en arguments, pas interpolées


def test_le_moteur_est_arrete_pendant_la_construction_et_toujours_relance():
    sh = lire("lxc/install-lxc.sh")
    corps = sh[sh.index("construire_interface() {"):]
    assert corps.index("systemctl stop voicestudio.service") < corps.index("construire_interface_dans_le_lxc || rc=$?")
    assert corps.index("construire_interface_dans_le_lxc || rc=$?") < corps.index("systemctl start voicestudio.service")
    assert 'if [ "$etait_actif" = 1 ]; then la systemctl start' in corps          # relancé même si la construction a échoué


def test_l_unite_de_construction_ne_tourne_qu_une_fois_apres_le_provisionnement():
    u = lire("systemd/secubox-voicestudio-interface.service")
    assert "ConditionPathExists=/var/lib/secubox/voicestudio/.lxc-provisioned" in u
    assert "ConditionPathExists=!/var/lib/secubox/voicestudio/.interface-native" in u
    assert "ExecStart=/usr/sbin/voicestudioctl interface" in u and "secubox-voicestudio-interface.service" in lire("debian/rules")
    assert "start --no-block secubox-voicestudio-interface.service" in lire("debian/postinst")


def test_la_postinst_expose_le_domaine_comme_les_modules_a_domaine_propre():
    post = lire("debian/postinst")
    assert 'secubox-domaine voicestudio' in post and "haproxyctl vhost add" in post and "haproxy-routes.json" in post
    assert '["127.0.0.1", 9080]' in post and "restart secubox-waf-ng" in post
    assert "kill -HUP" not in post and "SIGHUP" not in re.sub(r"#.*", "", post)       # un SIGHUP tue sbxwaf


def test_la_desinstallation_retire_le_vhost_et_la_cle_nginx():
    assert "voicestudioctl interface-ferme" in lire("debian/prerm")
    postrm = lire("debian/postrm")
    assert "secubox-voicestudio.conf" in postrm and "secubox-voicestudio-cle.conf" in postrm


def test_la_cle_nginx_n_est_ecrite_que_par_le_ctl_et_en_0600():
    ctl = lire("sbin/voicestudioctl")
    assert "os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600" in ctl[ctl.index("def appliquer_vhost"):]
    assert "secubox-voicestudio-cle.conf" in ctl and "secubox-voicestudio-cle" not in lire("debian/rules")   # pas livrée par dpkg


def test_la_console_montre_la_memoire_de_la_box_et_dit_ce_que_la_synthese_demande():
    h = lire("www/voicestudio/index.html")
    assert "memoire_hote" in h and "Mémoire de la box" in h and "Synthèse vocale" in h and "3800" in h


def test_le_paquet_cree_le_swap_disque_et_recommande_son_paquet():
    assert "secubox-tuning-apply swap" in lire("debian/postinst")
    assert "secubox-system-tuning (>= 1.2.5)" in lire("debian/control") and "secubox-profiles" in lire("debian/control")


def test_la_configuration_livre_les_reglages_memoire():
    d = tomllib.loads(lire("conf/voicestudio.toml"))
    assert d["moteur"]["liberation_modele_s"] == 60 and d["moteur"]["precharger_dictee"] is False
    assert d["memoire"]["besoin_synthese_mo"] == 3800 and d["memoire"]["modele_residente_mo"] == 2500
    assert d["memoire"]["delai_repetition_s"] == 120


def test_le_delai_du_moteur_couvre_une_synthese_a_froid():
    """Mesuré sur gk3 : 109 s à froid (chargement du modèle + calcul CPU). Un délai de 120 s était trop juste."""
    assert tomllib.loads(lire("conf/voicestudio.toml"))["limites"]["delai_s"] >= 300


# ── voix rapide (#1917) ──────────────────────────────────────────────────────────────────────────────────────────────
def test_la_voix_rapide_est_livree_verifiee_et_activee_par_le_paquet():
    assert "lxc/voix-rapide.py" in lire("debian/rules") and "secubox-voicestudio-rapide.service" in lire("debian/rules")
    assert "secubox-voicestudio-rapide.service" in lire("debian/postinst") and "secubox-voicestudio-rapide.service" in lire("debian/prerm")
    r = tomllib.loads(lire("conf/voicestudio.toml"))["rapide"]
    assert r["activer"] is True and r["modele_url"].startswith("https://") and re.fullmatch(r"[0-9a-f]{64}", r["modele_sha256"])
    inst = lire("lxc/install-lxc.sh")
    assert "sha256sum -c" in inst and "installer_voix_rapide" in inst and "--voix-rapide" in inst
    assert subprocess.run(["bash", "-n", str(PKG / "lxc/install-lxc.sh")]).returncode == 0
    assert subprocess.run(["python3", "-m", "py_compile", str(PKG / "lxc/voix-rapide.py")]).returncode == 0


def test_le_serveur_de_la_voix_rapide_exige_la_cle_et_borne_l_entree(monkeypatch):
    import http.client
    import importlib.util
    import threading
    monkeypatch.setenv("VOIX_RAPIDE_HOTE", "127.0.0.1")
    monkeypatch.setenv("OMNIVOICE_API_KEY", "cle-de-test")
    spec = importlib.util.spec_from_file_location("voix_rapide", PKG / "lxc/voix-rapide.py")
    vr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vr)
    monkeypatch.setattr(vr, "synthetiser", lambda t, f: b"AUDIO:" + t.encode())
    srv = vr.ThreadingHTTPServer(("127.0.0.1", 0), vr.Poignee)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(corps, cle="cle-de-test"):
        h = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
        h.request("POST", "/v1/audio/speech", body=json.dumps(corps), headers={"Authorization": f"Bearer {cle}"} if cle else {})
        r = h.getresponse()
        return r.status, r.read()
    try:
        assert post({"input": "Bonjour"}) == (200, b"AUDIO:Bonjour")
        assert post({"input": "Bonjour"}, cle="autre")[0] == 401 and post({"input": "Bonjour"}, cle="")[0] == 401
        assert post({"input": ""})[0] == 422 and post({"input": "x" * 4001})[0] == 422
        assert post({"input": "a", "response_format": "exe"})[0] == 422
    finally:
        srv.shutdown()


def test_unite_de_demarrage_du_lxc_est_livree_et_activee_2021():
    # #2021 : sans elle, un LXC arrêté au boot (lxc.service masqué sur gk3) donne un 502 à l'interface.
    unite = (PKG / "systemd" / "secubox-voicestudio-demarrage.service").read_text()
    assert "ExecStart=/usr/sbin/voicestudioctl boot" in unite
    assert "Type=oneshot" in unite and "RemainAfterExit=yes" in unite
    assert "data-lxc.mount" in unite                       # les conteneurs vivent sur ce volume
    assert "ConditionPathExists=/var/lib/secubox/voicestudio/.lxc-provisioned" in unite
    assert "secubox-voicestudio-demarrage.service" in (PKG / "debian" / "rules").read_text()
    assert "enable secubox-voicestudio-demarrage.service" in (PKG / "debian" / "postinst").read_text()
    assert "secubox-voicestudio-demarrage.service" in (PKG / "debian" / "prerm").read_text()
