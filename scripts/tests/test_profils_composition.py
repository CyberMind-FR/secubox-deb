# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Composition des profils : lite = protection, isp = lite + operateur + hebergement, full = isp + Hall."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def deps(profil):
    texte = (RACINE / "packages" / f"secubox-{profil}" / "debian" / "control").read_text()
    bloc = re.search(r"^Depends:(.*?)(?=^[A-Z][A-Za-z-]*:)", texte, re.S | re.M).group(1)
    sans_commentaires = "\n".join(l for l in bloc.splitlines() if not l.strip().startswith("#"))
    return set(re.findall(r"secubox-([a-z0-9-]+)", sans_commentaires))


def _champ(profil, champ):
    texte = (RACINE / "packages" / f"secubox-{profil}" / "debian" / "control").read_text()
    m = re.search(rf"^{champ}:(.*?)(?=^[A-Z][A-Za-z-]*:)", texte, re.S | re.M)
    bloc = "\n".join(l for l in (m.group(1) if m else "").splitlines() if not l.strip().startswith("#"))
    return set(re.findall(r"((?:secubox|sbxos)-[a-z0-9-]+)", bloc))


# Appartenance de chaque module a UN profil (decision du 2026-10-08) :
#   lite = tous les modules de protection
#   isp  = lite + operateur + tous les modules d'hebergement
#   full = isp + tout le contenu du Hall
# Meme regle que l'arbre : un module de l'arbre est dans un profil, ou declare
# hors profil (materiel, vestige) et reste installable a la demande.
HORS_PROFIL = {
    "secubox-c3box", "secubox-daemon-c3box", "secubox-eye-remote", "secubox-rbs-sensor",
    "secubox-led-heartbeat", "secubox-meshtastic", "secubox-daemon", "secubox-ui-manager",
    "secubox-voice-moteur", "secubox-zia-llm", "secubox-zkp", "secubox-clamav",
    "secubox-netboot", "secubox-vm",
}
PROTECTIONS = {f"secubox-{m}" for m in (
    "waf-ng", "ipblock", "toolbox-ng", "toolbox", "dpi", "ndpid-engine", "interceptor",
    "security-posture", "threats", "threatmesh", "ad-guard", "webfilter", "dns-guard",
    "cookies", "soc", "soc-agent", "nac", "ipv6guard", "wan-link-guard", "hardening",
    "wireguard", "vault", "backup", "haproxy", "dns", "routes", "qos", "freebox", "certs", "tor")}
HEBERGEMENT = {f"secubox-{m}" for m in (
    "mail", "matrix", "jitsi", "nextcloud", "photoprism", "gitea", "metablogizer", "bbs",
    "billets", "socialrelay", "metanews", "messagerie", "cdn", "saas-relay")}
HALL = {f"secubox-{m}" for m in (
    "webos", "sbxos", "surf", "ephemeride", "zia", "voice", "voicestudio", "radio", "podcaster",
    "peertube", "jellyfin", "ytsas", "media", "lyrion", "mqtt", "ai-gateway", "streamlit",
    "avatar", "repo", "console", "assist")} | {"sbxos-audio-mood"}


def test_lite_porte_toutes_les_protections():
    assert PROTECTIONS <= _champ("lite", "Depends")


def test_lite_ne_heberge_rien():
    assert not ((HEBERGEMENT | HALL) & _champ("lite", "Depends"))


def test_isp_herite_de_lite_et_porte_tout_l_hebergement():
    d = _champ("isp", "Depends")
    assert "secubox-lite" in d
    assert HEBERGEMENT <= d
    assert not (HALL & d)


def test_full_herite_de_isp_et_porte_tout_le_hall():
    d = _champ("full", "Depends")
    assert "secubox-isp" in d
    assert HALL <= d | _champ("full", "Recommends")


def test_aucun_module_dans_deux_profils():
    lite, isp, full = (_champ(p, "Depends") - {"secubox-lite", "secubox-isp"} for p in ("lite", "isp", "full"))
    assert not (lite & isp) and not (lite & full) and not (isp & full)


def test_chaque_module_de_l_arbre_est_dans_un_profil_ou_hors_profil():
    """Un module neuf de l'arbre doit etre place : sans quoi il n'est dans aucune image."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_meta", RACINE / "packages" / "secubox-meta" / "gen-meta.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    noeuds, _ = gen.lit_arbre(str(RACINE / "packages" / "secubox-meta" / "arbre.yaml"))
    metas = {n["meta"] for n in noeuds}
    feuilles = {x for n in noeuds if n["niveau"] == "service"
                for k in ("requiert", "recommande", "suggere") for x in n[k] if x not in metas}
    places = set()
    for p in ("lite", "isp", "full"):
        places |= _champ(p, "Depends") | _champ(p, "Recommends")
    assert not (feuilles - places - HORS_PROFIL), sorted(feuilles - places - HORS_PROFIL)
    assert not (HORS_PROFIL & places)


def test_full_s_installe_sur_toute_architecture():
    """secubox-full exigeait secubox-sentinelle-gsm, publie en arm64 seulement : non installable sur amd64."""
    assert "secubox-sentinelle-gsm" not in _champ("full", "Depends")
    assert "secubox-sentinelle-gsm" not in _champ("lite", "Depends")


def test_aucun_paquet_retire_ou_transitionnel_dans_un_profil():
    retires = {"secubox-vortex-dns", "secubox-waf", "secubox-localrecall", "secubox-streamforge", "secubox-zigbee"}
    for p in ("lite", "isp", "full"):
        assert not (retires & (_champ(p, "Depends") | _champ(p, "Recommends")))


def _version(module):
    ch = RACINE / "packages" / f"secubox-{module}" / "debian" / "changelog"
    m = re.match(r"secubox-[a-z0-9-]+ \(([^)]+)\)", ch.read_text())
    return m.group(1) if m else None


def _num(v):
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0].split(":")[-1])[:3])


def test_les_contraintes_de_version_des_profils_sont_satisfaisables():
    """`secubox-lite` exigeait secubox-antirootkit (>= 1.0) alors que ce paquet est en 0.1.6 :
    le profil était impossible à installer, et toutes les images échouaient."""
    violations = []
    for profil in ("lite", "isp", "full"):
        texte = (RACINE / "packages" / f"secubox-{profil}" / "debian" / "control").read_text()
        bloc = re.search(r"^Depends:(.*?)(?=^[A-Z][A-Za-z-]*:)", texte, re.S | re.M).group(1)
        for ligne in bloc.splitlines():
            if ligne.strip().startswith("#"):
                continue
            for module, exige in re.findall(r"secubox-([a-z0-9-]+)\s*\(>=\s*([0-9][^)]*)\)", ligne):
                v = _version(module)
                if v is not None and _num(v) < _num(exige):
                    violations.append(f"secubox-{profil} exige secubox-{module} (>= {exige}), le paquet est en {v}")
    assert not violations, violations
