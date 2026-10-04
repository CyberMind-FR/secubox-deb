# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Pose les fichiers générés : sauvegarde, écriture atomique, validation par unbound-checkconf, retour arrière si elle échoue.
Unbound n'est rechargé que si la configuration EFFECTIVE (lignes hors commentaires) change : une mise à jour qui ne touche que les
commentaires ne coupe jamais le DNS."""
import json
import os
import subprocess
import time
from pathlib import Path

from . import rendu

AUDIT = Path(os.environ.get("SECUBOX_DNS_LAN_AUDIT", "/var/log/secubox/audit.log"))
CHECKCONF = os.environ.get("SECUBOX_DNS_LAN_CHECKCONF", "unbound-checkconf")
CONTROL = os.environ.get("SECUBOX_DNS_LAN_CONTROL", "unbound-control")
NETWORKCTL = os.environ.get("SECUBOX_DNS_LAN_NETWORKCTL", "networkctl")


class ErreurApplication(RuntimeError):
    """La configuration n'a pas pu être appliquée ; l'état précédent est remis."""


def effectives(texte: str) -> list[str]:
    return [x.strip() for x in texte.splitlines() if x.strip() and not x.strip().startswith("#")]


class Systeme:
    """Les effets de bord réels ; les tests injectent un faux."""

    def verifier_unbound(self) -> tuple[bool, str]:
        r = subprocess.run([CHECKCONF], capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]

    def recharger_unbound(self) -> None:
        r = subprocess.run([CONTROL, "reload"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise ErreurApplication("unbound-control reload a échoué : " + (r.stdout + r.stderr).strip()[-200:])

    def recharger_reseau(self) -> None:
        r = subprocess.run([NETWORKCTL, "reload"], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise ErreurApplication("networkctl reload a échoué : " + (r.stdout + r.stderr).strip()[-200:])

    def audit(self, action: str, detail: str = "") -> None:
        try:
            with open(AUDIT, "a", encoding="utf-8") as f:                       # ajout seul ; le journal ne doit jamais bloquer l'opération
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "dns-lan",
                                    "action": action, "detail": detail[:200]}, ensure_ascii=False) + "\n")
        except OSError:
            pass


def _lire(chemin: Path) -> str | None:
    try:
        return chemin.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _ecrire_atomique(chemin: Path, texte: str) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_name("." + chemin.name + ".nouveau")
    tmp.write_text(texte, encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, chemin)


def _est_unbound(chemin: str, cfg: dict) -> bool:
    return Path(chemin).parent == Path(cfg["dossier"])


def deriver(cfg: dict) -> list[str]:
    """Chemins dont le contenu effectif sur disque diffère de ce que le TOML produirait."""
    ecart = []
    for chemin, texte in rendu.rendre(cfg).items():
        actuel = _lire(Path(chemin))
        if actuel is None or effectives(actuel) != effectives(texte):
            ecart.append(chemin)
    return ecart


def generer(cfg: dict, systeme: Systeme | None = None) -> dict:
    s = systeme or Systeme()
    voulu = rendu.rendre(cfg)
    avant = {c: _lire(Path(c)) for c in voulu}
    ecrits = [c for c, t in voulu.items() if avant[c] != t]
    if not ecrits:
        return {"ecrits": [], "recharge_unbound": False, "recharge_reseau": False}
    effectif = {c for c in ecrits if avant[c] is None or effectives(avant[c]) != effectives(voulu[c])}
    recharge_unbound = any(_est_unbound(c, cfg) for c in effectif)
    recharge_reseau = any(not _est_unbound(c, cfg) for c in effectif)
    crees_dossiers: list[Path] = []
    try:
        for c in ecrits:
            p = Path(c)
            if not p.parent.exists():
                crees_dossiers.append(p.parent)
            _ecrire_atomique(p, voulu[c])
        if any(_est_unbound(c, cfg) for c in ecrits):
            ok, sortie = s.verifier_unbound()
            if not ok:
                raise ErreurApplication("unbound-checkconf refuse la configuration : " + sortie)
    except (ErreurApplication, OSError) as e:
        for c in ecrits:                                                        # retour arrière : l'état précédent, octet pour octet
            p = Path(c)
            if avant[c] is None:
                p.unlink(missing_ok=True)
            else:
                _ecrire_atomique(p, avant[c])
        for d in crees_dossiers:
            try:
                d.rmdir()
            except OSError:
                pass
        s.audit("generate-refuse", str(e)[:180])
        raise e if isinstance(e, ErreurApplication) else ErreurApplication(f"écriture impossible : {e}") from e
    if recharge_unbound:
        s.recharger_unbound()
    if recharge_reseau:
        s.recharger_reseau()
    s.audit("generate", f"ecrits={len(ecrits)} unbound={'recharge' if recharge_unbound else 'inchange'} "
                        f"reseau={'recharge' if recharge_reseau else 'inchange'}")
    return {"ecrits": ecrits, "recharge_unbound": recharge_unbound, "recharge_reseau": recharge_reseau}
