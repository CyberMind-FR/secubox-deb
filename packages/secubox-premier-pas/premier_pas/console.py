# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — face CONSOLE (#1522, couche 3)
CyberMind — https://cybermind.fr

curses (bibliothèque standard) et non Textual : Textual n'existe dans
bookworm qu'en 0.1.13, inutilisable, et une box neuve n'a pas pip. curses
marche sur tout terminal, console série d'une carte comprise.

Même moteur que le kiosque : chaque étape passe par premier_pas.remplir.
La console tourne en root sur tty1, elle n'a donc pas besoin du jeton : c'est
l'accès physique à la box qui fait foi, comme pour le kiosque.

Touches : Tab / ↑↓ champ · ←→ choix · Entrée continuer · Échap retour · F10 quitter
"""
from __future__ import annotations

import curses
import locale
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import profil as P
from . import remplir as R


# ── Définition des étapes (logique pure, testée sans curses) ────────────────

@dataclass
class Champ:
    cle: str
    libelle: str
    genre: str = "texte"                      # texte | secret | choix
    options: List[Tuple[str, str]] = field(default_factory=list)   # (valeur, libellé)
    valeur: str = ""
    visible: Callable[[Dict[str, str]], bool] = lambda v: True


@dataclass
class Page:
    id: str
    aide: str
    champs: List[Champ]
    valeurs: Callable[[Dict[str, str]], Dict[str, Any]]


def _profils() -> List[Tuple[str, str]]:
    import tomllib
    out = []
    for p in sorted(P.PROFILS_DIR.glob("*.toml")) if P.PROFILS_DIR.is_dir() else []:
        try:
            d = tomllib.loads(p.read_text())
            out.append((p.stem, f"{d.get('label', p.stem)[:34]} ({len(d.get('on', []))})"))
        except (OSError, ValueError):
            continue
    return out or [("full", "full")]


def _fuseau() -> str:
    try:
        return Path("/etc/timezone").read_text().strip() or "Europe/Paris"
    except OSError:
        return "Europe/Paris"


def pages(profil: Dict[str, Any]) -> List[Page]:
    """Les pages, pré-remplies depuis le profil (vue sans secrets)."""
    b, r = profil.get("box") or {}, profil.get("reseau") or {}
    m, a = profil.get("maillage") or {}, profil.get("apt") or {}
    oui_non = lambda v: "oui" if v is True else "non" if v is False else "oui"  # noqa: E731
    return [
        Page("bienvenue", "Une box SecuBox neuve : nom, administrateur, services, maillage.",
             [Champ("langue", "Langue", "choix", [("fr", "Français"), ("en", "English")], b.get("langue", "fr")),
              Champ("clavier", "Clavier", "choix", [("fr", "fr-azerty"), ("us", "us-qwerty")], b.get("clavier", "fr"))],
             lambda v: {"langue": v["langue"], "clavier": v["clavier"]}),
        Page("nom", "Le nom sous lequel vos appareils et les autres box la verront.",
             [Champ("nom", "Nom", valeur=b.get("nom", ""))], lambda v: {"nom": v["nom"]}),
        Page("horloge", "L'heure juste d'abord : les codes TOTP en dépendent.",
             [Champ("fuseau", "Fuseau", valeur=b.get("fuseau", _fuseau()))],
             lambda v: {"fuseau": v["fuseau"], "ntp": True}),
        Page("admin", "Compte « admin ». 12 caractères au moins ; le QR TOTP viendra à la 1re connexion.",
             [Champ("mot_de_passe", "Mot passe", "secret"), Champ("confirmation", "Encore", "secret")],
             lambda v: {"mot_de_passe": v["mot_de_passe"], "confirmation": v["confirmation"]}),
        Page("reseau", "Comment la box se branche, et sous quel nom on la joint.",
             [Champ("mode", "Mode", "choix", [("routeur", "Routeur"), ("pont", "Pont"), ("lan", "LAN seul")], r.get("mode", "routeur")),
              Champ("domaine", "Domaine", valeur=r.get("domaine", ""), visible=lambda v: v.get("mode") != "lan")],
             lambda v: {"mode": v["mode"], **({"domaine": v["domaine"]} if v["mode"] != "lan" else {})}),
        Page("services", "Ce que la box fera (modifiable plus tard).",
             [Champ("profil", "Profil", "choix", _profils(), (profil.get("services") or {}).get("profil", ""))],
             lambda v: {"profil": v["profil"]}),
        Page("maillage", "Rejoindre vos autres box, ou être la première.",
             [Champ("mode", "Maillage", "choix", [("rejoindre", "Rejoindre"), ("premiere", "Première box"), ("plus_tard", "Plus tard")], m.get("mode", "plus_tard")),
              Champ("rejoindre", "Adresse", valeur=m.get("rejoindre", ""), visible=lambda v: v.get("mode") == "rejoindre"),
              Champ("jeton", "Jeton", "secret", visible=lambda v: v.get("mode") == "rejoindre")],
             lambda v: {"mode": v["mode"], **({"rejoindre": v["rejoindre"], "jeton": v["jeton"]} if v["mode"] == "rejoindre" else {})}),
        Page("majs", "Correctifs de apt.secubox.in, vérifiés par la clé du dépôt.",
             [Champ("auto", "Mises à j", "choix", [("oui", "Automatiques"), ("non", "Sur validation")], oui_non(a.get("auto"))),
              Champ("heure", "Heure", valeur=a.get("heure", "03:00"), visible=lambda v: v.get("auto") == "oui")],
             lambda v: {"auto": v["auto"] == "oui", **({"heure": v["heure"]} if v["auto"] == "oui" else {})}),
    ]


def valeurs_de(page: Page) -> Dict[str, str]:
    v = {}
    for c in page.champs:
        if c.genre == "choix" and not c.valeur and c.options:
            c.valeur = c.options[0][0]
        v[c.cle] = c.valeur
    return v


def champs_visibles(page: Page) -> List[Champ]:
    v = valeurs_de(page)
    return [c for c in page.champs if c.visible(v)]


# ── Rendu curses : cadre de 64 colonnes, comme la maquette ────────────────

L = 64


class Console:
    def __init__(self, ecran):
        self.e = ecran
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        for i, (fg, bg) in enumerate([(curses.COLOR_YELLOW, -1), (curses.COLOR_CYAN, -1),
                                       (curses.COLOR_GREEN, -1), (curses.COLOR_RED, -1),
                                       (8 if curses.COLORS > 8 else curses.COLOR_WHITE, -1)], 1):
            curses.init_pair(i, fg, bg)
        self.OR, self.CY, self.OK, self.KO, self.GR = (curses.color_pair(i) for i in range(1, 6))
        self.i = 0
        self.msg = ""

    def cadre(self, titre: str, compteur: str):
        e = self.e
        e.erase()
        h, w = e.getmaxyx()
        x0 = max(0, (w - L) // 2)
        self.x0 = x0
        e.addstr(1, x0, "┌" + "─" * (L - 2) + "┐", self.OR)
        e.addstr(2, x0, "│", self.OR)
        e.addstr(2, x0 + 2, "SECUBOX · PREMIER PAS", self.CY | curses.A_BOLD)
        e.addstr(2, x0 + L - 2 - len(compteur), compteur, self.GR)
        e.addstr(2, x0 + L - 1, "│", self.OR)
        e.addstr(3, x0, "├" + "─" * (L - 2) + "┤", self.OR)
        for y in range(4, 19):
            e.addstr(y, x0, "│", self.OR)
            e.addstr(y, x0 + L - 1, "│", self.OR)
        e.addstr(19, x0, "├" + "─" * (L - 2) + "┤", self.OR)
        e.addstr(20, x0, "│", self.OR)
        e.addstr(20, x0 + 2, "Tab champ · ←/→ choix · Entrée continuer · Échap retour"[:L - 4], self.GR)
        e.addstr(20, x0 + L - 1, "│", self.OR)
        e.addstr(21, x0, "└" + "─" * (L - 2) + "┘", self.OR)
        e.addstr(5, x0 + 2, titre.upper()[:L - 4], curses.A_BOLD)

    def texte(self, y, x, s, attr=0):
        s = s[:L - 4 - (x - 2)]
        self.e.addstr(y, self.x0 + x, s, attr)

    def lignes(self, texte: str, y: int, largeur: int = L - 4) -> int:
        mot, ligne = texte.split(), ""
        for m in mot:
            if len(ligne) + len(m) + 1 > largeur:
                self.texte(y, 2, ligne, self.GR)
                y, ligne = y + 1, m
            else:
                ligne = (ligne + " " + m).strip()
        if ligne:
            self.texte(y, 2, ligne, self.GR)
        return y + 1

    def page(self, page: Page, n: int, total: int, motif: Optional[str]) -> None:
        self.cadre(P.LIBELLES[page.id], f"{n}/{total}")
        y = self.lignes(page.aide, 7) + 1
        vis = champs_visibles(page)
        self.focus = min(getattr(self, "focus", 0), len(vis) - 1)
        for k, c in enumerate(vis):
            actif = k == self.focus
            self.texte(y, 2, f"{c.libelle:<10}", curses.A_BOLD if actif else 0)
            if c.genre == "choix":
                x = 13
                for val, lib in c.options:
                    marque = "(•)" if c.valeur == val else "( )"
                    s = f"{marque} {lib}  "
                    if x + len(s) > L - 2:
                        y, x = y + 1, 13
                    self.texte(y, x, s, (self.CY | curses.A_BOLD) if c.valeur == val else 0)
                    x += len(s)
            else:
                shown = "•" * len(c.valeur) if c.genre == "secret" else c.valeur
                cadre = f"[ {shown[-(L - 20):]:<{L - 20}}]"
                self.texte(y, 13, cadre, curses.A_REVERSE if actif else 0)
            y += 2
        if page.id == "bienvenue":
            self.texte(15, 2, "Préparer depuis une autre SecuBox, code :", self.GR)
            self.texte(16, 2, code_affiche(), self.OR | curses.A_BOLD)
        self.texte(17, 2, (motif or self.msg)[:L - 4], self.KO)
        self.e.refresh()

    def touche(self):
        """Attend une touche, mais regarde toutes les 2 s si la box maîtresse
        a proposé ou imposé une configuration."""
        self.e.timeout(2000)
        while True:
            try:
                return self.e.get_wch()
            except curses.error:
                p = R.proposition()
                if p.get("statut") == "forcee":
                    return "__force__"
                if p.get("statut") == "en_attente" and p.get("a") != getattr(self, "vue_prop", None):
                    return "__proposition__"

    def boucle_page(self, page: Page, n: int, total: int, motif: Optional[str]) -> str:
        """Rend 'suivant', 'precedent' ou 'quitter'."""
        self.focus = 0
        while True:
            self.page(page, n, total, motif)
            vis = champs_visibles(page)
            c = vis[self.focus]
            k = self.touche()
            if k in ("__force__", "__proposition__"):
                return k
            if k in ("\t", curses.KEY_DOWN):
                self.focus = (self.focus + 1) % len(vis)
            elif k in (curses.KEY_BTAB, curses.KEY_UP):
                self.focus = (self.focus - 1) % len(vis)
            elif k in (curses.KEY_LEFT, curses.KEY_RIGHT) and c.genre == "choix":
                vals = [o[0] for o in c.options]
                j = vals.index(c.valeur) if c.valeur in vals else 0
                c.valeur = vals[(j + (1 if k == curses.KEY_RIGHT else -1)) % len(vals)]
            elif k in ("\n", "\r", curses.KEY_ENTER):
                return "suivant"
            elif k == "\x1b":
                return "precedent"
            elif k == curses.KEY_F10:
                return "quitter"
            elif k in (curses.KEY_BACKSPACE, "\x7f", "\b") and c.genre != "choix":
                c.valeur = c.valeur[:-1]
            elif isinstance(k, str) and k.isprintable() and c.genre != "choix":
                c.valeur += k
            motif = None

    def recap_lignes(self, etat: Dict[str, Any]) -> List[str]:
        p = etat["profil"]
        b, r, m, a = p.get("box") or {}, p.get("reseau") or {}, p.get("maillage") or {}, p.get("apt") or {}
        self.cadre("Appliquer", f"{len(P.ETAPES)}/{len(P.ETAPES)}")
        lignes = [f"{b.get('nom', '—')} · {r.get('mode', '—')}{' · ' + r['domaine'] if r.get('domaine') else ''}",
                  f"services {(p.get('services') or {}).get('profil', '—')}",
                  f"maillage {m.get('mode', '—')}{' ' + m['rejoindre'] if m.get('rejoindre') else ''}",
                  f"mises à jour {'auto ' + a.get('heure', '03:00') if a.get('auto') else 'sur validation'}",
                  f"admin {'mot de passe choisi' if (p.get('admin') or {}).get('mot_de_passe') == 'défini' else '—'}"]
        for i, s in enumerate(lignes):
            self.texte(8 + i, 2, s)
        return lignes

    def recap(self, etat: Dict[str, Any]) -> str:
        p = etat["profil"]
        b, r, m, a = p.get("box") or {}, p.get("reseau") or {}, p.get("maillage") or {}, p.get("apt") or {}
        manque = [e["libelle"] for e in etat["etapes"] if e["statut"] != "pret" and e["id"] != "appliquer"]
        self.cadre("Appliquer", f"{len(P.ETAPES)}/{len(P.ETAPES)}")
        lignes = [f"{b.get('nom', '—')} · {r.get('mode', '—')}{' · ' + r['domaine'] if r.get('domaine') else ''}",
                  f"services {(p.get('services') or {}).get('profil', '—')}",
                  f"maillage {m.get('mode', '—')}{' ' + m['rejoindre'] if m.get('rejoindre') else ''}",
                  f"mises à jour {'auto ' + a.get('heure', '03:00') if a.get('auto') else 'sur validation'}",
                  f"admin {'mot de passe choisi' if (p.get('admin') or {}).get('mot_de_passe') == 'défini' else '—'}"]
        for i, s in enumerate(lignes):
            self.texte(7 + i, 2, s)
        if manque:
            self.texte(14, 2, "À compléter : " + ", ".join(manque), self.KO)
        else:
            self.texte(14, 2, "[ Entrée : Appliquer ]   [ Échap : Retour ]", self.CY | curses.A_BOLD)
        self.texte(17, 2, self.msg[:L - 4], self.KO)
        self.e.refresh()
        while True:
            k = self.touche()
            if k in ("__force__", "__proposition__"):
                return k
            if k in ("\n", "\r", curses.KEY_ENTER) and not manque:
                return "appliquer"
            if k == "\x1b":
                return "precedent"
            if k == curses.KEY_F10:
                return "quitter"

    def proposition(self, p: Dict[str, Any]) -> str:
        """La box maîtresse propose : la décision est ici. Rend accepter|refuser."""
        self.vue_prop = p.get("a")
        e = R.etat()
        self.recap_lignes(e)
        self.texte(6, 2, f"PROPOSITION DE {str(p.get('par', '?')).upper()}", self.OR | curses.A_BOLD)
        self.texte(14, 2, "[ Entrée : Accepter et appliquer ]   [ R : Refuser ]", self.CY | curses.A_BOLD)
        self.e.refresh()
        self.e.timeout(-1)
        while True:
            k = self.e.get_wch()
            if k in ("\n", "\r", curses.KEY_ENTER):
                return "accepter"
            if k in ("r", "R"):
                return "refuser"

    def suivi(self) -> bool:
        """Suit l'application ; rend True si la box est configurée."""
        self.e.timeout(-1)
        while True:
            e = R.etat()
            mo = e.get("moteur") or {}
            self.cadre("La box se configure", "")
            prop = e.get("proposition") or {}
            if prop.get("mode") == "forcer":
                self.texte(6, 2, f"! Configuration imposée à distance par {prop.get('par', '?')}"[:L - 4], self.KO | curses.A_BOLD)
            if e["fait"]:
                self.texte(8, 2, "Votre box est prête.", self.OK | curses.A_BOLD)
                self.lignes("Connectez-vous avec « admin » et votre mot de passe ; la box vous fera "
                            "scanner le QR de votre application d'authentification.", 10)
                self.texte(17, 2, "Entrée : terminer", self.CY)
                self.e.refresh()
                self.e.get_wch()
                return True
            if mo.get("phase") == "echec":
                self.texte(8, 2, f"Arrêt à l'étape « {P.LIBELLES.get(mo.get('etape'), mo.get('etape'))} »", self.KO | curses.A_BOLD)
                self.lignes(str(mo.get("erreur", "")), 10)
                self.texte(17, 2, "Entrée : revenir à l'assistant", self.CY)
                self.e.refresh()
                self.e.get_wch()
                return False
            n, t = mo.get("n", 0), mo.get("total", 1) or 1
            self.texte(8, 2, str(mo.get("action", "Démarrage…")))
            plein = int((L - 6) * n / t)
            self.texte(10, 2, "█" * plein + "░" * (L - 6 - plein), self.CY)
            self.texte(12, 2, "Ne l'éteignez pas : plusieurs minutes possibles.", self.GR)
            self.e.refresh()
            time.sleep(1.5)


def code_affiche() -> str:
    """Le code d'appairage, groupé par 4 (espaces : la box maîtresse les ignore)."""
    try:
        c = R.M.JETON.read_text().strip()
    except OSError:
        return "(pas encore prêt)"
    return " ".join(c[i:i + 4] for i in range(0, len(c), 4))


def _traite_distant(c: "Console", action: str) -> Optional[bool]:
    """Proposition ou application imposée : rend True si la box est prête,
    False pour revenir à l'assistant, None si rien à faire."""
    if action == "__force__":
        return c.suivi()
    if action == "__proposition__":
        choix = c.proposition(R.proposition())
        try:
            if choix == "accepter":
                R.accepte()
                return c.suivi()
            R.refuse()
        except R.Refus as e:
            c.msg = str(e)
        return False
    return None


def lance(ecran) -> int:
    c = Console(ecran)
    etat = R.etat()
    if etat["fait"]:
        return 0
    if etat["demande_en_cours"] or (etat.get("moteur") or {}).get("phase") == "application":
        if c.suivi():
            return 0
    ps = pages(R.lit() and R.vue(R.lit()))
    ids = [p.id for p in ps] + ["appliquer"]
    vide = not R.lit()
    cur = 0 if vide else max(0, ids.index(etat["reprendre"]) if etat["reprendre"] in ids else 0)
    motif = None
    while True:
        if cur >= len(ps):
            action = c.recap(R.etat())
            fin = _traite_distant(c, action)
            if fin:
                return 0
            if fin is False:
                cur = 0
                continue
            if action == "quitter":
                return 1
            if action == "precedent":
                cur -= 1
                continue
            try:
                R.demande_appliquer()
            except R.Refus as e:
                c.msg = str(e)
                continue
            if c.suivi():
                return 0
            etat = R.etat()
            cur = ids.index((etat.get("moteur") or {}).get("etape", "nom")) if (etat.get("moteur") or {}).get("etape") in ids else 0
            continue
        page = ps[cur]
        action = c.boucle_page(page, cur + 1, len(ids), motif)
        motif = None
        fin = _traite_distant(c, action)
        if fin:
            return 0
        if fin is False:
            ps = pages(R.vue(R.lit()))            # le maître a pu tout remplir
            cur = 0
            continue
        if action == "quitter":
            return 1
        if action == "precedent":
            cur = max(0, cur - 1)
            continue
        if page.id == "admin" and not valeurs_de(page)["mot_de_passe"] \
                and (R.vue(R.lit()).get("admin") or {}).get("mot_de_passe") == "défini":
            cur += 1                                   # déjà choisi, on garde
            continue
        try:
            e = R.enregistre(page.id, page.valeurs(valeurs_de(page)))
        except R.Refus as err:
            motif = str(err)
            continue
        st = next(x for x in e["etapes"] if x["id"] == page.id)
        if st["statut"] == "erreur":
            motif = st["motif"]
            continue
        for ch in page.champs:
            if ch.genre == "secret":
                ch.valeur = ""                         # rien ne traîne en mémoire d'écran
        cur += 1


def main() -> int:
    import os
    # Échap = « Retour » : un délai court, mais assez pour que curses assemble
    # les séquences des flèches avant de conclure à un Échap seul — sinon la
    # queue « [C » d'une flèche finissait tapée dans un champ.
    os.environ.setdefault("ESCDELAY", "150")
    locale.setlocale(locale.LC_ALL, "")
    return curses.wrapper(lance)
