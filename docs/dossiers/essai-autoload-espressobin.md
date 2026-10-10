<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# Essai Auto-Load, phase A (image préinstallée + agent) — procédure (#2182, #2210)

Prérequis : l'image **lite** de la release alpha.11 (elle embarque `secubox-autoload-agent`), une box cliente qui démarre (voir #2177 pour l'ESPRESSObin : si elle ne démarre pas de façon stable, essayer d'abord sur une MOCHAbin ou une VM amd64), et gk2 comme infrastructure.

## Côté infrastructure (gk2)
1. Vérifier le service : `systemctl is-active secubox-autoload wg-quick@wg-autoload` ; la page `https://admin.gk2.secubox.in/autoload/` répond.
2. Émettre un jeton : depuis la page (onglet « Jetons & abonnements »), ou `autoloadctl emettre --client essai-ebin --profil lite` (la valeur `gk2_…` n'est montrée qu'une fois).
3. Écrire le fichier de réponses (modèle : `/usr/share/doc/secubox-autoload-agent/examples/reponses-autoload.toml`), puis le signer : `autoloadctl signer reponses.toml` → `reponses.toml.sig`.

## Côté box
4. Copier `reponses.toml` et `reponses.toml.sig` dans `/boot/secubox/autoload/` de la box.
5. Poser le jeton : `install -m 0600 /dev/null /etc/secubox/secrets/autoload-jeton && echo gk2_… > /etc/secubox/secrets/autoload-jeton`.
6. **Essai sur le LAN de gk2** (pas de redirection Freebox) : `echo "192.168.1.200 admin.gk2.secubox.in" >> /etc/hosts` sur la box (le certificat est celui de ce nom ; l'UDP 51830 est ouvert sur gk2).
7. Lancer : `autoload-agentctl run` (root). Mode `one-shot` : confirmer le pré-rapport affiché avec `autoload-agentctl confirmer <empreinte>` ; mode `auto` : délai de grâce de `grace_min` minutes pendant lequel la page permet de refuser.
8. Suivre : `autoload-agentctl etat`, la page (progression en %), puis `autoload-agentctl rapport` à la fin.

## Ce qui n'est pas encore automatique
Le démarrage au boot (zero-touch) demande une unité root : décision de l'exploitant. La redirection UDP 51830 de la Freebox vers gk2 est nécessaire pour une box hors du LAN. Le courrier du rapport demande `/etc/secubox/autoload.toml`.
