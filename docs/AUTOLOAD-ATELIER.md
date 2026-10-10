<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Auto-Load — préparer une image qui se provisionne seule (phase A)

Cadrage : `docs/dossiers/provisionnement-auto-load.md` (#2182). Ce guide est la procédure d'atelier de la **phase A** : une image SecuBox ordinaire, préparée avant d'être livrée, qui au
premier démarrage appelle l'infrastructure et s'installe toute seule. (Le démarrage réseau sans préparation, phase B, n'est pas livré.)

## Ce qui se passe, de bout en bout

```
atelier ─ autoload-atelier preparer ─►  /boot/secubox/autoload/{reponses.toml, reponses.toml.sig, jeton}
client  ─ branche la box ─────────────►  secubox-autoload-agent.service (premier démarrage, si les 3 conditions sont réunies)
                                          1. installe le jeton (0600, root) et l'EFFACE de /boot
                                          2. vérifie la signature du fichier contre le trousseau « SecuBox Provisioning »
                                          3. génère la clé WireGuard SUR la box, s'enrôle (jeton à usage unique), monte le tunnel sortant
                                          4. établit le plan, publie un pré-rapport signé, attend le délai de grâce (15 min par défaut)
                                          5. installe le profil, applique réseau et comptes, écrit le rapport final (écran + courrier au client)
```

L'unité ne démarre **que** si `/boot/secubox/autoload/reponses.toml` existe, si `/usr/share/secubox/autoload/provisioning.gpg` est installé et si aucun rapport n'existe déjà. Une box
ordinaire n'est donc jamais touchée. Le fichier doit porter une signature valide de la clé « SecuBox Provisioning » ; modifié d'un octet, ou signé par une autre clé, il est refusé et rien
n'est installé.

## Procédure d'atelier

1. **Émettre le jeton** (sur l'infrastructure, `admin.gk2.secubox.in`) : `autoloadctl emettre --client C --profil lite --lot lot-2026-10`. Il s'affiche **une seule fois**.
2. **Écrire le fichier de réponses** à partir de `/usr/share/doc/secubox-premier-pas/examples/reponses-autoload.toml`. Garder `jeton = "ref:/etc/secubox/secrets/autoload-jeton"` : c'est le seul
   fichier que l'agent installe depuis `/boot`. `mode = "auto"` exige un profil complet (aucun écran pour demander ce qui manque) ; `mode = "one-shot"` attend la confirmation d'un opérateur.
3. **Flasher l'image** de la release, puis monter sa partition de démarrage (celle qui sera `/boot`).
4. **Préparer** : `printf '%s' "$JETON" | autoload-atelier preparer --reponses reponses.toml --boot /mnt/boot --homedir /etc/secubox/secrets/provisioning-gnupg --jeton-stdin`.
   L'outil valide le fichier comme la box le fera, le signe, **vérifie la signature contre le trousseau livré avec l'image**, et n'écrit rien tant que l'un des trois échoue.
5. **Contrôler** : `autoload-atelier verifier --boot /mnt/boot` (réponses valides, signature acceptée, jeton présent).
6. Démonter, livrer. Au premier démarrage, suivre avec `autoload-agentctl etat` ; le rapport final : `autoload-agentctl rapport`.

## La clé « SecuBox Provisioning »

- Créée **une fois**, sur l'infrastructure : `autoload-atelier cle-init --homedir /etc/secubox/secrets/provisioning-gnupg --export provisioning.gpg` (Ed25519, sans échéance). La partie
  privée reste dans ce dossier (0700, root) ; **elle ne quitte jamais l'atelier**. La partie publique est livrée par `secubox-autoload-agent` (`/usr/share/secubox/autoload/provisioning.gpg`).
- État actuel (2026-10-11) : la clé est tenue sur gk2 **sans phrase de passe**, protégée par les droits du système de fichiers seulement. La tenir comme la clé du dépôt apt (phrase
  aléatoire gérée par systemd-creds, niveau 0, #1366) est une décision du propriétaire en attente (point 5 du dossier) ; la clé du dépôt apt et celle-ci restent distinctes.
- Rotation : générer une nouvelle clé, publier un paquet dont le trousseau contient **les deux** publiques, re-signer les fichiers des lots à venir, puis retirer l'ancienne.
- Une clé privée perdue ou compromise : révoquer les jetons non réclamés (`autoloadctl revoquer --lot …`) et publier un trousseau sans elle.

## Sécurité, en bref

- Aucun secret dans le fichier de réponses (mot de passe = empreinte argon2, jeton = référence). Le jeton est à usage unique, lié à la clé WireGuard de la box à la réclamation, et effacé de `/boot`
  dès le premier démarrage (au mieux sur FAT ; c'est l'usage unique qui protège).
- Aucun port entrant : le tunnel est sortant, vers `admin.gk2.secubox.in`. Validation : pré-rapport signé, délai de grâce, refus possible avant application, rollback 4R après.
- Une box clonée n'hérite d'aucune identité : la clé WireGuard est générée sur la box, jamais dans l'image.

## Limites connues

- Phase B (netboot HTTP signé) non livrée : l'U-Boot d'usine du MOCHAbin n'a pas `wget` (dossier, D3). Essai ESPRESSObin : #2177.
- Les images de la release portent l'agent (profil `lite`, donc `isp` et `full`) mais **aucun fichier de réponses** : c'est l'atelier qui le dépose, par client.
- Le courrier du rapport final dépend de la configuration SMTP de l'infrastructure.
