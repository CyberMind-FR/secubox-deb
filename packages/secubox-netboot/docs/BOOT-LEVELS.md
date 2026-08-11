# Niveaux de boot remote (#737) — sourcer × valider

Le boot remote est gradué comme les niveaux R0–R4 : chaque niveau définit **où**
U-Boot va chercher le boot (la *source*) et **comment** il en garantit l'intégrité
(la *validation*). Le profil d'une board fixe son niveau.

| Niveau | Source | Validation | Quand |
|--------|--------|------------|-------|
| **B0 — Local** | eMMC/SD locale (amorce usine) | — (rien sur le réseau) | serveur (gk2) **untouched** ; défaut sûr |
| **B1 — TFTP brut** | TFTP serveur | aucune (réseau de confiance) | *chain-proof* / banc série, LAN fermé |
| **B2 — HTTP signé** | HTTP serveur `boot.fit` | **signature FIT** (vérifiée par `bootm`) | **prod réseau** : intègre même en HTTP simple |
| **B3 — Install signé** | B2 + image release | FIT + **signature image détachée** | provisioning : DL image → vérif → écrit eMMC → reboot |
| (B4) | A/B + verified boot TF-A | chaîne de confiance complète | P3/P4 |

## Doctrine
- **B0 = par défaut** : tant qu'un profil n'a pas opt-in un niveau réseau, la board
  reste en boot local — un serveur (gk2) qui ne fait que *servir* reste B0/untouched.
- **B2 = cible prod** : HTTP simple acceptable car l'intégrité vient de la
  **signature FIT**, pas du transport (cf. `boot.gk2.secubox.in`, vhost hors WAF).
- **B1 = test seulement** : pas de signature → réservé au banc / LAN de confiance.
- **B3 = provisioning** : ajoute la vérif de la **signature détachée de l'image**
  release dans l'installeur initrd avant écriture eMMC (anti supply-chain).

## Mapping niveau → artefacts à publier (par board)
| Niveau | Publié sous `/srv/secubox/netboot/{tftp,http}/<id>/` |
|--------|------------------------------------------------------|
| B0 | (rien — pas de source réseau) |
| B1 | TFTP : `Image`, `board.dtb`, `initrd.img` |
| B2 | HTTP : `boot.fit` (kernel+dtb+initrd, **signé**) + repli TFTP |
| B3 | B2 + image release signée (`secubox-<ver>.img` + `.sig`) servie à l'installeur |

## « Sourcer et valider » côté DUT (overlay `sbx-boot.cmd`)
1. **Sourcer** : `dhcp` → `sbx_srv` (profil ou serverip) ; `sbx_id` = MAC.
2. **Valider** :
   - B2/B3 : `wget …/boot.fit` → `bootm` **vérifie la signature** (clé publique
     embarquée dans l'overlay U-Boot) → refus si invalide → repli/halte.
   - B1 : `tftpboot` brut → `booti` (aucune vérif — niveau test).
3. **Anti-brick** : tout échec retombe sur `factory_bootcmd` (bootcount/altbootcmd).

## Validation côté serveur (publish)
`secubox-netboot-publish` refuse de publier un `boot.fit` non signé pour un profil
B2/B3 (cohérence niveau ↔ artefact). Le niveau est porté par le profil board.
