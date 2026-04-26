# 👁️ Eye Remote — Addon

**SecuBox Eye Remote** — Addon de monitoring USB gadget pour SecuBox OS.

> **Note:** Eye Remote est un **addon optionnel** pour SecuBox OS.
> Il n'est pas nécessaire pour utiliser SecuBox OS, mais offre un affichage
> déporté pratique pour le monitoring et le débogage.

**Hardware:** Raspberry Pi Zero W + HyperPixel 2.1 Round (480×480)

---

## Pour qui ?

| Cas d'usage | Description |
|-------------|-------------|
| **Datacenter** | Monitoring visuel sans écran sur appliance |
| **Debug terrain** | Console série + affichage status |
| **Démonstration** | Dashboard compact pour salons/présentations |
| **Récupération** | Boot USB de secours via mass storage |

---

## Documentation

| Page | Description |
|------|-------------|
| [[Eye-Remote-Hardware]] | Configuration matérielle, GPIO, display |
| [[Eye-Remote-Implementation]] | Architecture logicielle, agent, renderer |
| [[Eye-Remote-Bootstrap]] | Boot device, slots A/B, mass storage |
| [[Eye-Remote-Gateway]] | Émulateur gateway pour tests |

---

## Features

### Dashboard circulaire
- Affichage framebuffer 480×480 rond
- 6 anneaux de status (AUTH, WALL, BOOT, MIND, ROOT, MESH)
- Métriques temps réel SecuBox
- Navigation tactile

### Connexion USB OTG
- **CDC-ECM** : réseau 10.55.0.2 ↔ 10.55.0.1
- **CDC-ACM** : console série
- **Mass Storage** : images de boot

### Boot Device (optionnel)
- Slots A/B pour boot media
- Swap atomique pour mises à jour sécurisées
- Rollback 4 niveaux (R1-R4)
- Serveur TFTP netboot

---

## Schéma de connexion

```
┌─────────────────┐     USB OTG      ┌─────────────────┐
│   Eye Remote    │◄────────────────►│   SecuBox OS    │
│  Pi Zero W      │   10.55.0.0/30   │   Appliance     │
│  HyperPixel 2.1 │                  │                 │
└─────────────────┘                  └─────────────────┘
       │                                     │
       │ Display                             │ LAN/WAN
       ▼                                     ▼
  ┌─────────┐                          ┌─────────┐
  │ 480×480 │                          │ Network │
  │ Round   │                          │ Clients │
  └─────────┘                          └─────────┘
```

---

## Build & Deploy

```bash
# Prérequis: SecuBox OS déjà déployé sur l'appliance cible

# Build image Eye Remote
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz

# Flasher sur carte SD
sudo dd if=eye-remote.img of=/dev/sdX bs=4M status=progress

# Brancher le Pi Zero W sur le port USB de l'appliance SecuBox
# (port DATA, pas PWR)
```

---

## Palette de couleurs

| Module | Couleur | Hex |
|--------|---------|-----|
| AUTH | Orange | #C04E24 |
| WALL | Jaune-brun | #9A6010 |
| BOOT | Rouge-brun | #803018 |
| MIND | Violet | #3D35A0 |
| ROOT | Vert | #0A5840 |
| MESH | Bleu | #104A88 |

Voir [[eye-remote-icons]] pour la référence des icônes.

---

## Traductions

- [[Eye-Remote-Bootstrap-FR|Français]]
- [[Eye-Remote-Bootstrap-ZH|中文]]

---

*← Retour à [[Home|SecuBox OS]]*
