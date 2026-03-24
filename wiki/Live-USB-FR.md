# Guide Live USB

[English](Live-USB) | [中文](Live-USB-ZH)

Demarrez SecuBox directement depuis une cle USB avec tous les paquets pre-installes.

## Telechargement

**Derniere version :** [secubox-live-amd64-bookworm.img.gz](https://github.com/CyberMind-FR/secubox-deb/releases/latest)

## Fonctionnalites

| Fonctionnalite | Description |
|----------------|-------------|
| Demarrage UEFI | Chargeur GRUB moderne |
| SquashFS | Racine compressee (~250Mo) |
| Persistance | Sauvegarde des modifications entre redemarrages |
| Slipstream | Plus de 30 paquets SecuBox inclus |

## Flasher sur USB

### Linux / macOS

```bash
# Trouver votre peripherique USB
lsblk

# Flasher (remplacez /dev/sdX par votre peripherique !)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### Windows

1. Telechargez [Rufus](https://rufus.ie/) ou [balenaEtcher](https://etcher.balena.io/)
2. Extrayez le fichier `.img.gz` pour obtenir `.img`
3. Selectionnez le fichier `.img`
4. Selectionnez votre cle USB
5. Cliquez sur Ecrire/Flasher

## Options du Menu de Demarrage

| Option | Description |
|--------|-------------|
| **SecuBox Live** | Demarrage normal avec persistance |
| **Mode Sans Echec** | Pilotes minimaux pour depannage |
| **Sans Persistance** | Demarrage vierge, modifications non sauvegardees |
| **En RAM** | Charger tout le systeme en memoire |

## Identifiants par Defaut

| Service | Utilisateur | Mot de passe |
|---------|-------------|--------------|
| Interface Web | admin | admin |
| SSH | root | secubox |
| SSH | secubox | secubox |

**Important :** Changez les mots de passe apres le premier demarrage !

## Acces Reseau

Apres le demarrage :

1. Trouver l'IP : `ip addr` ou verifier les baux DHCP du routeur
2. Interface Web : `https://<IP>:8443`
3. SSH : `ssh root@<IP>`

Configuration reseau par defaut :
- Client DHCP sur toutes les interfaces
- Repli : 192.168.1.1/24

## Persistance

Modifications sauvegardees automatiquement :
- `/home/*` - Fichiers utilisateur
- `/etc/*` - Configuration
- `/var/log/*` - Journaux
- Paquets installes

### Reinitialiser la Persistance

```bash
# Demarrer avec "Sans Persistance", puis :
sudo mkfs.ext4 -L persistence /dev/sdX3
```

## Schema des Partitions

| Partition | Taille | Type | Fonction |
|-----------|--------|------|----------|
| p1 | 512Mo | EFI | Chargeur GRUB |
| p2 | 2Go | FAT32 | Systeme live (SquashFS) |
| p3 | Restant | ext4 | Persistance |

## Verification

```bash
# Telecharger les checksums
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/SHA256SUMS

# Verifier
sha256sum -c SHA256SUMS --ignore-missing
```

## Depannage

### USB Ne Demarre Pas

1. Entrer dans BIOS/UEFI (F2, F12, Suppr, Echap)
2. Activer le demarrage USB
3. Desactiver Secure Boot
4. Definir USB comme premier peripherique de demarrage

### Ecran Noir

1. Essayer "Mode Sans Echec" dans le menu
2. Ajouter `nomodeset` aux parametres du noyau :
   - Appuyer sur `e` dans GRUB
   - Ajouter `nomodeset` a la ligne `linux`
   - Appuyer sur Ctrl+X

### Pas de Reseau

```bash
ip link show
sudo systemctl restart networking
sudo dhclient eth0
```

## Compilation depuis les Sources

```bash
git clone https://github.com/CyberMind-FR/secubox-deb
cd secubox-deb
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

## Voir Aussi

- [[Installation-FR]] - Installation permanente
- [[Configuration-FR]] - Configuration systeme
- [[Troubleshooting-FR]] - Plus de solutions
