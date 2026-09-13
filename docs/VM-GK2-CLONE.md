# VM GK2 Clone — VirtualBox, KVM et QEMU

Ce guide décrit les topologies de virtualisation compatibles avec une SecuBox-DEB AMD64. VirtualBox est la voie automatisée officielle ; KVM et QEMU conviennent aux postes Linux et aux chaînes CI de laboratoire.

## Table des matières

- [1. Comparatif](#1-comparatif)
- [2. Réseau de référence](#2-réseau-de-référence)
- [3. VirtualBox](#3-virtualbox)
- [4. KVM/libvirt](#4-kvmlibvirt)
- [5. QEMU](#5-qemu)
- [6. Snapshots et clones](#6-snapshots-et-clones)

## 1. Comparatif

| Hyperviseur | Support | État |
|---|---|---|
| VirtualBox | AMD64, EFI x64, NAT avec redirections automatiques | Référence automatisée |
| KVM/libvirt | AMD64, Linux avec accélération KVM | Supporté en laboratoire |
| QEMU | AMD64, Linux/macOS/Windows selon accélérateur | Supporté en laboratoire |

## 2. Réseau de référence

La topologie minimale conserve la gestion sur l’hôte et limite l’exposition :

```text
Poste hôte ── NAT ── SecuBox GK2 Clone ── services internes
     │
     ├── localhost:2222  → SSH invité:22
     ├── localhost:9443  → HTTPS invité:443
     └── localhost:8080  → HTTP invité:80
```

Ajoutez un second NIC Host-Only, Internal Network ou bridge uniquement si un scénario le nécessite. Le bridge expose la machine comme un équipement du LAN : appliquez d’abord les étapes de [Premier démarrage](FIRST-BOOT.md).

## 3. VirtualBox

Le script officiel est la seule procédure à privilégier pour créer une VM VirtualBox :

```bash
bash image/create-vbox-vm.sh --download --name GK2-Clone --memory 8192 --cpus 4
```

Il configure Debian 64 bits, EFI x64, ICH9, VMSVGA, SATA et une carte VirtIO en NAT. Pour consulter sa configuration :

```bash
VBoxManage showvminfo "GK2-Clone"
```

Pour ajouter un réseau host-only de développement après la création :

```bash
VBoxManage modifyvm "GK2-Clone" --nic2 hostonly --hostonlyadapter2 vboxnet0
```

Créez d’abord `vboxnet0` dans VirtualBox si l’interface n’existe pas. Gardez la redirection NAT de gestion comme accès de secours.

## 4. KVM/libvirt

Installez les composants de virtualisation sur l’hôte Linux :

```bash
sudo apt update
sudo apt install --yes qemu-kvm libvirt-daemon-system virtinst
```

Décompressez l’image publiée et importez-la dans une VM EFI. Le chemin OVMF varie selon la distribution ; vérifiez-le avant usage.

```bash
gunzip -kf secubox-live-amd64-bookworm.img.gz
sudo virt-install \
  --name GK2-Clone \
  --memory 8192 \
  --vcpus 4 \
  --import \
  --disk path="$PWD/secubox-live-amd64-bookworm.img",format=raw,bus=virtio \
  --os-variant debian12 \
  --boot uefi \
  --network network=default,model=virtio \
  --graphics spice
```

Le réseau `default` de libvirt fournit un NAT. Déterminez l’adresse invitée avec `virsh net-dhcp-leases default` ou créez une redirection explicitement dans votre politique réseau hôte.

## 5. QEMU

Le dépôt fournit un lanceur QEMU qui définit les redirections de référence :

```bash
bash scripts/run-qemu.sh --help
bash scripts/run-qemu.sh secubox-live-amd64-bookworm.img
```

Sur Linux avec KVM disponible, QEMU utilise l’accélération matérielle si le lanceur et l’hôte la permettent. Accédez ensuite au frontal via `https://localhost:9443` et à SSH avec `ssh -p 2222 root@localhost`.

> **Important**
>
> Ne démarrez jamais simultanément deux hyperviseurs utilisant les mêmes redirections. Modifiez les ports hôte d’une des instances avant le lancement.

## 6. Snapshots et clones

Créez le snapshot **après** le changement du mot de passe, la synchronisation de l’heure et la validation des services. Avec VirtualBox :

```bash
VBoxManage snapshot "GK2-Clone" take "gk2-baseline" \
  --description "Baseline GK2 AMD64 sécurisée"
VBoxManage snapshot "GK2-Clone" list
```

Avec libvirt, utilisez un snapshot externe ou un volume QCOW2 selon la politique de stockage de l’équipe. Pour un clone durable, arrêtez la VM, clonez le disque et donnez à la nouvelle instance un hostname, des identifiants et des clés propres. Ne clonez pas des secrets de production.
