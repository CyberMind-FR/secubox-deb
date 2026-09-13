# Dépannage AMD64 — GK2 Clone

Ce guide couvre les incidents de démarrage et d’accès les plus courants sur une SecuBox-DEB AMD64. Exécutez les diagnostics dans l’ordre et conservez les journaux avant toute réinitialisation.

## Table des matières

- [1. HTTPS inaccessible](#1-https-inaccessible)
- [2. La VM ne démarre pas](#2-la-vm-ne-démarre-pas)
- [3. Boucle EFI](#3-boucle-efi)
- [4. Ports VirtualBox occupés](#4-ports-virtualbox-occupés)
- [5. Certificat auto-signé](#5-certificat-auto-signé)
- [6. Réinitialisation admin](#6-réinitialisation-admin)

## 1. HTTPS inaccessible

En VirtualBox NAT, vérifiez d’abord que la VM est en cours d’exécution et que la redirection HTTPS existe :

```bash
VBoxManage showvminfo "GK2-Clone" --details | rg 'NIC 1|Rule'
curl -kIv https://localhost:9443/
```

Dans la console de l’invité, vérifiez l’adresse, le frontal et les journaux :

```bash
hostname -I
systemctl status nginx haproxy --no-pager
journalctl -u nginx -u haproxy --since "-15 min" --no-pager
sudo nginx -t
```

Un `curl -k` ne vérifie pas la confiance du certificat : il sert seulement à isoler une panne réseau ou HTTP pendant le diagnostic. Une fois le service rétabli, traitez le certificat comme indiqué dans [Premier démarrage](FIRST-BOOT.md).

## 2. La VM ne démarre pas

Contrôlez que VirtualBox voit la VM et que la virtualisation matérielle est disponible sur l’hôte :

```bash
VBoxManage list vms
VBoxManage showvminfo "GK2-Clone"
VBoxManage startvm "GK2-Clone" --type gui
```

Si VirtualBox signale VT-x/AMD-V indisponible, activez la virtualisation dans l’UEFI de l’hôte. Sous Linux, un autre hyperviseur ou une politique de sécurité peut réserver l’accélération. Arrêtez les VMs concurrentes et vérifiez la configuration de l’hyperviseur plutôt que de désactiver les protections de l’hôte.

Si le disque VDI a été déplacé ou recréé, regénérez la VM avec le script canonique. N’éditez pas manuellement le registre des médias VirtualBox : le script retire les inscriptions périmées avant d’attacher le disque.

```bash
bash image/create-vbox-vm.sh --download --name GK2-Clone --force
```

> **Warning**
>
> `--force` supprime la VM VirtualBox du même nom. Sauvegardez ou exportez tout état utile avant de l’utiliser.

## 3. Boucle EFI

La VM officielle utilise `efi64`. Dans les réglages VirtualBox, vérifiez : système d’exploitation Debian 64 bits, EFI activé, contrôleur SATA et disque VDI attaché au port 0. Depuis le terminal :

```bash
VBoxManage showvminfo "GK2-Clone" --details | rg 'Firmware|Storage|SATA'
```

Une boucle EFI est généralement causée par une image ARM64, un disque absent ou un firmware non compatible. Recréez la VM depuis une image dont le nom contient `amd64` :

```bash
bash image/create-vbox-vm.sh output/secubox-live-amd64-bookworm.img \
  --name GK2-Clone --force
```

Sur bare metal, démarrez explicitement l’entrée UEFI de la clé/disque SecuBox et désactivez le démarrage Legacy/CSM pour l’essai. Ne réinstallez pas le chargeur de démarrage sans avoir identifié le bon disque.

## 4. Ports VirtualBox occupés

Les redirections par défaut utilisent les ports hôte `2222`, `9443` et `8080`. Identifiez le processus qui les détient :

```bash
ss -ltnp '( sport = :2222 or sport = :9443 or sport = :8080 )'
```

Créez une VM avec des ports libres :

```bash
bash image/create-vbox-vm.sh --download --name GK2-Clone \
  --ssh 22222 --https 19443 --http 18080
```

Les nouvelles adresses sont `ssh -p 22222 root@localhost`, `https://localhost:19443` et `http://localhost:18080`. Ne forcez pas l’arrêt d’un processus inconnu pour libérer un port ; identifiez son propriétaire et son rôle au préalable.

## 5. Certificat auto-signé

Un certificat auto-signé est attendu au bootstrap. Inspectez son sujet, ses dates et ses SAN :

```bash
sudo openssl x509 -in /etc/secubox/tls/cert.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

L’avertissement du navigateur disparaît seulement après l’import contrôlé d’une autorité de confiance ou le déploiement d’un certificat signé correspondant au nom utilisé. Le nom `localhost` en NAT et une adresse IP LAN ne sont pas nécessairement présents dans le certificat : préférez un nom DNS stable et émettez un certificat pour ce nom.

## 6. Réinitialisation admin

Si le compte du portail est inaccessible mais que vous avez accès à la console de la VM ou au terminal local, exécutez :

```bash
sudo secubox-passwd
```

L’outil demande un nouveau mot de passe et redémarre les services du portail. Vérifiez ensuite les journaux et reconnectez-vous par HTTPS :

```bash
journalctl -u secubox-portal -u secubox-hub --since "-10 min" --no-pager
```

Si la console elle-même n’est plus accessible, restaurez le dernier snapshot validé depuis l’hyperviseur ou, si disponible, depuis `secubox-snapshot`. Une restauration remplace la configuration et les données courantes : préservez les éléments nécessaires avant l’opération.
