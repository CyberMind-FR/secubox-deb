# SecuBox Depannage

[English](Troubleshooting) | [中文](Troubleshooting-ZH)

## Diagnostics rapides

```bash
# Etat du systeme
secubox-status

# Verifier tous les services
systemctl status secubox-* --no-pager

# Voir les logs
journalctl -u secubox-* -f

# Diagnostics reseau
secubox-netdiag
```

## Problemes courants

### Impossible d'acceder a l'interface Web

**Symptomes :** Le navigateur affiche une erreur de connexion refusee ou un delai d'expiration

**Solutions :**

1. Verifier que nginx fonctionne :
   ```bash
   systemctl status nginx
   systemctl restart nginx
   ```

2. Verifier le pare-feu :
   ```bash
   nft list ruleset | grep 443
   ```

3. Verifier l'adresse IP :
   ```bash
   ip addr show br-lan
   ```

4. Verifier le certificat :
   ```bash
   openssl x509 -in /etc/secubox/tls/cert.pem -text -noout
   ```

### Connexion SSH refusee

**Solutions :**

1. Verifier le service SSH :
   ```bash
   systemctl status sshd
   ```

2. Verifier que le pare-feu autorise SSH :
   ```bash
   nft list ruleset | grep 22
   ```

3. Verifier le port d'ecoute :
   ```bash
   ss -tlnp | grep ssh
   ```

### Pas d'Internet sur les clients LAN

**Solutions :**

1. Verifier que le NAT est active :
   ```bash
   nft list table inet nat
   ```

2. Verifier la redirection IP :
   ```bash
   sysctl net.ipv4.ip_forward
   ```

3. Verifier le serveur DHCP :
   ```bash
   systemctl status dnsmasq
   ```

4. Verifier que l'interface WAN a une IP :
   ```bash
   ip addr show eth0
   ```

### CrowdSec ne bloque pas

**Solutions :**

1. Verifier que CrowdSec fonctionne :
   ```bash
   systemctl status crowdsec
   cscli metrics
   ```

2. Verifier les bouncers :
   ```bash
   cscli bouncers list
   ```

3. Verifier les decisions :
   ```bash
   cscli decisions list
   ```

### WireGuard ne se connecte pas

**Solutions :**

1. Verifier que l'interface est active :
   ```bash
   wg show
   ```

2. Verifier que le port est ouvert :
   ```bash
   ss -ulnp | grep 51820
   nft list ruleset | grep 51820
   ```

3. Verifier que les cles sont configurees :
   ```bash
   cat /etc/wireguard/wg0.conf
   ```

### Utilisation elevee du CPU/memoire

**Solutions :**

1. Verifier ce qui utilise les ressources :
   ```bash
   htop
   # ou
   secubox-glances
   ```

2. Verifier les processus bloques :
   ```bash
   ps aux --sort=-%cpu | head -10
   ```

3. Sur ESPRESSObin (RAM limitee) :
   ```bash
   # Activer le swap si ce n'est pas deja fait
   swapon --show
   free -h
   ```

## Emplacement des logs

| Service | Emplacement des logs |
|---------|---------------------|
| Systeme | `journalctl` |
| Nginx | `/var/log/nginx/` |
| HAProxy | `/var/log/haproxy.log` |
| CrowdSec | `cscli metrics` / `journalctl -u crowdsec` |
| Modules SecuBox | `journalctl -u secubox-*` |
| Audit | `/var/log/secubox/audit.log` |

## Mode de recuperation

### Via console serie (ARM)

1. Connecter la console serie (115200 8N1)
2. Demarrer et interrompre U-Boot
3. Demarrer en mode mono-utilisateur :
   ```
   => setenv bootargs "root=LABEL=rootfs single"
   => boot
   ```

### Via GRUB (x86)

1. Au menu GRUB, appuyer sur `e`
2. Ajouter `single` a la ligne du noyau
3. Appuyer sur F10 pour demarrer

### Reinitialisation aux parametres d'usine

```bash
# ATTENTION : Ceci reinitialise toute la configuration !
secubox-factory-reset

# Ou manuellement :
rm -rf /etc/secubox/modules/*
cp /usr/share/secubox/defaults/* /etc/secubox/
systemctl restart secubox-*
```

## Debogage reseau

### Capturer le trafic

```bash
# Sur l'interface WAN
tcpdump -i eth0 -w /tmp/wan.pcap

# Sur le pont LAN
tcpdump -i br-lan -w /tmp/lan.pcap
```

### Verifier le routage

```bash
ip route show
ip rule show
```

### Problemes DNS

```bash
# Verifier la resolution DNS
dig @127.0.0.1 google.com

# Verifier dnsmasq
systemctl status dnsmasq
cat /etc/resolv.conf
```

## Obtenir de l'aide

1. Verifier les logs : `journalctl -xe`
2. Consulter le wiki : [[Modules]] pour l'aide specifique aux modules
3. GitHub Issues : [Signaler un bug](https://github.com/CyberMind-FR/secubox-deb/issues)

## Voir aussi

- [[Configuration-FR]] — Reference de configuration
- [[Installation-FR]] — Guide d'installation
- [[ARM-Installation-FR]] — Problemes specifiques ARM
- [[ESPRESSObin-FR]] — Guide specifique ESPRESSObin
