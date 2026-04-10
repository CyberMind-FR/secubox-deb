# SecuBox Fehlerbehebung

[English](Troubleshooting) | [Français](Troubleshooting-FR) | [中文](Troubleshooting-ZH)

## Schnelldiagnose

```bash
# Systemstatus
secubox-status

# Alle Dienste prüfen
systemctl status secubox-* --no-pager

# Logs anzeigen
journalctl -u secubox-* -f

# Netzwerkdiagnose
secubox-netdiag
```

## Häufige Probleme

### Web UI nicht erreichbar

**Symptome:** Browser zeigt Verbindung abgelehnt oder Timeout

**Lösungen:**

1. Prüfen ob nginx läuft:
   ```bash
   systemctl status nginx
   systemctl restart nginx
   ```

2. Firewall prüfen:
   ```bash
   nft list ruleset | grep 443
   ```

3. IP-Adresse verifizieren:
   ```bash
   ip addr show br-lan
   ```

4. Zertifikat prüfen:
   ```bash
   openssl x509 -in /etc/secubox/tls/cert.pem -text -noout
   ```

### SSH-Verbindung abgelehnt

**Lösungen:**

1. SSH-Dienst prüfen:
   ```bash
   systemctl status sshd
   ```

2. Firewall erlaubt SSH:
   ```bash
   nft list ruleset | grep 22
   ```

3. Listening-Port verifizieren:
   ```bash
   ss -tlnp | grep ssh
   ```

### Kein Internet für LAN-Clients

**Lösungen:**

1. NAT aktiviert prüfen:
   ```bash
   nft list table inet nat
   ```

2. IP-Forwarding prüfen:
   ```bash
   sysctl net.ipv4.ip_forward
   ```

3. DHCP-Server prüfen:
   ```bash
   systemctl status dnsmasq
   ```

4. WAN-Interface hat IP:
   ```bash
   ip addr show eth0
   ```

### CrowdSec blockiert nicht

**Lösungen:**

1. CrowdSec läuft prüfen:
   ```bash
   systemctl status crowdsec
   cscli metrics
   ```

2. Bouncers prüfen:
   ```bash
   cscli bouncers list
   ```

3. Entscheidungen prüfen:
   ```bash
   cscli decisions list
   ```

### WireGuard verbindet nicht

**Lösungen:**

1. Interface ist aktiv:
   ```bash
   wg show
   ```

2. Port ist offen:
   ```bash
   ss -ulnp | grep 51820
   nft list ruleset | grep 51820
   ```

3. Schlüssel konfiguriert:
   ```bash
   cat /etc/wireguard/wg0.conf
   ```

### Hohe CPU/Speicherauslastung

**Lösungen:**

1. Ressourcenverbrauch prüfen:
   ```bash
   htop
   # oder
   secubox-glances
   ```

2. Blockierte Prozesse suchen:
   ```bash
   ps aux --sort=-%cpu | head -10
   ```

3. Auf ESPRESSObin (wenig RAM):
   ```bash
   # Swap aktivieren falls nicht bereits
   swapon --show
   free -h
   ```

## Log-Speicherorte

| Dienst | Log-Speicherort |
|--------|-----------------|
| System | `journalctl` |
| Nginx | `/var/log/nginx/` |
| HAProxy | `/var/log/haproxy.log` |
| CrowdSec | `cscli metrics` / `journalctl -u crowdsec` |
| SecuBox Module | `journalctl -u secubox-*` |
| Audit | `/var/log/secubox/audit.log` |

## Wiederherstellungsmodus

### Über serielle Konsole (ARM)

1. Serielle Konsole verbinden (115200 8N1)
2. Booten und U-Boot unterbrechen
3. In Single-User-Modus booten:
   ```
   => setenv bootargs "root=LABEL=rootfs single"
   => boot
   ```

### Über GRUB (x86)

1. Im GRUB-Menü `e` drücken
2. `single` zur Kernel-Zeile hinzufügen
3. F10 zum Booten drücken

### Auf Werkseinstellungen zurücksetzen

```bash
# WARNUNG: Dies setzt alle Konfigurationen zurück!
secubox-factory-reset

# Oder manuell:
rm -rf /etc/secubox/modules/*
cp /usr/share/secubox/defaults/* /etc/secubox/
systemctl restart secubox-*
```

## Netzwerk-Debugging

### Datenverkehr aufzeichnen

```bash
# Auf WAN-Interface
tcpdump -i eth0 -w /tmp/wan.pcap

# Auf LAN-Bridge
tcpdump -i br-lan -w /tmp/lan.pcap
```

### Routing prüfen

```bash
ip route show
ip rule show
```

### DNS-Probleme

```bash
# DNS-Auflösung prüfen
dig @127.0.0.1 google.com

# dnsmasq prüfen
systemctl status dnsmasq
cat /etc/resolv.conf
```

## Hilfe erhalten

1. Logs prüfen: `journalctl -xe`
2. Wiki prüfen: [[MODULES-DE|Module]] für modulspezifische Hilfe
3. GitHub Issues: [Fehler melden](https://github.com/CyberMind-FR/secubox-deb/issues)

## Siehe auch

- [[Configuration]] — Konfigurationsreferenz
- [[Installation]] — Installationsanleitung
- [[ARM-Installation]] — ARM-spezifische Probleme
- [[ESPRESSObin]] — ESPRESSObin-spezifische Anleitung
