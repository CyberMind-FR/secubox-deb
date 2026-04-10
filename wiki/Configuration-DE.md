# SecuBox Konfiguration

[English](Configuration) | [Français](Configuration-FR) | [中文](Configuration-ZH)

## Konfigurationsdateien

SecuBox verwendet TOML-Konfigurationsdateien in `/etc/secubox/`.

### Hauptkonfiguration

```
/etc/secubox/
├── secubox.toml          # Hauptkonfiguration
├── modules/              # Pro-Modul-Konfigurationen
│   ├── crowdsec.toml
│   ├── wireguard.toml
│   ├── dpi.toml
│   └── ...
├── tls/                  # TLS-Zertifikate
│   ├── cert.pem
│   └── key.pem
└── secrets/              # Sensible Daten (chmod 600)
    └── jwt.key
```

### secubox.toml

```toml
[general]
hostname = "secubox"
timezone = "Europe/Berlin"
locale = "de_DE.UTF-8"

[network]
wan_interface = "eth0"
lan_interfaces = ["lan0", "lan1"]
bridge_name = "br-lan"
lan_ip = "192.168.1.1"
lan_netmask = "255.255.255.0"
dhcp_enabled = true
dhcp_range_start = "192.168.1.100"
dhcp_range_end = "192.168.1.200"

[security]
firewall_enabled = true
default_policy = "drop"
crowdsec_enabled = true
waf_enabled = true

[services]
nginx_enabled = true
haproxy_enabled = true
ssh_enabled = true
ssh_port = 22
```

## Modul-Konfiguration

Jedes Modul hat seine eigene Konfigurationsdatei in `/etc/secubox/modules/`.

### Beispiel: CrowdSec

```toml
# /etc/secubox/modules/crowdsec.toml
[crowdsec]
enabled = true
api_url = "http://127.0.0.1:8080"
log_level = "info"

[bouncers]
firewall = true
nginx = true

[scenarios]
ssh_bruteforce = true
http_bad_user_agent = true
```

### Beispiel: WireGuard

```toml
# /etc/secubox/modules/wireguard.toml
[wireguard]
enabled = true
interface = "wg0"
listen_port = 51820
private_key_file = "/etc/secubox/secrets/wg_private.key"

[peers]
# Peers werden über API verwaltet
```

## Umgebungsvariablen

Einige Einstellungen können über Umgebungsvariablen überschrieben werden:

```bash
SECUBOX_DEBUG=1              # Debug-Modus aktivieren
SECUBOX_LOG_LEVEL=debug      # Log-Level setzen
SECUBOX_CONFIG=/pfad/zu/cfg  # Benutzerdefinierter Konfigurationspfad
```

## Änderungen anwenden

Nach Änderung der Konfiguration:

```bash
# Konfiguration validieren
secubox-config validate

# Änderungen anwenden
secubox-config apply

# Oder spezifisches Modul neustarten
systemctl restart secubox-<modul>
```

## Double-Buffer-System (CSPN)

Für sicherheitskritische Änderungen verwendet SecuBox ein Double-Buffer-System:

```
/etc/secubox/
├── active/     # Aktuelle Live-Konfiguration (nur lesen)
├── shadow/     # Ausstehende Änderungen (bearbeitbar)
└── rollback/   # 4 vorherige Versionen (R1-R4)
```

### Arbeitsablauf

1. In `shadow/` bearbeiten
2. Validieren: `secubox-config validate --shadow`
3. Wechseln: `secubox-config swap`
4. Bei Bedarf zurücksetzen: `secubox-config rollback R1`

## Siehe auch

- [[Installation]] — Ersteinrichtung
- [[API-Reference]] — REST API-Dokumentation
- [[MODULES-DE|Module]] — Verfügbare Module
- [[Troubleshooting]] — Häufige Probleme
