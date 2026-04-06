# Configuration SecuBox

[English](Configuration) | [中文](Configuration-ZH)

## Fichiers de configuration

SecuBox utilise des fichiers de configuration TOML situes dans `/etc/secubox/`.

### Configuration principale

```
/etc/secubox/
├── secubox.toml          # Configuration principale
├── modules/              # Configs par module
│   ├── crowdsec.toml
│   ├── wireguard.toml
│   ├── dpi.toml
│   └── ...
├── tls/                  # Certificats TLS
│   ├── cert.pem
│   └── key.pem
└── secrets/              # Donnees sensibles (chmod 600)
    └── jwt.key
```

### secubox.toml

```toml
[general]
hostname = "secubox"
timezone = "Europe/Paris"
locale = "en_US.UTF-8"

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

## Configuration des modules

Chaque module possede son propre fichier de configuration dans `/etc/secubox/modules/`.

### Exemple : CrowdSec

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

### Exemple : WireGuard

```toml
# /etc/secubox/modules/wireguard.toml
[wireguard]
enabled = true
interface = "wg0"
listen_port = 51820
private_key_file = "/etc/secubox/secrets/wg_private.key"

[peers]
# Les peers sont geres via l'API
```

## Variables d'environnement

Certains parametres peuvent etre surcharges via des variables d'environnement :

```bash
SECUBOX_DEBUG=1              # Activer le mode debug
SECUBOX_LOG_LEVEL=debug      # Definir le niveau de log
SECUBOX_CONFIG=/path/to/cfg  # Chemin de config personnalise
```

## Appliquer les modifications

Apres modification de la configuration :

```bash
# Valider la configuration
secubox-config validate

# Appliquer les modifications
secubox-config apply

# Ou redemarrer un module specifique
systemctl restart secubox-<module>
```

## Systeme Double-Buffer (CSPN)

Pour les modifications critiques de securite, SecuBox utilise un systeme double-buffer :

```
/etc/secubox/
├── active/     # Config live actuelle (lecture seule)
├── shadow/     # Modifications en attente (editable)
└── rollback/   # 4 versions precedentes (R1-R4)
```

### Flux de travail

1. Editer dans `shadow/`
2. Valider : `secubox-config validate --shadow`
3. Permuter : `secubox-config swap`
4. Rollback si necessaire : `secubox-config rollback R1`

## Voir aussi

- [[Installation]] — Configuration initiale
- [[API-Reference]] — Documentation de l'API REST
- [[Modules]] — Modules disponibles
- [[Troubleshooting]] — Problemes courants
