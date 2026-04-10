# API-Referenz

[English](API-Reference) | [Français](API-Reference-FR) | [中文](API-Reference-ZH)

Alle SecuBox-Module stellen REST-APIs über Unix-Sockets bereit, die von nginx unter `/api/v1/<modul>/` weitergeleitet werden.

**Gesamt: 48 Module | ~1000+ API-Endpunkte**

---

## Authentifizierung

### Anmelden

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Antwort:
```json
{
  "success": true,
  "token": "eyJ...",
  "username": "admin",
  "role": "admin"
}
```

### Token verwenden

```bash
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

---

## Allgemeine Endpunkte

Alle Module implementieren:

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | Modulstatus |
| `/health` | GET | Nein | Gesundheitsprüfung |

---

## Kern-Module

### Hub API (`/api/v1/hub/`)

Dashboard und Modulverwaltung.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Ja | Systemstatus und Modulgesundheit |
| `/modules` | GET | Ja | Alle installierten Module auflisten |
| `/alerts` | GET | Nein | Systemwarnungen |
| `/monitoring` | GET | Ja | CPU-, Speicher-, Last-Metriken |
| `/settings` | GET | Ja | Systemkonfiguration |
| `/dashboard` | GET | Nein | Vollständige Dashboard-Daten |
| `/widgets` | GET | Ja | Dashboard-Widget-Konfiguration |
| `/save_widgets` | POST | Ja | Widget-Einstellungen speichern |
| `/security_summary` | GET | Ja | Sicherheitsübersicht |
| `/network_summary` | GET | Nein | Netzwerkschnittstellen-Übersicht |
| `/quick_actions` | GET | Ja | Verfügbare Schnellaktionen |
| `/execute_action` | POST | Ja | Systemaktion ausführen |
| `/notifications` | GET | Ja | Systembenachrichtigungen |
| `/dismiss_notification` | POST | Ja | Benachrichtigung verwerfen |
| `/theme` | GET | Ja | Aktuelles UI-Theme |
| `/set_theme` | POST | Ja | UI-Theme setzen |
| `/version` | GET | Ja | SecuBox-Versionsinformation |
| `/module_control` | POST | Ja | Modul starten/stoppen/neustarten |
| `/module_status` | GET | Ja | Status eines bestimmten Moduls |
| `/module_logs` | GET | Ja | Aktuelle Logs eines Moduls |
| `/uptime` | GET | Ja | System-Betriebszeit |
| `/cpu` | GET | Ja | CPU-Statistiken |
| `/memory` | GET | Ja | Speicherstatistiken |
| `/disk` | GET | Ja | Festplattenstatistiken |
| `/network_stats` | GET | Ja | Netzwerk-I/O-Statistiken |
| `/logs` | GET | Ja | System-Journal-Logs |

### Portal API (`/api/v1/portal/`)

Authentifizierung und Sitzungsverwaltung.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | Portal-Status |
| `/login` | POST | Nein | Benutzer authentifizieren |
| `/logout` | POST | Nein | Sitzung beenden |
| `/verify` | GET | Nein | Aktuelle Sitzung verifizieren |
| `/recover` | POST | Nein | Passwort-Wiederherstellung |
| `/sessions` | GET | Ja | Aktive Sitzungen auflisten |
| `/users` | GET | Ja | Alle Benutzer auflisten (Admin) |
| `/users/create` | POST | Ja | Neuen Benutzer erstellen (Admin) |
| `/users/change-password` | POST | Ja | Passwort ändern |

### System API (`/api/v1/system/`)

Systemadministration und Diagnose.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Ja | Systemstatus-Übersicht |
| `/info` | GET | Nein | Systeminformation |
| `/resources` | GET | Nein | CPU/Speicher/Festplatten-Nutzung |
| `/services` | GET | Nein | Dienste-Liste |
| `/network` | GET | Nein | Netzwerkschnittstellen |
| `/security` | GET | Nein | Sicherheitsstatus |
| `/packages` | GET | Nein | Installierte SecuBox-Pakete |
| `/restart_services` | POST | Ja | SecuBox-Dienste neustarten |
| `/reload_firewall` | POST | Ja | nftables neu laden |
| `/sync_time` | POST | Ja | Mit NTP synchronisieren |
| `/clear_cache` | POST | Ja | System-Caches leeren |
| `/check_updates` | GET | Ja | Nach Updates suchen |
| `/apply_updates` | POST | Ja | Updates anwenden |
| `/shutdown` | POST | Ja | System herunterfahren |
| `/reboot` | POST | Ja | System neustarten |
| `/settings` | POST | Ja | Hostname/Zeitzone aktualisieren |
| `/backup` | POST | Ja | Konfigurationsbackup erstellen |
| `/restore_config` | POST | Ja | Aus Backup wiederherstellen |

---

## Sicherheits-Module

### CrowdSec API (`/api/v1/crowdsec/`)

Intrusion Detection und Prevention.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | CrowdSec-Dienststatus |
| `/metrics` | GET | Ja | Verarbeitete Ereignisse, Entscheidungen |
| `/decisions` | GET | Ja | Aktive Sperrentscheidungen |
| `/alerts` | GET | Ja | Aktuelle Sicherheitswarnungen |
| `/bouncers` | GET | Ja | Registrierte Bouncers |
| `/machines` | GET | Ja | Registrierte Maschinen |
| `/collections` | GET | Ja | Installierte Sammlungen |
| `/scenarios` | GET | Ja | Aktive Szenarien |
| `/ban` | POST | Ja | IP manuell sperren |
| `/unban` | POST | Ja | IP entsperren |

### WAF API (`/api/v1/waf/`)

Web Application Firewall.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | WAF-Status |
| `/rules` | GET | Ja | Aktive ModSecurity-Regeln |
| `/logs` | GET | Ja | Aktuelle WAF-Logs |
| `/blocked` | GET | Ja | Blockierte Anfragen |
| `/whitelist` | GET | Ja | Whitelist-Einträge |
| `/whitelist/add` | POST | Ja | Zur Whitelist hinzufügen |
| `/whitelist/remove` | POST | Ja | Von Whitelist entfernen |

### Firewall API (`/api/v1/firewall/`)

nftables-Firewall-Verwaltung.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | Firewall-Status |
| `/rules` | GET | Ja | Aktuelle nftables-Regeln |
| `/zones` | GET | Ja | Firewall-Zonen |
| `/reload` | POST | Ja | Regeln neu laden |
| `/add_rule` | POST | Ja | Regel hinzufügen |
| `/remove_rule` | POST | Ja | Regel entfernen |

---

## Netzwerk-Module

### WireGuard API (`/api/v1/wireguard/`)

VPN-Verwaltung.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | WireGuard-Status |
| `/interfaces` | GET | Ja | VPN-Schnittstellen auflisten |
| `/peers` | GET | Ja | Verbundene Peers |
| `/peer/add` | POST | Ja | Neuen Peer hinzufügen |
| `/peer/remove` | POST | Ja | Peer entfernen |
| `/generate_config` | POST | Ja | Client-Konfiguration generieren |
| `/qrcode` | GET | Ja | QR-Code für mobilen Client |

### DPI API (`/api/v1/dpi/`)

Deep Packet Inspection.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | DPI-Engine-Status |
| `/flows` | GET | Ja | Aktive Netzwerkflüsse |
| `/protocols` | GET | Ja | Erkannte Protokolle |
| `/applications` | GET | Ja | Erkannte Anwendungen |
| `/stats` | GET | Ja | Verkehrsstatistiken |
| `/top_talkers` | GET | Ja | Top-Bandbreitenverbraucher |

### QoS API (`/api/v1/qos/`)

Bandbreitenmanagement.

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|--------------|
| `/status` | GET | Nein | QoS-Status |
| `/rules` | GET | Ja | Aktive QoS-Regeln |
| `/classes` | GET | Ja | Verkehrsklassen |
| `/stats` | GET | Ja | Bandbreitenstatistiken |
| `/add_rule` | POST | Ja | QoS-Regel hinzufügen |
| `/remove_rule` | POST | Ja | Regel entfernen |

---

## Fehlerbehandlung

Alle Endpunkte geben konsistente Fehlerantworten zurück:

```json
{
  "success": false,
  "error": "Fehlermeldung",
  "code": "ERROR_CODE"
}
```

### HTTP-Statuscodes

| Code | Bedeutung |
|------|-----------|
| 200 | Erfolg |
| 400 | Ungültige Anfrage |
| 401 | Nicht autorisiert |
| 403 | Verboten |
| 404 | Nicht gefunden |
| 500 | Serverfehler |

---

## Siehe auch

- [[MODULES-DE|Module]] — Vollständige Modulliste
- [[Configuration]] — Systemkonfiguration
- [[Troubleshooting]] — Fehlerbehebung
