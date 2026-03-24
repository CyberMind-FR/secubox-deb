# Reference API

[English](API-Reference) | [中文](API-Reference-ZH)

Tous les modules SecuBox exposent des APIs REST via sockets Unix, proxies par nginx a `/api/v1/<module>/`.

## Authentification

### Connexion

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Reponse :
```json
{
  "success": true,
  "token": "eyJ...",
  "username": "admin",
  "role": "admin"
}
```

### Utilisation du Token

```bash
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

## Endpoints Communs

Tous les modules implementent :

| Endpoint | Methode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut du module |
| `/health` | GET | Non | Verification sante |

## API Hub (`/api/v1/hub/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/dashboard` | GET | Donnees tableau de bord |
| `/menu` | GET | Menu lateral dynamique |
| `/modules` | GET | Liste statut modules |
| `/alerts` | GET | Alertes actives |
| `/system_health` | GET | Score sante systeme |
| `/network_summary` | GET | Statut reseau |

## API CrowdSec (`/api/v1/crowdsec/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/metrics` | GET | Metriques CrowdSec |
| `/decisions` | GET | Decisions actives |
| `/alerts` | GET | Alertes securite |
| `/bouncers` | GET | Statut bouncers |
| `/ban` | POST | Bannir IP |
| `/unban` | POST | Debannir IP |

## API WireGuard (`/api/v1/wireguard/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/interfaces` | GET | Interfaces WG |
| `/peers` | GET | Liste peers |
| `/peer` | POST | Ajouter peer |
| `/peer/{id}` | DELETE | Supprimer peer |
| `/qrcode/{peer}` | GET | QR code peer |

## API HAProxy (`/api/v1/haproxy/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/stats` | GET | Statistiques HAProxy |
| `/backends` | GET | Serveurs backend |
| `/frontends` | GET | Listeners frontend |

## API DPI (`/api/v1/dpi/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/flows` | GET | Flux actifs |
| `/applications` | GET | Apps detectees |
| `/protocols` | GET | Stats protocoles |

## API QoS (`/api/v1/qos/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/status` | GET | Statut QoS |
| `/classes` | GET | Classes trafic |
| `/rules` | GET | Regles shaping |

## API Systeme (`/api/v1/system/`)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/info` | GET | Informations systeme |
| `/services` | GET | Statut services |
| `/logs` | GET | Journaux systeme |
| `/reboot` | POST | Redemarrer |
| `/update` | POST | Mettre a jour |

## Reponses Erreur

| Code | Description |
|------|-------------|
| 400 | Requete invalide |
| 401 | Non autorise |
| 403 | Interdit |
| 404 | Non trouve |
| 500 | Erreur serveur |

## Voir Aussi

- [[Configuration-FR]] - Configuration API
- [[Modules-FR]] - Details modules
