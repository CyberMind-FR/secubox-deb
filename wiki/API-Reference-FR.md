# Référence API

[English](API-Reference) | [中文](API-Reference-ZH)

Tous les modules SecuBox exposent des APIs REST via sockets Unix, proxiés par nginx à `/api/v1/<module>/`.

**Total : 48 modules | ~1000+ endpoints API**

---

## Authentification

### Connexion

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Réponse :
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

---

## Endpoints Communs

Tous les modules implémentent :

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut du module |
| `/health` | GET | Non | Vérification santé |

---

## Modules Centraux

### API Hub (`/api/v1/hub/`)

Tableau de bord et gestion des modules.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Oui | Statut système et santé modules |
| `/modules` | GET | Oui | Liste tous les modules installés |
| `/alerts` | GET | Non | Alertes système |
| `/monitoring` | GET | Oui | Métriques CPU, mémoire, charge |
| `/dashboard` | GET | Non | Données tableau de bord complet |
| `/menu` | GET | Non | Menu latéral dynamique |
| `/security_summary` | GET | Oui | Aperçu sécurité |
| `/network_summary` | GET | Non | Résumé interfaces réseau |
| `/module_control` | POST | Oui | Démarrer/arrêter/redémarrer module |
| `/notifications` | GET | Oui | Notifications système |
| `/system_health` | GET | Non | Score santé système |
| `/check_updates` | GET | Oui | Vérifier mises à jour |
| `/apply_updates` | POST | Oui | Appliquer mises à jour |

### API Portail (`/api/v1/portal/`)

Authentification et gestion des sessions.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/login` | POST | Non | Authentifier utilisateur |
| `/logout` | POST | Non | Terminer session |
| `/verify` | GET | Non | Vérifier session courante |
| `/sessions` | GET | Oui | Lister sessions actives |
| `/users` | GET | Oui | Lister utilisateurs (admin) |
| `/users/create` | POST | Oui | Créer utilisateur (admin) |
| `/users/change-password` | POST | Oui | Changer mot de passe |

### API Système (`/api/v1/system/`)

Administration et diagnostics système.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/info` | GET | Non | Informations système |
| `/resources` | GET | Non | Utilisation CPU/mémoire/disque |
| `/services` | GET | Non | Liste des services |
| `/restart_services` | POST | Oui | Redémarrer services SecuBox |
| `/reload_firewall` | POST | Oui | Recharger nftables |
| `/shutdown` | POST | Oui | Arrêter système |
| `/reboot` | POST | Oui | Redémarrer système |
| `/logs` | GET | Oui | Journaux système |
| `/diagnostics` | GET | Oui | Rapport diagnostique |
| `/backup` | POST | Oui | Créer sauvegarde config |
| `/restore_config` | POST | Oui | Restaurer sauvegarde |

---

## Modules Sécurité

### API CrowdSec (`/api/v1/crowdsec/`)

Détection et prévention d'intrusions.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/components` | GET | Non | Composants système |
| `/metrics` | GET | Oui | Métriques CrowdSec |
| `/decisions` | GET | Oui | Décisions actives (bans) |
| `/alerts` | GET | Oui | Alertes sécurité |
| `/bouncers` | GET | Oui | Statut bouncers |
| `/ban` | POST | Oui | Bannir adresse IP |
| `/unban` | POST | Oui | Débannir adresse IP |
| `/nftables` | GET | Oui | Statistiques nftables |
| `/service/start` | POST | Oui | Démarrer CrowdSec |
| `/service/stop` | POST | Oui | Arrêter CrowdSec |
| `/console/enroll` | POST | Oui | Enregistrer à Console CrowdSec |

#### Exemple Bannir IP
```bash
curl -X POST https://localhost/api/v1/crowdsec/ban \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.1.100","duration":"24h","reason":"manuel"}'
```

### API WAF (`/api/v1/waf/`)

Pare-feu applicatif web avec 300+ règles.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut WAF |
| `/categories` | GET | Non | Catégories de règles |
| `/rules` | GET | Oui | Toutes les règles WAF |
| `/rules/{category}` | GET | Oui | Règles par catégorie |
| `/category/{category}/toggle` | POST | Oui | Activer/désactiver catégorie |
| `/stats` | GET | Non | Statistiques menaces |
| `/alerts` | GET | Non | Alertes menaces récentes |
| `/bans` | GET | Non | Bans IP actifs |
| `/ban` | POST | Oui | Bannir IP manuellement |
| `/unban/{ip}` | POST | Oui | Supprimer ban IP |
| `/whitelist` | GET | Oui | IPs en liste blanche |

### API NAC (`/api/v1/nac/`)

Contrôle d'accès réseau.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Oui | Statut système NAC |
| `/clients` | GET | Oui | Clients connectés |
| `/zones` | GET | Oui | Zones réseau |
| `/parental_rules` | GET | Oui | Règles contrôle parental |
| `/add_to_zone` | POST | Oui | Déplacer client vers zone |
| `/approve_client` | POST | Oui | Approuver nouveau client |
| `/ban_client` | POST | Oui | Bannir client |
| `/quarantine_client` | POST | Oui | Mettre en quarantaine |

### API Hardening (`/api/v1/hardening/`)

Durcissement noyau et système.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut durcissement |
| `/components` | GET | Non | Composants durcissement |
| `/benchmark` | POST | Oui | Exécuter benchmark sécurité |
| `/apply` | POST | Oui | Appliquer paramètres |

---

## Modules Réseau

### API Network Modes (`/api/v1/netmodes/`)

Configuration topologie réseau.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Oui | Mode réseau actuel |
| `/get_available_modes` | GET | Oui | Modes disponibles |
| `/get_interfaces` | GET | Oui | Interfaces réseau |
| `/set_mode` | POST | Oui | Préparer changement mode |
| `/apply_mode` | POST | Oui | Appliquer mode réseau |
| `/rollback` | POST | Oui | Revenir au précédent |
| `/router_config` | GET | Oui | Config mode routeur |
| `/ap_config` | GET | Oui | Config point d'accès |

### API WireGuard (`/api/v1/wireguard/`)

Gestion tunnels VPN.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/interfaces` | GET | Non | Interfaces WireGuard |
| `/interface/{name}/up` | POST | Oui | Activer interface |
| `/interface/{name}/down` | POST | Oui | Désactiver interface |
| `/peers` | GET | Non | Liste des pairs |
| `/peer` | POST | Oui | Ajouter nouveau pair |
| `/peer` | DELETE | Oui | Supprimer pair |
| `/peer/{name}/config` | GET | Oui | Fichier config pair |
| `/peer/{name}/qr` | GET | Oui | QR code pair |
| `/genkey` | POST | Oui | Générer paire de clés |

#### Exemple Ajouter Pair
```bash
curl -X POST https://localhost/api/v1/wireguard/peer \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"mobile","allowed_ips":"10.0.0.2/32"}'
```

### API QoS (`/api/v1/qos/`)

Gestion bande passante et traffic shaping. 80+ endpoints.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Oui | Statut QoS |
| `/classes` | GET | Oui | Classes de trafic |
| `/rules` | GET | Oui | Règles classification |
| `/quotas` | GET | Oui | Quotas bande passante |
| `/usage` | GET | Oui | Utilisation courante |
| `/apply_qos` | POST | Oui | Appliquer config QoS |
| `/realtime` | GET | Oui | Bande passante temps réel |
| `/top_talkers` | GET | Oui | Plus gros consommateurs |
| `/vlans` | GET | Oui | Interfaces VLAN |
| `/vlan/create` | POST | Oui | Créer VLAN |
| `/parental` | GET | Oui | Contrôles parentaux |

### API DPI (`/api/v1/dpi/`)

Inspection approfondie des paquets. 40+ endpoints.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Oui | Statut DPI |
| `/flows` | GET | Oui | Flux actifs |
| `/applications` | GET | Oui | Applications détectées |
| `/devices` | GET | Oui | Appareils connectés |
| `/top_apps` | GET | Oui | Top applications |
| `/bandwidth_by_app` | GET | Oui | BP par application |
| `/block_rules` | GET | Oui | Règles blocage apps |
| `/add_block_rule` | POST | Oui | Créer règle blocage |
| `/dns_queries` | GET | Oui | Requêtes DNS |
| `/ssl_flows` | GET | Oui | Flux SSL/TLS |

---

## Modules Services

### API HAProxy (`/api/v1/haproxy/`)

Gestion équilibreur de charge.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut HAProxy |
| `/stats` | GET | Oui | Statistiques HAProxy |
| `/backends` | GET | Oui | Serveurs backend |
| `/frontends` | GET | Oui | Listeners frontend |
| `/acls` | GET | Oui | Listes contrôle accès |
| `/waf/status` | GET | Oui | Statut intégration WAF |
| `/waf/toggle` | POST | Oui | Activer/désactiver WAF |
| `/reload` | POST | Oui | Recharger configuration |

### API VHost (`/api/v1/vhost/`)

Gestion hôtes virtuels.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/vhosts` | GET | Oui | Lister hôtes virtuels |
| `/vhost/{domain}` | GET | Oui | Détails hôte virtuel |
| `/vhost` | POST | Oui | Créer hôte virtuel |
| `/vhost/{domain}` | PUT | Oui | Modifier hôte virtuel |
| `/vhost/{domain}` | DELETE | Oui | Supprimer hôte virtuel |
| `/certificates` | GET | Non | Certificats SSL |
| `/certificate/issue` | POST | Oui | Émettre cert Let's Encrypt |
| `/reload` | POST | Oui | Recharger nginx |

### API Netdata (`/api/v1/netdata/`)

Proxy monitoring système.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut Netdata |
| `/charts` | GET | Oui | Graphiques disponibles |
| `/data` | GET | Oui | Données graphique |
| `/cpu` | GET | Oui | Métriques CPU |
| `/memory` | GET | Oui | Métriques mémoire |
| `/disk` | GET | Oui | Métriques disque |
| `/alerts` | GET | Oui | Alertes actives |

---

## Modules Applications

### API Mail (`/api/v1/mail/`)

Gestion serveur email (Postfix/Dovecot).

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut serveur mail |
| `/users` | GET | Oui | Utilisateurs mail |
| `/user` | POST | Oui | Créer utilisateur |
| `/user/{email}` | DELETE | Oui | Supprimer utilisateur |
| `/aliases` | GET | Oui | Alias mail |
| `/domains` | GET | Oui | Domaines mail |
| `/dkim/status` | GET | Oui | Statut DKIM |
| `/dkim/setup` | POST | Oui | Configurer DKIM |
| `/spam/status` | GET | Oui | Statut SpamAssassin |
| `/spam/setup` | POST | Oui | Configurer antispam |
| `/av/status` | GET | Oui | Statut ClamAV |
| `/av/setup` | POST | Oui | Configurer antivirus |
| `/acme/issue` | POST | Oui | Émettre certificat |
| `/webmail/install` | POST | Oui | Installer webmail |

### API DNS (`/api/v1/dns/`)

Gestion serveur DNS BIND.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/zones` | GET | Oui | Zones DNS |
| `/zone/{name}` | GET | Oui | Détails zone |
| `/zone` | POST | Oui | Créer zone |
| `/records/{zone}` | GET | Oui | Enregistrements zone |
| `/record` | POST | Oui | Ajouter enregistrement |
| `/dnssec/enable/{zone}` | POST | Oui | Activer DNSSEC |
| `/reload` | POST | Oui | Recharger BIND |

### API Users (`/api/v1/users/`)

Gestion identité unifiée pour 7 services.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/users` | GET | Oui | Lister utilisateurs |
| `/user` | POST | Oui | Créer utilisateur |
| `/user/{username}` | PUT | Oui | Modifier utilisateur |
| `/user/{username}` | DELETE | Oui | Supprimer utilisateur |
| `/user/{username}/passwd` | POST | Oui | Changer mot de passe |
| `/groups` | GET | Oui | Lister groupes |
| `/import` | POST | Oui | Import utilisateurs masse |
| `/export` | GET | Oui | Exporter utilisateurs |
| `/sync` | POST | Oui | Synchroniser services |

---

## Modules Intelligence

### API SOC (`/api/v1/soc/`)

Tableau de bord Centre Opérations Sécurité.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut SOC |
| `/clock` | GET | Non | Horloge mondiale (10 fuseaux) |
| `/map` | GET | Non | Carte menaces mondiale |
| `/tickets` | GET | Oui | Tickets sécurité |
| `/ticket` | POST | Oui | Créer ticket |
| `/intel` | GET | Oui | IOCs renseignement menaces |
| `/intel` | POST | Oui | Ajouter IOC |
| `/alerts` | GET | Oui | Alertes sécurité |
| `/ws` | WebSocket | Oui | Mises à jour temps réel |

### API Metrics (`/api/v1/metrics/`)

Tableau de bord métriques temps réel.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/status` | GET | Non | Statut métriques |
| `/overview` | GET | Non | Aperçu système |
| `/waf_stats` | GET | Non | Statistiques WAF |
| `/connections` | GET | Non | Connexions TCP |
| `/all` | GET | Non | Toutes métriques combinées |
| `/certs` | GET | Non | Certificats SSL |
| `/vhosts` | GET | Non | Hôtes virtuels |

### API Device Intel (`/api/v1/device-intel/`)

Découverte et empreinte des actifs.

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/devices` | GET | Oui | Appareils découverts |
| `/device/{mac}` | GET | Oui | Détails appareil |
| `/scan` | POST | Oui | Déclencher scan actif |
| `/vendors` | GET | Oui | Lookup vendeur MAC |
| `/dhcp_leases` | GET | Oui | Baux DHCP |
| `/arp_table` | GET | Oui | Table ARP |
| `/trust/{mac}` | POST | Oui | Marquer comme fiable |

---

## Réponses Erreur

```json
{
  "success": false,
  "error": "Non autorisé",
  "code": 401
}
```

| Code | Description |
|------|-------------|
| 400 | Requête invalide |
| 401 | Non autorisé |
| 403 | Interdit |
| 404 | Non trouvé |
| 500 | Erreur serveur |

---

## Limitation de Débit

- 100 requêtes/minute par IP (non authentifié)
- 1000 requêtes/minute par utilisateur (authentifié)

---

## WebSocket

Mises à jour temps réel disponibles à `wss://localhost/api/v1/<module>/ws` :

```javascript
const ws = new WebSocket('wss://localhost/api/v1/soc/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Mise à jour:', data);
};
```

Modules avec support WebSocket :
- `/api/v1/soc/ws` — Alertes SOC temps réel
- `/api/v1/dpi/ws` — Mises à jour flux
- `/api/v1/qos/ws` — Stats bande passante

---

## Notes Architecture

**Communication Socket :**
- Chaque module fonctionne sur socket Unix : `/run/secubox/<module>.sock`
- Nginx proxie : `http+unix:///run/secubox/<module>.sock`

**Pattern Authentification :**
- Tokens JWT via `Authorization: Bearer <token>`
- Émis par `/api/v1/portal/login`
- Expiration 24 heures par défaut

---

## Voir Aussi

- [[Installation-FR]] - Guide installation
- [[Modules-FR]] - Détails modules
- [[Configuration-FR]] - Configuration API
