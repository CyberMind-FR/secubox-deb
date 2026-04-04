# SecuBox CyberFeed

Threat Intelligence Feed Aggregator for SecuBox-DEB.

## Overview

CyberFeed aggregates threat intelligence feeds from multiple sources and provides
unified blocklist management for IPs, domains, and other Indicators of Compromise (IoCs).

## Features

- **Multi-Source Feed Aggregation**: Built-in support for popular threat feeds
  - abuse.ch (Feodo Tracker, SSL Blacklist, URLhaus)
  - Spamhaus DROP/EDROP
  - Emerging Threats
  - blocklist.de
  - Phishing Army
  - OpenPhish
  - Tor Exit Nodes
  - CINS Score
  - AlienVault OTX

- **Blocklist Management**: Unified IP and domain blocklists
- **IoC Tracking**: Track threat indicators with source attribution
- **Feed Health Monitoring**: Status and error tracking for each feed
- **Scheduled Updates**: Automatic feed refresh (configurable intervals)
- **Export Formats**:
  - Plain text
  - nftables sets
  - Unbound RPZ
  - dnsmasq
  - Hosts file

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/status` | GET | Public status |
| `/stats` | GET | Aggregated statistics |
| `/feeds` | GET | List all feeds |
| `/feed/{name}` | GET | Get feed details |
| `/feed/{name}/enable` | POST | Enable/disable feed |
| `/feed/{name}/update` | POST | Update specific feed |
| `/feeds/add` | POST | Add custom feed |
| `/feeds/{name}` | DELETE | Remove custom feed |
| `/feeds/update` | POST | Update all enabled feeds |
| `/blocklist/ips` | GET | Get IP blocklist |
| `/blocklist/domains` | GET | Get domain blocklist |
| `/indicators` | GET | Get threat indicators |
| `/check/ip/{ip}` | GET | Check if IP is blocked |
| `/check/domain/{domain}` | GET | Check if domain is blocked |
| `/export/ips` | GET | Export IP blocklist |
| `/export/domains` | GET | Export domain blocklist |

## Configuration

Configuration is stored in `/etc/secubox/cyberfeed/` and state in `/var/lib/secubox/cyberfeed/`.

## Built-in Feeds

| Feed Name | Type | Category | Source |
|-----------|------|----------|--------|
| abuse-ch-feodo | IP | botnet | Feodo Tracker |
| abuse-ch-sslbl | IP | malware | SSL Blacklist |
| abuse-ch-urlhaus-domain | Domain | malware | URLhaus |
| spamhaus-drop | IP | spam | Spamhaus DROP |
| spamhaus-edrop | IP | spam | Spamhaus EDROP |
| emergingthreats-compromised | IP | threats | Emerging Threats |
| blocklist-de-all | IP | abuse | blocklist.de |
| phishing-army | Domain | phishing | Phishing Army |
| openphish | URL | phishing | OpenPhish |
| tor-exit-nodes | IP | anonymizer | Tor Project |
| cinsscore-badguys | IP | threats | CINS Score |
| alienvault-reputation | IP | reputation | AlienVault OTX |

## Integration

### With Vortex-Firewall

Export IP blocklist in nftables format:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost/api/v1/cyberfeed/export/ips?format=nftables"
```

### With Vortex-DNS

Export domain blocklist for Unbound:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost/api/v1/cyberfeed/export/domains?format=unbound"
```

## Building

```bash
cd packages/secubox-cyberfeed
dpkg-buildpackage -us -uc -b
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
