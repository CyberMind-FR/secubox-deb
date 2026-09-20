<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# DPI vivant — nDPId émancipé en Go (sbxdpi)

La carte **🔬 DPI · Trafic** du [[Hall|Cartes-du-Hall]] montre le trafic **réel**
de la box, classé par **nDPI 5.x** — plus aucun jeu de démo. La donnée est
**agrégée et sans PII** (compteurs par protocole / application / catégorie /
paire d'IP / risque), servie en lecture seule.

## Chaîne

```
nDPId (capture eth2, nDPI 5.x libre) → nDPIsrvd (distributeur)
    → sbxdpi (couche Go du parc) → /run/secubox/dpi-live.sock (/api/v1/dpi/*)
    → relais nginx du Hall → carte DPI · Trafic (slices à bullets)
```

* **nDPId + nDPIsrvd** = paquet **`secubox-dpi-engine`** (nDPI 5.x **compilé des
  sources amont** — le libndpi 4.2 du système est trop vieux). nDPId capture,
  classe, et pousse du JSON encadré ; nДPIsrvd le rediffuse.
* **`sbxdpi`** = daemon Go dans `secubox-toolbox-ng` (`cmd/sbxdpi/`), même dessin
  modulaire que `sbx-sentinel`. Il **compose** le distributeur en lecture seule,
  applique le **filtrage go-level** du parc, agrège, et sert l'API.

## Filtrage go-level (déclaratif, hot-reload)

Des conffiles `*.txt` sous `/etc/secubox/dpi/`, rechargés à la volée (mtime) :

* `app-deny.txt` — apps / protocoles / catégories / hôtes à écarter du tableau
  (bruit : mDNS, DHCP…).
* `app-allow.txt` — épingles qui **priment** sur le deny.
* `risk-mute.txt` — risques nDPI à ne pas afficher (faux positifs).
* **Exemption première partie** — nos propres vhosts (clés de
  `haproxy-routes.json`) et le LAN ne sont jamais comptés comme « le grand large ».

## API (GET, sans PII)

`/api/v1/dpi/` : `health` · `stats` · `top_protocols` · `top_apps` ·
`top_categories` · `talkers` · `risks` (`?limit=`). Le JWT est posé au niveau
nginx / FastAPI ; le socket Go ne sert que des compteurs agrégés locaux.

## Bon à savoir

* Le snapshot d'état va sur le **SSD `/data`**, jamais l'eMMC racine (15 Go) — un
  gros fichier la remplit et fait tomber SQLite des autres modules.
* `aggregator.sock` = **passerelle API maîtresse** du parc, surtout PAS un socket
  DPI ; `sbxdpi` a le sien (`dpi-live.sock`).
* Cadrage nDPIsrvd : préfixe **5 chiffres = longueur du corps** qui suit.

---

Voir aussi : [[SBXOS · le Hall|Cartes-du-Hall]] · [[Architecture]] · [[WAF-FR]]
