<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-metanews

SecuBox — radar d'actualite multi-sources (MetaNews).

MetaNews agrege des flux RSS/Atom, detecte quand plusieurs sources parlent du meme evenement et les regroupe en UN sujet : un resume court et factuel, les liens vers les sources originales, puis une discussion dans le BBS SecuBox.

Types de source (`type`) : `rss` (defaut, flux RSS/Atom) et `mediapart-blog` (lecture de la liste publique des billets d'un blog du Club Mediapart, qui n'expose plus de flux RSS ; l'hote `blogs.mediapart.fr` est aussi auto-detecte). Cf. `internal/linker/mediapart.go`.

Ce n'est pas un portail de presse ni une recopie d'articles : c'est un radar. Plusieurs sources -> un evenement -> un resume -> les liens -> une discussion.

Regroupement heuristique local (sans LLM obligatoire), agregation locale, pas de traqueur tiers : les appels externes se limitent a lire les flux declares.

Paquet Debian : version `0.1.50-1~bookworm1`, architecture `any`.

## Contenu

- `cmd/` : sources Go
- `internal/` : fichiers du module
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `systemd/` : unités systemd
- `tmpfiles/` : répertoires d'exécution
- `vendor/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/bbs.sock`, `/run/secubox/metanews.sock`.
- `secubox-metanews.service` : SecuBox MetaNews — radar d'actualite multi-sources (utilisateur `secubox-metanews`), lance `secubox-metanewsd`

## Dépendances SecuBox

`secubox-sbxui`.
