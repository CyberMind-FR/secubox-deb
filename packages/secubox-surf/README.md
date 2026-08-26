# secubox-surf — POC de relais MITM d'un site externe

**Ce n'est pas un service. C'est un banc d'essai.** Il mesure si un site donné
peut être relayé à travers la box en origine isolée, tracker-strippé — sans
monter aucune origine publique ni toucher la production.

```bash
python3 -m surf.mesure https://www.facebook.com/
python3 -m surf.mesure --egress tor https://check.torproject.org/
python3 -m surf.mesure <adresse>.onion
SECUBOX_TOR_SOCKS=192.168.1.200:9050 python3 -m surf.mesure --egress tor …
```

Résultats et décision : **`docs/POC-SURF.md`**. Roadmap : `.claude/WIP.md` §0bis.
Le pendant (l’inverse) (corréler NOS services au lieu de les cloisonner) : #1216.
