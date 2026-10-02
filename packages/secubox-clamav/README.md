# secubox-clamav — antivirus à la demande dans un LXC dédié (#1912)

clamd avec `main.cvd` + `daily.cvd` demande ~1 Go de mémoire. Le conteneur `mail` est limité à
384 Mo (#496) : ClamAV vit donc dans son propre LXC, **endormi tant que personne n'en a besoin**.

```
Rspamd (conteneur mail)
   └─► 10.100.0.1:3310       mandataire de l'hôte, activé par socket (secubox-clamav-proxy.socket)
          ├─ ExecStartPre : clamavctl wake      démarre le LXC, attend PONG (~45 s à froid)
          ├─ systemd-socket-proxyd --exit-idle-time=600s ─► 10.100.0.220:3310 (clamd, LXC clamav)
          └─ ExecStopPost : clamavctl sleep     arrête le LXC : la mémoire est rendue à l'hôte
```

| | |
|---|---|
| Conteneur | `clamav`, Debian bookworm non privilégié, `10.100.0.220`, `lxc.start.auto = 0` |
| Mémoire | `memory.high` 1,4 Go / `memory.max` 1,8 Go, **alloués seulement éveillé** (≈ 1 Go mesuré) |
| Écoute | clamd sur `10.100.0.220:3310` seulement (unité `clamav-daemon.socket`) ; l'hôte sur `10.100.0.1:3310` (pont des conteneurs) ; rien sur la LAN |
| Base | `freshclam` quand le LXC est éveillé + minuterie hebdomadaire (`secubox-clamav-update.timer`, dimanche 04:30) |
| Politique de panne | scanner indisponible → le message passe **avec le symbole `CLAM_VIRUS_FAIL`**, jamais une perte silencieuse |

## clamavctl

```
clamavctl install          crée le LXC et télécharge la base (plusieurs minutes)
clamavctl wake | sleep     démarre / arrête le LXC
clamavctl update           réveille, freshclam, rendort (s'il l'a réveillé)
clamavctl status [--json]  état du LXC, de clamd, âge de la base
```

## Activer côté courrier

`mailctl antivirus on` (paquet `secubox-mail` ≥ 2.10.18) dépose le module Rspamd
(`local.d/antivirus.conf`, délai 120 s) et porte `task_timeout` à 150 s. **Rien n'est installé dans le
conteneur mail.** `mailctl antivirus status` montre l'état du LXC et du module.

## Pièges rencontrés (et corrigés)

- **clamd ignore `TCPSocket`** quand il est démarré par activation de socket (Debian) : l'écoute TCP se
  déclare sur `clamav-daemon.socket.d/tcp.conf`.
- **`local.d/antivirus.conf` est déjà dans la section du module** : ne pas l'envelopper dans
  `antivirus { … }` (Rspamd lit `antivirus { antivirus { … } }`, répond « unknown antivirus type » et
  désactive le module en silence).
- **`options.inc` du conteneur mail appartient à l'uid 0 de l'hôte** : `task_timeout` s'écrit côté hôte.
- **Démarrage à froid** : le premier message après un long repos attend ~45–90 s ; sans
  `task_timeout = 150s` Rspamd coupait le scan à 8 s et le message passait sans verdict.

## Fail-closed

Pour refuser plutôt que laisser passer quand le scanner est indisponible, ajouter dans le conteneur
mail un `local.d/force_actions.conf` sur le symbole `CLAM_VIRUS_FAIL` (voir la documentation Rspamd).
Le défaut reste fail-open **visible**.
