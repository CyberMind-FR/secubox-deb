<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Dépôt apt : la clé de signature se déverrouille avec le Coffre

Le dépôt `apt.secubox.in` (gk2, `/data/apt`) est géré par `reprepro` : chaque suite déclare
`SignWith: default` et la clé (`44E50F0178E8BC7E`) est protégée par une phrase de passe.
`reprepro` tourne sans terminal : la phrase doit déjà être dans la mémoire de `gpg-agent`, qui
l'oublie à chaque redémarrage de gk2 (sinon : `Pinentry: Inappropriate ioctl for device`).

## Principe (#2007)

1. La phrase de la clé est **un secret du Coffre** : compartiment `box`, nom `depot-<empreinte>`.
   Elle n'existe nulle part ailleurs, ni en fichier ni en variable.
2. Le Coffre est **scellé au démarrage**. La **connexion d'un administrateur l'ouvre** (#1855).
3. `secubox-depot-coffre.timer` lance chaque minute
   `coffrectl depot deverrouiller --depuis-coffre --si-ouvert` :
   Coffre scellé → rien ; clé qui signe déjà → rien ; sinon la phrase est lue dans le Coffre et
   donnée à `gpg-agent` (TTL d'un an, donc jusqu'au prochain démarrage).

Après un redémarrage de gk2, il suffit donc de **se connecter** : dans la minute, la signature
fonctionne de nouveau, pour toutes les suites.

## Mise en place (une fois, par le propriétaire, sur gk2 en root)

L'empreinte entière de la clé :

```bash
coffrectl depot etat
```

Ranger la phrase de passe actuelle de la clé dans le Coffre (saisie masquée ; **jamais** en argument) :

```bash
coffrectl poser box depot-219BA872E3933EAAC3486A1344E50F0178E8BC7E
```

(L'interface `/vault/` du Hall permet la même chose : compartiment `box`, même nom.)

Vérifier :

```bash
coffrectl depot deverrouiller --depuis-coffre      # Coffre ouvert : « déverrouillée depuis le Coffre »
coffrectl depot etat                               # « session ouverte (l'agent tient la phrase) »
reprepro -b /data/apt export bookworm              # signe sans invite
systemctl list-timers secubox-depot-coffre.timer
```

## Pourquoi pas un fichier secret

Une phrase conservée en clair (0600) sur la machine qui porte la clé ne protège pas d'un accès
root à gk2, et un agent ou un script pourrait la lire. Dans le Coffre, elle n'est lisible que
Coffre ouvert, par root, et chaque lecture est inscrite au journal chaîné.

## Autres chemins déjà prévus par le Coffre (P2, #1366)

| Besoin | Commande |
|---|---|
| Session de signature limitée à N ≤ 60 minutes | `coffrectl depot session --minutes N` puis `coffrectl depot fin` |
| Clé sans humain, déverrouillée à chaque démarrage (niveau 0, systemd-creds) | `coffrectl depot proteger --demarrage` |

## Suite `trixie`

Sa strophe de `conf/distributions` doit porter `SignWith: default` comme les autres. Elle est
restée non signée tant que la signature ne marchait pas. Une fois la clé déverrouillée :
ajouter la ligne, `reprepro -b /data/apt export trixie bookworm`, puis faire pointer les clients
sur `https://apt.secubox.in trixie main` avec `signed-by=/usr/share/keyrings/secubox-archive-keyring.gpg`.
