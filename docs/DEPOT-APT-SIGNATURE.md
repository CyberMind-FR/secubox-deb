<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Dépôt apt : signature automatique après démarrage

Le dépôt `apt.secubox.in` est géré par `reprepro` sur gk2 (`/data/apt`). Chaque suite déclare
`SignWith: default` dans `conf/distributions`, et la clé (`44E50F0178E8BC7E`, empreinte
`219BA872E3933EAAC3486A1344E50F0178E8BC7E`) est protégée par une phrase de passe.

## Le problème

`reprepro` tourne sans terminal. La phrase de passe doit donc déjà être dans la mémoire de
`gpg-agent`. Un redémarrage de gk2 vide cette mémoire : toute inclusion ou tout `export` échoue
avec `Pinentry: Inappropriate ioctl for device`, pour **toutes** les suites.

## La solution : un service qui la redonne à chaque démarrage

`secubox-apt-gpg-preset` (script) et `secubox-apt-gpg-preset.service` (unité systemd) lisent la
phrase dans `/etc/secubox/secrets/apt-gpg-passphrase` et la prérèglent dans `gpg-agent`, puis
vérifient qu'une signature réussit sans invite.

Le fichier secret est créé **par le propriétaire**. Aucun agent ni paquet ne le fabrique ni ne le lit.

### Installation (une fois, sur gk2, en root)

```bash
install -m 0755 scripts/apt-infra/secubox-apt-gpg-preset /usr/local/sbin/
install -m 0644 scripts/apt-infra/secubox-apt-gpg-preset.service /etc/systemd/system/

# Le secret : saisie masquée, fichier 0600 root.
umask 077
read -rs -p "Phrase de passe de la clé du dépôt : " P; echo
printf '%s\n' "$P" > /etc/secubox/secrets/apt-gpg-passphrase; unset P
chmod 600 /etc/secubox/secrets/apt-gpg-passphrase

systemctl daemon-reload
systemctl enable --now secubox-apt-gpg-preset.service
systemctl status secubox-apt-gpg-preset.service --no-pager | head -5
```

Succès attendu : `clé 44E50F0178E8BC7E déverrouillée, signature vérifiée`.

### Vérification

```bash
echo test | gpg --batch --pinentry-mode error --local-user 44E50F0178E8BC7E --clearsign | head -2
reprepro -b /data/apt export bookworm
```

## Limite à connaître

La phrase de passe est conservée en clair (0600 root) sur la machine qui porte aussi la clé :
cela ne protège pas contre quelqu'un qui obtiendrait un accès root à gk2. Cela protège la clé
d'un vol de sauvegarde de `~/.gnupg` seul, et rend la signature automatique. Une protection plus
forte passe par un module matériel ou le TPM (voir #1902).

## Suite `trixie`

Sa strophe de `conf/distributions` doit porter `SignWith: default` comme les autres ; elle a été
laissée non signée tant que le secret GPG n'existait pas côté CI. Après installation du service :
ajouter la ligne, `reprepro -b /data/apt export trixie bookworm`, puis faire pointer les clients
sur `https://apt.secubox.in trixie main` avec `signed-by=/usr/share/keyrings/secubox-archive-keyring.gpg`.
