# Task 8 — Rapport : TLS pour la série Z (nginx dans le LXC, secubox-picobrew)

**Statut :** Terminé.

(Note : ce fichier contenait précédemment un rapport Task-8 sans rapport avec
ce plan — sleeper `serve` daemon loop / secubox-profiles, ref #896 — écrasé
ici car il ne concernait pas ce plan.)

## Commit
`bde53fb0` — "feat(picobrew): terminaison TLS dans le LXC pour la série Z"

Fichiers modifiés (scope volontairement limité à ces deux-là) :
- `packages/secubox-picobrew/sbin/picobrewctl` (modifié)
- `packages/secubox-picobrew/tests/test_ctl_tls.py` (créé)

## Séquence TDD

1. Test écrit (`test_ctl_tls.py`, verbatim du brief, 3 cas : TLS sur 443,
   `proxy_pass` vers `127.0.0.1:80`, absence de `listen 80`).
2. Run initial → échec confirmé, `__emit-nginx` inconnu :
   ```
   FFF
   AssertionError: usage: picobrewctl {install|start|stop|status [--json]|update <sha>|logs}
   assert 1 == 0
   3 failed in 0.08s
   ```
3. Implémentation ajoutée (verbatim du brief) avant `usage()` :
   `_emit_nginx_config` (heredoc `<<'EOF'` — délimiteur **quoté**, donc pas
   d'interpolation bash de `$host`/`$remote_addr`) et `_ensure_cert`
   (génération de certificat auto-signé via `lxc_attach`, effet de bord
   confiné au conteneur, jamais sur l'hôte). Branche
   `__emit-nginx) _emit_nginx_config ;;` ajoutée dans le `case`, avant `*)`.
   Câblage dans `cmd_install` juste avant `_install_service_unit` :
   `_ensure_cert`, écriture de la config dans `sites-available`, symlink vers
   `sites-enabled`, suppression du vhost `default`, `nginx -t` puis
   `systemctl enable --now nginx`.
4. Re-run → vert :
   ```
   syntaxe OK
   ...
   3 passed in 0.06s
   ```

## Vérifications obligatoires — sorties réelles

### `cd packages/secubox-picobrew && python3 -m pytest tests/ -q` (suite complète)
```
...................                                                      [100%]
19 passed in 0.34s
```

### `bash tests/test_picobrewctl_guards.sh`
```
PASS accept sha '0123456789abcdef0123456789abcdef01234567'
PASS reject sha 'HEAD'
PASS reject sha 'main'
PASS reject sha '0123456789abcdef0123456789abcdef0123456'
PASS reject sha '0123456789ABCDEF0123456789ABCDEF01234567'
PASS reject sha 'v1.0; rm -rf /'
PASS reject unknown cmd
```
7/7 PASS.

### `bash -n sbin/picobrewctl`
```
syntaxe OK
```
(aucune sortie d'erreur — syntaxe bash valide, `set -e` toujours absent du
script, `set -uo pipefail` inchangé)

### Sortie réelle de `bash sbin/picobrewctl __emit-nginx` (preuve du non-interpolage)
```
# SecuBox-Deb :: PicoBrew — terminaison TLS pour la série Z.
#
# picobrew_pico écoute déjà en clair sur :80 — c'est le comportement upstream,
# et c'est ce que les Pico/Zymatic attendent. nginx ne prend donc QUE le 443 :
# le faire écouter aussi sur :80 tout en proxifiant vers 127.0.0.1:80 le ferait
# se parler à lui-même (boucle infinie). Les appareils non-Z continuent de
# joindre Flask directement en :80.
server {
    listen 443 ssl;
    server_name picobrew.com _;
    client_max_body_size 32m;
    ssl_certificate     /etc/picobrew/tls/cert.pem;
    ssl_certificate_key /etc/picobrew/tls/key.pem;
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```
`$host` et `$remote_addr` apparaissent **littéralement** dans la sortie (pas
de substitution bash — ces variables n'existent pas dans le shell hôte, une
interpolation les aurait remplacées par une chaîne vide). Le heredoc utilise
le délimiteur quoté `<<'EOF'`, ce qui désactive toute expansion. Confirmé
aussi dans cette même sortie : `listen 443 ssl` présent une seule fois,
`proxy_pass http://127.0.0.1:80` présent, et **aucune** occurrence de
`listen 80`.

## Diff appliqué (`sbin/picobrewctl`)

Conforme verbatim au brief : ajout de `_emit_nginx_config`, `_ensure_cert`,
branche `__emit-nginx` avant `*)` dans le `case`, et câblage dans
`cmd_install` juste avant `_install_service_unit`. Vérifié via `git diff` :
deux blocs d'ajout uniquement, aucune suppression ni altération de code
existant.

```diff
@@ cmd_install() { ... } @@
+    _ensure_cert || { err "génération du certificat échouée"; return 1; }
+    _emit_nginx_config > "$LXC_PATH/$CONTAINER/rootfs/etc/nginx/sites-available/picobrew"
+    lxc_attach 'ln -sf /etc/nginx/sites-available/picobrew /etc/nginx/sites-enabled/picobrew
+                rm -f /etc/nginx/sites-enabled/default
+                nginx -t >/dev/null 2>&1 && systemctl enable --now nginx' \
+        || { err "configuration nginx invalide"; return 1; }
+
     _install_service_unit
     ...

@@ après cmd_update(), avant usage() @@
+_emit_nginx_config() {
+    cat <<'EOF'
+    ...(config nginx, listen 443 ssl uniquement)...
+EOF
+}
+
+_ensure_cert() {
+    lxc_attach 'set -e
+        mkdir -p /etc/picobrew/tls
+        [ -s /etc/picobrew/tls/cert.pem ] && exit 0
+        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
+            -subj "/CN=picobrew.com" \
+            -addext "subjectAltName=DNS:picobrew.com,DNS:*.picobrew.com" \
+            -keyout /etc/picobrew/tls/key.pem \
+            -out /etc/picobrew/tls/cert.pem >/dev/null 2>&1
+        chmod 600 /etc/picobrew/tls/key.pem'
+}

@@ case "${1:-}" in ... @@
     __emit-config) _emit_lxc_config ;;
+    __emit-nginx) _emit_nginx_config ;;
```

## Préoccupations

- `_ensure_cert` et le câblage nginx de `cmd_install` (symlink,
  `nginx -t`, `systemctl enable --now nginx`) dépendent de `lxc_attach`,
  donc d'un conteneur LXC réellement démarré — non testable en CI hors
  environnement LXC. Seule `_emit_nginx_config` (sans effet de bord, stdout
  uniquement, comme exigé) est couverte par des tests automatisés ; c'est le
  même niveau de couverture que le reste du module (`_emit_lxc_config` /
  `cmd_install` suivent déjà ce schéma — pas de régression de rigueur).
- Aucune régression détectée : 19/19 tests pytest du module (dont les 3
  nouveaux) et 7/7 gardes shell passent après la modification.

---

## Correctif de revue — `enable --now nginx` → `enable && restart` (post-Task 8)

**Statut :** Terminé.

### Défaut relevé en revue

`nginx` figure dans `--include=` du debootstrap ; le paquet Debian
auto-active son unit via preset. Sur un conteneur fraîchement débootstrappé,
nginx tourne donc déjà (vhost `default` stock, `listen 80 default_server`)
avant même l'écriture de la config TLS. `systemctl enable --now nginx` sur
une unit **déjà active** est un no-op côté (re)démarrage : la nouvelle
config 443 n'est jamais chargée par le process en mémoire, et nginx reste
planté sur `:80`, empêchant ensuite `picobrew.service` (Flask) de se lier
sur ce port. Installation bloquée sur tout conteneur neuf.

### Correctif

Dans `cmd_install`, remplacement de :
```bash
nginx -t >/dev/null 2>&1 && systemctl enable --now nginx
```
par :
```bash
nginx -t >/dev/null 2>&1 && systemctl enable nginx && systemctl restart nginx
```
Commentaire ajouté juste avant le bloc `lxc_attach` expliquant pourquoi
`restart` (et non `enable --now`) est requis, pour empêcher qu'un futur
lecteur ne « simplifie » en réintroduisant le bug.

Conservé à l'identique : `nginx -t` avant toute (re)activation, le
`|| { err "configuration nginx invalide"; return 1; }`, `set -uo pipefail`
en tête sans `set -e` au niveau du script, et le reste de `cmd_install`
(ordre `_ensure_cert` → écriture config → nginx → `picobrew.service`).

### Vérifications obligatoires — sorties réelles

`bash -n sbin/picobrewctl` → aucune sortie, syntaxe OK.

`bash tests/test_picobrewctl_guards.sh` (depuis `packages/secubox-picobrew`) :
```
PASS accept sha '0123456789abcdef0123456789abcdef01234567'
PASS reject sha 'HEAD'
PASS reject sha 'main'
PASS reject sha '0123456789abcdef0123456789abcdef0123456'
PASS reject sha '0123456789ABCDEF0123456789ABCDEF01234567'
PASS reject sha 'v1.0; rm -rf /'
PASS reject unknown cmd
```
7/7 PASS.

`cd packages/secubox-picobrew && python3 -m pytest tests/ -q` :
```
...................                                                      [100%]
19 passed in 0.31s
```

`bash sbin/picobrewctl __emit-nginx` : sortie strictement identique à celle
documentée plus haut dans ce fichier (mêmes octets, `listen 443 ssl`
uniquement, `proxy_pass http://127.0.0.1:80`), confirmée par
`grep -n "listen 80"` → aucune occurrence.

`git diff` sur `packages/secubox-picobrew/sbin/picobrewctl` : diff minimal,
un commentaire ajouté + une ligne modifiée (`enable --now nginx` →
`enable nginx && systemctl restart nginx`), aucun autre changement.

### Préoccupations

- Comme pour le reste du câblage nginx/LXC de ce module, ce chemin dépend de
  `lxc_attach` (conteneur réellement démarré) et n'est donc pas couvert par
  un test automatisé direct — même limite déjà documentée plus haut pour
  `_ensure_cert`/`cmd_install`. Seule la non-régression de `_emit_nginx_config`
  (sortie statique) est vérifiable en CI, et elle est confirmée inchangée.
- Le correctif n'a pas été testé en conditions réelles sur un LXC fraîchement
  débootstrappé (pas d'accès à un tel environnement dans cette session) ;
  la garantie repose sur la sémantique documentée de `systemctl restart`
  (fonctionne indifféremment sur une unit active ou arrêtée).
