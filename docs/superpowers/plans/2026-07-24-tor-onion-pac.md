# PAC auto-routing .onion → Tor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** livrer un PAC qui route les `.onion` vers le SOCKS Tor local (le reste en DIRECT), dans le module `secubox-tor`.

**Architecture :** trois fichiers statiques + packaging — un dropin torrc qui ouvre un `SocksPort` LAN confiné, un fichier PAC (`.onion` → `SOCKS5`, else `DIRECT`), et le service nginx du PAC. Aucun code applicatif : la logique tient dans une fonction PAC pure, testable hors navigateur.

**Tech Stack :** torrc (Tor), JavaScript PAC (`FindProxyForURL`), nginx, debhelper. Tests : `node` (éval du PAC), `tor --verify-config`, `bash -n`/`nginx -t`.

**Spec :** `docs/superpowers/specs/2026-07-24-tor-onion-pac-design.md`

## Global Constraints

- SOCKS Tor exposé sur **`192.168.1.200:9050`** (IP LAN du box), confiné par `SocksPolicy accept 192.168.0.0/16` + `accept 10.99.0.0/16` + `reject *` (dans cet ordre — premier match). **Jamais** `0.0.0.0`, **jamais** SOCKS ouvert.
- Le `SocksPort 10.10.0.1:9050` existant (mesh) est **conservé** — on AJOUTE, on ne déplace pas.
- Le PAC renvoie **`SOCKS5`** (pas SOCKS4) pour que Tor résolve le `.onion` (remote DNS).
- `.onion` match : `shExpMatch(host, "*.onion")` ∪ `shExpMatch(host, "onion")` ; **ne doit PAS** matcher un host qui contient « onion » sans être le TLD `.onion` (ex. `onion.example.com`).
- PAC servi en `application/x-ns-proxy-autoconfig`, **LAN-only** (allow privé / deny all).
- En-tête SPDX `LicenseRef-CMSD-1.0` en tête de chaque fichier créé (commentaire adapté au format).
- Le dropin torrc s'installe dans `/etc/tor/torrc.d/` (le torrc du board fait `%include /etc/tor/torrc.d/*.conf`).
- **Prérequis runtime :** `tor@default` est `failed` sur le board depuis 2026-07-10. Le PAC est une pièce morte tant que Tor ne sert pas le SOCKS — la vérification manuelle finale l'inclut.

## File Structure

| Fichier | Responsabilité |
|---|---|
| `conf/torrc.d/50-secubox-socks-lan.conf` | Ajoute le `SocksPort` LAN + `SocksPolicy` |
| `www/tor/tor.pac` | Le PAC (fonction pure `FindProxyForURL`) |
| `nginx/tor.conf` | (modifié) ajoute la `location = /tor.pac` avec le bon MIME |
| `tests/test_tor_pac.js` | Éval du PAC sur les cas (onion vs faux match) |
| `tests/test_socks_dropin.py` | Vérifie les directives + l'ordre du dropin torrc |
| `debian/rules` | (modifié) installe le dropin torrc |
| `README.md` | (modifié) runbook client (URL PAC + `socks_remote_dns`) |

---

### Task 1 : le PAC (`FindProxyForURL`) — cœur, testable hors navigateur

**Files:**
- Create: `packages/secubox-tor/www/tor/tor.pac`
- Create: `packages/secubox-tor/tests/test_tor_pac.js`

**Interfaces:**
- Produces: un fichier PAC exposant `function FindProxyForURL(url, host)` renvoyant `"SOCKS5 192.168.1.200:9050"` pour un `.onion`, `"DIRECT"` sinon.

- [ ] **Step 1 : écrire le test qui échoue**

`packages/secubox-tor/tests/test_tor_pac.js` :

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Évalue le PAC hors navigateur : on injecte le shim PAC `shExpMatch` (glob
// insensible à la casse sur le host, comme les navigateurs), on charge le
// fichier, puis on vérifie FindProxyForURL sur des cas réels.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function shExpMatch(str, pat) {
  // équivalent PAC : * = n'importe quelle suite ; ancré début→fin ; casse ignorée
  const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                                 .replace(/\*/g, '.*') + '$', 'i');
  return re.test(str);
}

const src = fs.readFileSync(path.join(__dirname, '..', 'www', 'tor', 'tor.pac'), 'utf8');
const sandbox = { shExpMatch };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const F = sandbox.FindProxyForURL;

const SOCKS = 'SOCKS5 192.168.1.200:9050';
const cases = [
  ['http://abcdefhij.onion/',      'abcdefhij.onion', SOCKS],   // onion simple
  ['http://a.b.deep.onion/x',      'a.b.deep.onion',  SOCKS],   // sous-domaines
  ['http://onion/',                'onion',           SOCKS],   // host « onion » nu
  ['https://example.com/',         'example.com',     'DIRECT'],
  ['https://onion.example.com/',   'onion.example.com','DIRECT'],// faux match !
  ['https://not-onion.org/',       'not-onion.org',   'DIRECT'],
];
let fail = 0;
for (const [url, host, want] of cases) {
  const got = F(url, host);
  if (got !== want) { console.error(`FAIL ${host}: got ${got} want ${want}`); fail = 1; }
  else console.log(`PASS ${host} -> ${got}`);
}
process.exit(fail);
```

- [ ] **Step 2 : lancer le test, vérifier qu'il échoue**

Run: `node packages/secubox-tor/tests/test_tor_pac.js`
Expected: FAIL — `tor.pac` n'existe pas (`ENOENT`).

- [ ] **Step 3 : écrire le PAC**

`packages/secubox-tor/www/tor/tor.pac` :

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox :: routage automatique .onion -> Tor. Tout le reste en DIRECT
// (l'inspection transparente wg-toolbox s'en charge déjà). SOCKS5 est requis
// pour que la résolution du nom .onion soit déléguée à Tor (remote DNS).
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.onion") || shExpMatch(host, "onion"))
        return "SOCKS5 192.168.1.200:9050";
    return "DIRECT";
}
```

- [ ] **Step 4 : relancer, vérifier vert**

Run: `node packages/secubox-tor/tests/test_tor_pac.js`
Expected: 6 lignes `PASS`, code de sortie 0. Le cas `onion.example.com -> DIRECT` prouve l'absence de faux match.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-tor/www/tor/tor.pac packages/secubox-tor/tests/test_tor_pac.js
git commit -m "feat(tor): PAC .onion -> SOCKS5 Tor, reste en DIRECT"
```

---

### Task 2 : dropin torrc — SOCKS LAN confiné

**Files:**
- Create: `packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf`
- Create: `packages/secubox-tor/tests/test_socks_dropin.py`

**Interfaces:**
- Produces: un dropin torrc installé (Task 4) en `/etc/tor/torrc.d/50-secubox-socks-lan.conf`.

- [ ] **Step 1 : écrire le test qui échoue**

`packages/secubox-tor/tests/test_socks_dropin.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le SOCKS exposé au LAN ne doit JAMAIS être ouvert : SocksPort sur l'IP LAN
(pas 0.0.0.0), et une SocksPolicy dont le `reject *` vient EN DERNIER (Tor
applique la première policy qui matche)."""
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf" / "torrc.d" / "50-secubox-socks-lan.conf"

def test_socksport_bound_to_lan_ip_not_wildcard():
    t = CONF.read_text()
    assert "SocksPort 192.168.1.200:9050" in t
    assert "0.0.0.0" not in t

def test_policy_accepts_lan_and_wg():
    t = CONF.read_text()
    assert "SocksPolicy accept 192.168.0.0/16" in t
    assert "SocksPolicy accept 10.99.0.0/16" in t

def test_reject_all_is_last_policy_line():
    lines = [l.strip() for l in CONF.read_text().splitlines()
             if l.strip().startswith("SocksPolicy")]
    assert lines[-1] == "SocksPolicy reject *", f"reject * doit être en dernier, got {lines}"
```

- [ ] **Step 2 : lancer, vérifier l'échec**

Run: `cd packages/secubox-tor && python3 -m pytest tests/test_socks_dropin.py -q`
Expected: FAIL — `FileNotFoundError`.

- [ ] **Step 3 : écrire le dropin**

`packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf` :

```text
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox :: SOCKS local pour les clients LAN / wg-toolbox (PAC .onion -> Tor).
# JAMAIS ouvert : le SocksPort est lié à l'IP LAN (pas 0.0.0.0), et la
# SocksPolicy ferme tout sauf LAN + wg. L'ordre compte : Tor applique la
# PREMIERE policy qui matche, donc `reject *` reste en dernier.
SocksPort 192.168.1.200:9050
SocksPolicy accept 192.168.0.0/16
SocksPolicy accept 10.99.0.0/16
SocksPolicy reject *
```

- [ ] **Step 4 : relancer**

Run: `cd packages/secubox-tor && python3 -m pytest tests/test_socks_dropin.py -q`
Expected: `3 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf packages/secubox-tor/tests/test_socks_dropin.py
git commit -m "feat(tor): dropin torrc — SocksPort LAN confiné (accept LAN+wg, reject *)"
```

---

### Task 3 : servir le PAC (nginx, bon MIME, LAN-only)

**Files:**
- Modify: `packages/secubox-tor/nginx/tor.conf`

- [ ] **Step 1 : lire la conf nginx actuelle pour insérer proprement**

Run: `cat packages/secubox-tor/nginx/tor.conf`
Note la ou les `location` déjà présentes (on AJOUTE une `location = /tor.pac`, on ne remplace rien).

- [ ] **Step 2 : ajouter la location PAC**

Ajouter en tête de `packages/secubox-tor/nginx/tor.conf` (avant les locations existantes) :

```nginx
# PAC : routage automatique .onion -> Tor. Servi en MIME PAC, LAN-only.
location = /tor.pac {
    alias /usr/share/secubox/www/tor/tor.pac;
    types { } default_type application/x-ns-proxy-autoconfig;
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
}
```

- [ ] **Step 3 : vérifier la cohérence du fragment nginx**

Run: `grep -c "location = /tor.pac" packages/secubox-tor/nginx/tor.conf`
Expected: `1`.
Run: `grep -c "application/x-ns-proxy-autoconfig" packages/secubox-tor/nginx/tor.conf`
Expected: `1`.
(La validation `nginx -t` réelle est faite à la vérification manuelle, sur la board — un fragment `secubox.d` seul n'est pas une config complète.)

- [ ] **Step 4 : commit**

```bash
git add packages/secubox-tor/nginx/tor.conf
git commit -m "feat(tor): nginx sert /tor.pac en application/x-ns-proxy-autoconfig, LAN-only"
```

---

### Task 4 : packaging — installer le dropin torrc + README + changelog

**Files:**
- Modify: `packages/secubox-tor/debian/rules`
- Modify: `packages/secubox-tor/README.md`
- Modify: `packages/secubox-tor/debian/changelog`

- [ ] **Step 1 : installer le dropin torrc via `debian/rules`**

Ajouter à la fin du bloc `override_dh_auto_install:` de `packages/secubox-tor/debian/rules` :

```makefile
	# Dropin torrc : SOCKS LAN confiné pour le PAC .onion -> Tor.
	install -d $(CURDIR)/debian/secubox-tor/etc/tor/torrc.d
	install -m 644 conf/torrc.d/50-secubox-socks-lan.conf \
		$(CURDIR)/debian/secubox-tor/etc/tor/torrc.d/50-secubox-socks-lan.conf
```

- [ ] **Step 2 : documenter le runbook client dans `README.md`**

Ajouter à la fin de `packages/secubox-tor/README.md` :

```markdown
## PAC .onion → Tor (client)

Configure le navigateur/OS en « URL de configuration automatique du proxy » :

    http://<box>/tor.pac

Le PAC dévie les `.onion` vers le SOCKS Tor du box (`192.168.1.200:9050`), tout
le reste passe en DIRECT.

**Firefox :** active `network.proxy.socks_remote_dns = true` (`about:config`),
sinon Firefox tente de résoudre le `.onion` en DNS local et échoue avant
d'atteindre Tor. Chrome fait le remote DNS pour un SOCKS5 issu d'un PAC par
défaut.

Le SOCKS est **fermé à l'extérieur** (`SocksPolicy` : LAN + wg-toolbox
uniquement) : ce n'est jamais un relais SOCKS ouvert.
```

- [ ] **Step 3 : entrée de changelog**

Ajouter en tête de `packages/secubox-tor/debian/changelog` (adapter le numéro au précédent + 1) :

```text
secubox-tor (1.0.7-1~bookworm1) bookworm; urgency=medium

  * PAC .onion -> Tor : nouveau /tor.pac (dévie les .onion vers le SOCKS Tor
    local en SOCKS5, reste en DIRECT), servi en application/x-ns-proxy-autoconfig
    LAN-only. Dropin torrc ajoutant un SocksPort LAN confiné (192.168.1.200:9050,
    SocksPolicy accept LAN+wg reject *, jamais open-relay). README : runbook
    client + network.proxy.socks_remote_dns.

 -- Gerald KERMA <devel@cybermind.fr>  Thu, 24 Jul 2026 16:00:00 +0200
```

- [ ] **Step 4 : construire le paquet + vérifier le contenu**

Run:
```bash
cd packages/secubox-tor && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb -c ../secubox-tor_1.0.7-1~bookworm1_all.deb | grep -E "torrc.d/50-secubox-socks-lan|www/tor/tor.pac|nginx/secubox.d/tor.conf"
```
Expected: le `.deb` est construit ; la liste contient `/etc/tor/torrc.d/50-secubox-socks-lan.conf`, `/usr/share/secubox/www/tor/tor.pac`, `/etc/nginx/secubox.d/tor.conf`.

- [ ] **Step 5 : vérifier que le postinst résiste à l'expansion debhelper**

Run:
```bash
tmp=$(mktemp -d); dpkg-deb -e ../secubox-tor_1.0.7-1~bookworm1_all.deb "$tmp/DEBIAN"
bash -n "$tmp/DEBIAN/postinst" && echo "postinst OK"; rm -rf "$tmp"
```
Expected: `postinst OK` (le jeton `#DEBHELPER#` doit rester seul sur sa ligne — jamais dans un commentaire).

- [ ] **Step 6 : lancer toute la suite**

Run:
```bash
node packages/secubox-tor/tests/test_tor_pac.js
cd packages/secubox-tor && python3 -m pytest tests/test_socks_dropin.py -q
```
Expected: PAC 6/6 PASS ; pytest `3 passed`.

- [ ] **Step 7 : commit**

```bash
git add packages/secubox-tor/debian packages/secubox-tor/README.md
git commit -m "feat(tor): packaging PAC .onion (install dropin torrc + README client + 1.0.7)"
```

---

## Recette de vérification manuelle (sur le board)

Le PAC est inerte sans Tor. Après déploiement du `.deb` :

```bash
# 1. Tor sert-il le nouveau SOCKS LAN ? (PRÉREQUIS — tor@default est failed sur gk2)
systemctl status secubox-tor tor@default --no-pager | grep -iE "Active"
ss -tlnp | grep 9050            # attendu : 192.168.1.200:9050 en écoute
# Si tor est failed : diagnostiquer (journalctl -u tor@default -n 30) et réparer
# AVANT de conclure — sinon le PAC est une pièce morte.

# 2. Le PAC est servi avec le bon MIME ?
curl -sI http://192.168.1.200/tor.pac | grep -i content-type
# attendu : application/x-ns-proxy-autoconfig
# NB gk2 : le vhost réel (webui.conf) sert /www statiquement ; si le dropin
# secubox.d n'est pas inclus, le PAC est aussi joignable en /tor/tor.pac mais
# avec un MIME par défaut — ajouter la location à webui.conf pour le MIME strict.

# 3. Confinement SOCKS : refuse une source hors LAN/wg (test de policy).

# 4. Bout en bout : un .onion connu résout via le SOCKS.
curl --socks5-hostname 192.168.1.200:9050 -sS -o /dev/null -w "%{http_code}\n" \
     http://<onion-connu>/
```

## Hors périmètre

WPAD, `.onion` hors HTTP(S), pays d'exit, rotation de circuit (backlog Tor distinct). La réparation de fond de `tor@default failed` au-delà de « le faire servir le SOCKS » relève d'un debug Tor séparé si la cause dépasse la config.
