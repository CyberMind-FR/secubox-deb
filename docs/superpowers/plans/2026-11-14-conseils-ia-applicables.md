<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Conseils IA applicables (#3716) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** rendre applicables les conseils de l'onglet Menaces : bans de bloc /24 sur gk2, compte de service `ai-ban`
borné, application d'office des cas sûrs par le relais du POC gk0, un clic sinon, annulation, plafonds, suspension.

**Architecture :** gk2 gagne une table nft séparée pour les blocs (`inet secubox_waf_blocs`, script root `waf-blocs`
derrière `wafctl`) et trois routes `/api/v1/waf/ai/*` gardées par un jeton EdDSA à usage unique dont la clé privée
reste sur la box de l'IA (`secubox_core.compte_service`). Le relais du POC calcule seul le verdict (règles en code),
décide (mode, suspension, plafonds), signe et journalise ; la page suit la maquette.

**Tech Stack :** Bash + Python 3 stdlib (`waf-blocs`, `python3 -I`), nftables, systemd, sudoers ; FastAPI, PyJWT
(EdDSA) + cryptography (Ed25519) ; POC : FastAPI + httpx, page HTML/JS sans dépendance.

**Spec :** `docs/superpowers/specs/2026-11-14-conseils-ia-applicables-design.md` (à lire avec ce plan).

## Global Constraints

- Français partout (code, messages, commentaires, commits).
- En-tête SPDX CMSD-1.0 sur tout fichier créé (`scripts/license-headers.py` pour vérifier), y compris dans le POC.
- Commits : `type(portée): message (ref #3716)`, ligne vide, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Jamais `closes #3716` avant déploiement **et** go du propriétaire. Jamais `git stash`. Jamais `git add` sous `.superpowers/`.
- Versions : `X.Y.Z-N~trixie1`. secubox-core `1.8.31` → **`1.8.32-1~trixie1`** ; secubox-waf-ng `1.34.1` →
  **`1.35.0-1~trixie1`**, `Depends: secubox-core (>= 1.8.32~)`.
- Python des essais : `PY=/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python` (`$PY -m pytest`).
- Cas sûr (valeurs exactes) : bloc IPv4 **/24** exact ; **≥ 20** adresses du bloc dans `waf_ban` ; catégories
  ⊆ **`{"scanners", "recon_crawler"}`** ; aucune adresse protégée ; durée **86 400 s**.
- Plafonds d'office : **5 / 3 600 s**, **20 / 86 400 s** (fenêtres glissantes). Plafond du compte sur gk2 :
  **30 / 3 600 s**, **100 / 86 400 s**.
- Durées : d'office ≤ **86 400 s** ; un clic **3 600 à 604 800 s** ; choix de la page : 4 h, 24 h, 7 j.
- Jeton `ai-ban` : `alg=EdDSA`, `kid` = SHA-256 hex (64) de la clé publique DER ; `sub="ai-ban"`, `aud="gk2"`
  (nom court de la box cible), `portee="waf-ban"`, `exp - iat ≤ 60`, dérive 5 s, `jti` = 32 hex à usage unique,
  `corps` = SHA-256 hex du corps brut (`b""` pour un GET).
- Chemins : clés publiques gk2 `/etc/secubox-comptes-service/ai-ban/<kid>.pub` (root:root 0755/0644) ; clé privée POC
  `/etc/secubox/secrets/ai-ban/ai-ban.key` (reepost, 0600, dossier 0700) ; état des blocs
  `/var/lib/secubox-waf-blocs/blocs.json` (root 0600, dossier 0700) ; journal gk2
  `/var/lib/secubox/waf/ai-ban.jsonl` ; journal POC `relais/gestes.jsonl` ; audit gk2 `/var/log/secubox/audit.log`.
- IPv4 seulement pour `ai-ban` et pour les blocs (pas de /64, pas d'adresse IPv6) — spec, § IPv6.
- `RULES-CODE.md` : § 2 permissions, § 3 garde (exception écrite pour `/ai/*`), § 6 pas de bloquant en `async def`,
  § 7 `subprocess.run([...], check=…, timeout=…)` sans `shell=True`, § 8 dates UTC, § 9 shell strict.
- gk2 = production : rien n'y est essayé avant le banc gk6 ; déploiement par apt, jamais d'édition à chaud ;
  aucune limite de temps sur apt/dpkg ; un seul redémarrage de l'agrégateur.

## Review Focus

1. **Rechargement du pare-feu ou redémarrage** : `systemctl reload nftables` relance `flush ruleset` ; les blocs
   actifs doivent revenir avec leur temps restant, sinon un ban « actif » au journal ne bloque plus rien.
   → Tâche 2 : `test_unite_reappliquer_suit_nftables`, `test_reappliquer_rejoue_les_blocs_non_echus_avec_le_reste`.
2. **Horloge de gk0 en avance ou gk2 qui refuse le jeton (401)** : tout refus d'authentification doit se lire
   « jeton refusé par gk2 » dans la page, ne pas compter dans les plafonds et ne pas être relancé en boucle.
   → Tâche 7 : `test_401_gk2_avis_jeton_rien_compte`.
3. **gk2 injoignable ou 5xx pendant un geste d'office, puis résumé suivant qui repropose le même bloc** : jamais
   compté comme appliqué, jamais deux bans actifs du même bloc par `ai-ban`.
   → Tâche 7 : `test_gk2_injoignable_rien_compte`, `test_deja_applique_pas_de_second_post`.
4. **`gestes.toml` absent ou illisible** (liste des protégées inconnue) : l'automatique doit se fermer (tout en un
   clic, avis), pas s'ouvrir avec une liste vide.
   → Tâche 6 : `test_gestes_toml_absent_desactive_l_auto`.
5. **Geste échu** : « Annuler » disparaît, l'état passe à « échu », et un `unban` tardif rend 200 idempotent, jamais 500.
   → Tâche 4 : `test_unban_echu_idempotent` ; Tâche 7 : `test_synchro_etat_marque_echu`.

---

### Task 1 : `waf-blocs` — forme des cibles et gardes de protection

**Files :**
- Create : `packages/secubox-waf-ng/composants/waf/scripts/waf-blocs` (Python, `#!/usr/bin/python3 -I`, stdlib seule, 0755)
- Test : `packages/secubox-waf-ng/composants/waf/tests/test_waf_blocs_3716.py`

**Interfaces :**
- Consumes : rien.
- Produces (importable par `importlib.machinery.SourceFileLoader("waf_blocs", <chemin>)`) :
  - `INTERDITS: tuple[ipaddress._BaseNetwork, ...]` — même liste que `_valide_ip` de `wafctl`.
  - `normaliser_bloc(texte: str) -> ipaddress.IPv4Network` — `ValueError` hors IPv4 /24 strict.
  - `normaliser_cible(texte: str) -> ipaddress.IPv4Network | ipaddress.IPv4Address | ipaddress.IPv6Address`.
  - `lire_protegees(chemin: Path) -> list[ipaddress._BaseNetwork]` — fichier absent ⇒ `[]` ; ligne illisible ⇒ `GardeIllisible`.
  - `adresses_locales(executer) -> set[ipaddress._BaseAddress]` (`ip -j addr`, échec ⇒ `GardeIllisible`).
  - `adresses_pairs(executer) -> set[ipaddress._BaseAddress]` (`wg show all endpoints` ; `wg` absent ⇒ `set()`).
  - `motif_refus(cible, protegees, locales, pairs) -> str | None` — `"privee" | "protegee" | "box" | "pair" | None`.
  - `class GardeIllisible(Exception)`.
  - `executer(argv: list[str]) -> str` — `subprocess.run(argv, check=True, timeout=10, capture_output=True, text=True).stdout`.
  - CLI `waf-blocs verifier <cible>` : une ligne JSON `{"ok": bool, "motif": str | null}` ; sortie 0 ok, 1 invalide,
    2 privee, 3 protegee, 4 box, 5 pair, 6 garde_illisible. `PROTEGEES_ENV = Path("/etc/secubox/waf/protegees.env")`
    (clé `SECUBOX_WAF_PROTEGEES`, liste séparée par des virgules).

- [ ] **Step 1 : écrire les tests qui échouent**

```python
def test_bloc_exact_24_seulement(wb):
    assert str(wb.normaliser_bloc("203.0.113.0/24")) == "203.0.113.0/24"
    for faux in ("203.0.113.0/23", "203.0.113.0/25", "203.0.113.7/24", "2001:db8::/64", "203.0.113.0", "x"):
        with pytest.raises(ValueError):
            wb.normaliser_bloc(faux)

def test_interdits_refuses(wb):
    for b in ("10.1.2.0/24", "192.168.1.0/24", "172.16.5.0/24", "127.0.0.0/24", "169.254.1.0/24"):
        assert wb.motif_refus(wb.normaliser_bloc(b), [], set(), set()) == "privee"

def test_protegees_env_recoupe(wb, tmp_path):
    f = tmp_path / "protegees.env"; f.write_text("SECUBOX_WAF_PROTEGEES=203.0.113.7/32,198.51.100.0/22\n")
    p = wb.lire_protegees(f)
    assert wb.motif_refus(wb.normaliser_bloc("203.0.113.0/24"), p, set(), set()) == "protegee"
    assert wb.motif_refus(wb.normaliser_bloc("198.51.101.0/24"), p, set(), set()) == "protegee"
    assert wb.motif_refus(wb.normaliser_bloc("192.0.2.0/24"), p, set(), set()) is None

def test_adresse_de_la_box(wb):
    locales = {ipaddress.ip_address("198.51.100.10")}
    assert wb.motif_refus(wb.normaliser_bloc("198.51.100.0/24"), [], locales, set()) == "box"

def test_pair_wireguard(wb):
    sortie = "wg-mesh\tAbC=\t192.0.2.5:51820\nwg0\tDeF=\t(none)\n"
    pairs = wb.adresses_pairs(lambda argv: sortie)
    assert pairs == {ipaddress.ip_address("192.0.2.5")}
    assert wb.motif_refus(wb.normaliser_bloc("192.0.2.0/24"), [], set(), pairs) == "pair"

def test_wg_absent_n_est_pas_un_refus(wb):
    def absent(argv): raise FileNotFoundError(argv[0])
    assert wb.adresses_pairs(absent) == set()

def test_garde_illisible_ferme(wb, tmp_path, capsys):
    f = tmp_path / "protegees.env"; f.write_text("SECUBOX_WAF_PROTEGEES=pas-une-plage\n")
    with pytest.raises(wb.GardeIllisible):
        wb.lire_protegees(f)
    # en CLI : sortie 6, motif garde_illisible (PROTEGEES_ENV et executer remplacés par monkeypatch)

def test_adresse_seule_verifiee_pareil(wb):
    assert wb.motif_refus(wb.normaliser_cible("192.168.1.20"), [], set(), set()) == "privee"
    assert wb.motif_refus(wb.normaliser_cible("198.51.100.10"), [], {ipaddress.ip_address("198.51.100.10")}, set()) == "box"

def test_sortie_json_une_ligne(wb, monkeypatch, capsys):
    # verifier 203.0.113.0/24, sans protégée : rc 0, stdout == '{"ok": true, "motif": null}\n'
    ...
```

- [ ] **Step 2 : lancer, constater l'échec**

Run : `cd packages/secubox-waf-ng/composants/waf && $PY -m pytest tests/test_waf_blocs_3716.py -q`
Expected : FAIL (fichier `scripts/waf-blocs` absent).

- [ ] **Step 3 : écrire `waf-blocs` (fonctions ci-dessus et le verbe `verifier`)**

`motif_refus` : `privee` si la cible recoupe un réseau de `INTERDITS` (`overlaps` pour un bloc, `in` pour une
adresse) ; puis `protegee`, `box`, `pair` dans cet ordre. `adresses_locales` lit `addr_info[].local` de `ip -j addr`.
Le verbe `verifier` construit les trois listes à chaque appel (pas de cache) et rend `GardeIllisible` → 6.

- [ ] **Step 4 : relancer, constater le succès** — même commande, Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-waf-ng/composants/waf/scripts/waf-blocs packages/secubox-waf-ng/composants/waf/tests/test_waf_blocs_3716.py
git commit -m "feat(waf): waf-blocs, forme des blocs /24 et gardes box, LAN, pairs (ref #3716)"
```

---

### Task 2 : table nft des blocs, verbes `wafctl`, réapplication, sudoers

**Files :**
- Modify : `packages/secubox-waf-ng/composants/waf/scripts/waf-blocs` (verbes `ajouter`, `retirer`, `lister`, `reappliquer`)
- Create : `packages/secubox-waf-ng/composants/waf/config/blocs.nft` (installé par le `cp -r composants/waf/config/.` existant vers `/usr/share/secubox/waf/`)
- Create : `packages/secubox-waf-ng/systemd/secubox-waf-blocs.service`
- Modify : `packages/secubox-waf-ng/composants/waf/scripts/wafctl` (`cmd_ban` passe par `waf-blocs verifier` ; verbes `ban-bloc`, `unban-bloc`, `blocs` ; aide)
- Modify : `packages/secubox-waf-ng/composants/waf/sudoers/secubox-waf` (§ 5 blocs)
- Modify : `packages/secubox-waf-ng/tmpfiles.d/secubox-waf-ng.conf`, `packages/secubox-waf-ng/debian/rules` (installer `waf-blocs` en `/usr/sbin`, l'unité, `dh_installsystemd --name=secubox-waf-blocs`)
- Test : `packages/secubox-waf-ng/composants/waf/tests/test_waf_blocs_nft_3716.py`

**Interfaces :**
- Consumes : Task 1 (`normaliser_bloc`, `motif_refus`, gardes, `executer`).
- Produces :
  - Table `inet secubox_waf_blocs`, ensemble `blocs4` (`type ipv4_addr; flags interval, timeout; counter;`), chaîne
    `entree` (`hook input priority -101; policy accept;` règle `ip saddr @blocs4 counter drop`). Fichier rejouable :
    `table inet secubox_waf_blocs` / `delete table inet secubox_waf_blocs` / définition.
  - `ETAT_DOSSIER = Path("/var/lib/secubox-waf-blocs")`, `lire_etat(dossier) -> list[dict]` (`{"bloc", "debut", "fin"}`,
    epoch UTC), `ecrire_etat(dossier, blocs) -> None` (dossier ouvert `O_DIRECTORY|O_NOFOLLOW`, propriétaire root
    vérifié, fichier temporaire `O_EXCL|O_NOFOLLOW` 0600 relu et validé, puis `os.replace`).
  - `ajouter(bloc: str, secondes: int, executer, maintenant: float) -> dict`, `retirer(bloc: str, executer) -> dict`,
    `lister(executer, maintenant) -> list[dict]`, `reappliquer(executer, maintenant) -> int`.
  - CLI : `waf-blocs ajouter <cidr> <secondes>` / `retirer <cidr>` / `lister` / `reappliquer` — une ligne JSON
    `{"ok", "motif", ...}` ; motifs en plus : `duree` (hors 3 600…604 800), `nft` (nft refuse, sortie 7).
    Chaque `ajouter`/`retirer` réussi écrit une ligne d'audit `{"module": "waf", "action": "ban-bloc"|"unban-bloc", "detail", "by": "wafctl"}`.
  - `wafctl ban-bloc <cidr> <durée>` (durée `^[0-9]+[smhd]$` → secondes), `wafctl unban-bloc <cidr>`, `wafctl blocs`
    → `exec /usr/sbin/waf-blocs …`. `wafctl ban <ip>` : refus de `verifier` imprimé `refus:<motif>` sur stderr, sortie 1.
  - Sudoers `secubox` : `/usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/wafctl ban-bloc *`,
    `… unban-bloc *`, `/usr/sbin/wafctl blocs` (Cmnd_Alias `SBX_WAF_BLOCS`, `!requiretty`, `log_output`).
  - Unité `secubox-waf-blocs.service` : `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart=` et `ExecReload=/usr/sbin/waf-blocs reappliquer`,
    `After=nftables.service`, `PartOf=nftables.service`, `ReloadPropagatedFrom=nftables.service`, `WantedBy=multi-user.target` ;
    root, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/secubox-waf-blocs /var/log/secubox`,
    `ProtectHome=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE`,
    `RestrictAddressFamilies=AF_NETLINK AF_UNIX`, `UMask=0027`.
  - tmpfiles : `d /var/lib/secubox-waf-blocs 0700 root root -`.

- [ ] **Step 1 : écrire les tests qui échouent**

```python
def test_ajouter_pose_l_element_avec_timeout_et_ecrit_l_etat(wb, etat, nft):
    r = wb.ajouter("203.0.113.0/24", 3600, nft, 1_800_000_000)
    assert r["ok"] and ["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4",
                        "{ 203.0.113.0/24 timeout 3600s }"] in nft.appels
    assert wb.lire_etat(etat) == [{"bloc": "203.0.113.0/24", "debut": 1_800_000_000, "fin": 1_800_003_600}]

def test_ajouter_refuse_avant_nft_si_protegee(wb, etat, nft, protegee_203):
    assert wb.ajouter("203.0.113.0/24", 3600, nft, 0)["motif"] == "protegee" and nft.appels == []

def test_duree_hors_bornes(wb, etat, nft):
    assert wb.ajouter("203.0.113.0/24", 3599, nft, 0)["motif"] == "duree"
    assert wb.ajouter("203.0.113.0/24", 604_801, nft, 0)["motif"] == "duree"

def test_retirer_absent_n_est_pas_une_erreur(wb, etat, nft_absent):
    assert wb.retirer("203.0.113.0/24", nft_absent)["ok"] is True

def test_reappliquer_rejoue_les_blocs_non_echus_avec_le_reste(wb, etat, nft):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000},
                          {"bloc": "198.51.100.0/24", "debut": 0, "fin": 500}])
    assert wb.reappliquer(nft, 600) == 1
    assert ["nft", "-f", str(wb.FICHIER_TABLE)] in nft.appels
    assert ["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 203.0.113.0/24 timeout 400s }"] in nft.appels

def test_reappliquer_ignore_une_entree_forgee(wb, etat, nft):
    wb.ecrire_etat(etat, [{"bloc": "10.0.0.0/8", "debut": 0, "fin": 10**10}])   # écrit hors validation par le test
    assert wb.reappliquer(nft, 0) == 0

def test_etat_refuse_un_lien_ou_un_dossier_non_root(wb, tmp_path): ...   # GardeIllisible

def test_fichier_nft_rejouable_dans_un_espace_de_noms():
    # skip si `unshare -rn true` échoue ; sinon : nft -f deux fois, puis add element 203.0.113.0/24 timeout 60s, rc 0
    ...

def test_wafctl_verbes_et_ban_verifie():
    t = WAFCTL.read_text()
    assert "ban-bloc)" in t and "unban-bloc)" in t and "blocs)" in t
    assert "/usr/sbin/waf-blocs verifier" in t        # cmd_ban passe par la garde
    assert subprocess.run(["bash", "-n", str(WAFCTL)], check=False, timeout=10).returncode == 0

def test_sudoers_bornes_et_visudo():
    t = SUDOERS.read_text()
    assert "/usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/wafctl ban-bloc *" in t
    assert "cle-ai-ban" not in t                     # la gestion des clés reste à root
    # visudo -c -f si disponible, sinon skip

def test_unite_reappliquer_suit_nftables():
    u = UNITE.read_text()
    for l in ("PartOf=nftables.service", "ReloadPropagatedFrom=nftables.service",
              "ExecReload=/usr/sbin/waf-blocs reappliquer", "UMask=0027", "NoNewPrivileges=yes"):
        assert l in u

def test_tmpfiles_dossier_root_0700():
    assert "d /var/lib/secubox-waf-blocs 0700 root root -" in TMPFILES.read_text()
```

- [ ] **Step 2 : lancer, constater l'échec**

Run : `cd packages/secubox-waf-ng/composants/waf && $PY -m pytest tests/test_waf_blocs_nft_3716.py -q`
Expected : FAIL.

- [ ] **Step 3 : écrire `blocs.nft`, les verbes de `waf-blocs`, les verbes `wafctl`, l'unité, le sudoers, tmpfiles, `debian/rules`**

`ajouter` : garde (Task 1) → durée → `nft list table inet secubox_waf_blocs`, absente ⇒ `nft -f FICHIER_TABLE` →
`nft delete element` puis `add element` (un `add` ne change pas le timeout d'un élément présent) → état → audit.
`reappliquer` : `nft -f`, puis pour chaque entrée encore valide (forme, garde, `fin > maintenant`, `fin - maintenant ≤ 604 800`) `add element` avec le reste.

- [ ] **Step 4 : relancer + lint**

Run : `$PY -m pytest tests/test_waf_blocs_3716.py tests/test_waf_blocs_nft_3716.py -q && shellcheck scripts/wafctl && $PY -m ruff check scripts/waf-blocs`
Expected : PASS, aucun constat nouveau.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-waf-ng/composants/waf/scripts packages/secubox-waf-ng/composants/waf/config/blocs.nft \
        packages/secubox-waf-ng/composants/waf/sudoers/secubox-waf packages/secubox-waf-ng/systemd/secubox-waf-blocs.service \
        packages/secubox-waf-ng/tmpfiles.d/secubox-waf-ng.conf packages/secubox-waf-ng/debian/rules \
        packages/secubox-waf-ng/composants/waf/tests/test_waf_blocs_nft_3716.py
git commit -m "feat(waf): bans de bloc /24 dans une table nft dédiée, rejoués au rechargement du pare-feu (ref #3716)"
```

---

### Task 3 : `secubox_core.compte_service` — jeton signé à portée, clé publique root

**Files :**
- Create : `common/secubox_core/compte_service.py`
- Test : `common/secubox_core/tests/test_compte_service_3716.py`

**Interfaces :**
- Consumes : `auth._lire_fichier_root`, `auth._proprietaire_attendu`, `auth.nom_box_locale`, `auth._bearer`, `auth._ecrire_audit` (existants).
- Produces :
  - `DOSSIER_COMPTES_SERVICE = "/etc/secubox-comptes-service"`, `COMPTES_SERVICE = {"ai-ban": "waf-ban"}`,
    `DUREE_MAX_S = 60`, `DERIVE_S = 5`, `ALGORITHME = "EdDSA"`, `CLES_MAX = 2`.
  - `empreinte(cle_publique_pem: bytes) -> str` (SHA-256 hex du DER SubjectPublicKeyInfo).
  - `cles_publiques(compte: str) -> dict[str, Ed25519PublicKey]` — fichiers `<kid>.pub` du dossier du compte, dont le
    nom est l'empreinte réelle ; dossier douteux ⇒ `{}` ; relu quand le dossier change (inode, `mtime_ns`).
  - `class RefusCompteService(Exception)` avec `statut: int` (401/403) et `motif: str`.
  - `verifier_jeton(compte: str, jeton: str, corps: bytes, maintenant: float) -> dict` → `{"sub", "compte_service", "jti", "cle"}`.
  - `frapper_jeton(cle_privee_pem: bytes, compte: str, aud: str, corps: bytes, maintenant: float, duree_s: int = 30) -> str`.
  - `garde_compte_service(compte: str)` → dépendance `async (request, creds) -> dict` (lit `await request.body()`).
  - `require_ai_ban = garde_compte_service("ai-ban")`.
  - Rejeu : `jti` gardés jusqu'à `exp + DERIVE_S`, 10 000 au plus (au-delà ⇒ 503, jamais d'oubli d'un jti valide).
  - Audit des refus : `{"module": "compte-service", "action": "refus", "compte", "motif", "ip"}`, au plus une ligne
    par (compte, motif) toutes les 10 s ; jamais le jeton.

- [ ] **Step 1 : écrire les tests qui échouent** (fixture : paire Ed25519 générée, dossier `tmp_path/ai-ban/<kid>.pub`,
  `monkeypatch` de `DOSSIER_COMPTES_SERVICE`, `auth._proprietaire_attendu` → `os.getuid()`, `auth.nom_box_locale` → `"gk2"`)

```python
def test_jeton_valide_rend_le_compte(cs, cle):
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b'{"x":1}', T)
    p = cs.verifier_jeton("ai-ban", j, b'{"x":1}', T + 1)
    assert p["sub"] == "ai-ban" and p["compte_service"] == "ai-ban" and p["cle"] == cle.kid

@pytest.mark.parametrize("cas,statut", [("aud_autre_box", 403), ("portee", 403), ("duree_61s", 401),
    ("iat_futur_6s", 401), ("echu", 401), ("kid_inconnu", 401), ("corps_modifie", 401), ("alg_hs256", 401),
    ("sub_autre", 403), ("jti_court", 401)])
def test_refus(cs, cle, cas, statut): ...

def test_refus_rejeu_meme_jti(cs, cle):
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T)
    cs.verifier_jeton("ai-ban", j, b"", T)
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", j, b"", T + 1)
    assert e.value.statut == 401 and e.value.motif == "rejeu"

def test_dossier_inscriptible_par_le_groupe_aucune_cle(cs, cle):   # chmod 0775 ⇒ {} ⇒ 401
def test_cle_retiree_refus_immediat(cs, cle):                      # unlink du .pub ⇒ jeton suivant 401
def test_compte_hors_liste_refuse(cs, cle):                       # garde_compte_service("autre") ⇒ ValueError
def test_jeton_ai_ban_refuse_par_require_jwt_session_lecture(cs, cle, monkeypatch):
    # TestClient d'une petite app : GET/POST gardés par require_jwt, require_session, require_lecture
    # (mode tableau de bord inactif) ⇒ 401 avec Authorization: Bearer <jeton ai-ban>
def test_session_admin_refusee_par_require_ai_ban(cs, cle):        # create_token("admin") ⇒ 401
def test_refus_audite_sans_le_jeton(cs, cle, tmp_path):            # la ligne d'audit ne contient pas le jeton
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `$PY -m pytest common/secubox_core/tests/test_compte_service_3716.py -q` ; Expected : FAIL (module absent).

- [ ] **Step 3 : écrire `compte_service.py`**

Ordre de `verifier_jeton` : en-tête non vérifié → `alg == "EdDSA"` et `kid` connu → `jwt.decode(..., algorithms=["EdDSA"],
audience=nom_box_locale(), options={"require": ["exp", "iat", "jti", "sub", "aud"]}, leeway=DERIVE_S)` → `sub == compte`
(403) → `portee == COMPTES_SERVICE[compte]` (403) → `exp - iat ≤ DUREE_MAX_S` et `iat ≤ maintenant + DERIVE_S` → `jti`
`[0-9a-f]{32}` non vu → `corps == sha256(corps)`. Une audience refusée est un 403 (jeton d'une autre box).

- [ ] **Step 4 : relancer, et les suites voisines** — Run : `$PY -m pytest common/secubox_core/tests -q` ; Expected : PASS (aucune régression de `test_auth_pilotage_3126.py`, `test_lecture_gardee.py`).

- [ ] **Step 5 : commit**

```bash
git add common/secubox_core/compte_service.py common/secubox_core/tests/test_compte_service_3716.py
git commit -m "feat(core): compte de service par clé Ed25519, jeton à portée et usage unique (ref #3716)"
```

---

### Task 4 : routes WAF `/ai/ban`, `/ai/unban`, `/ai/etat`, gestion des clés, exception écrite

**Files :**
- Create : `packages/secubox-waf-ng/composants/waf/api/gestes_ia.py`
- Modify : `packages/secubox-waf-ng/composants/waf/api/main.py` (fin de fichier : `gestes_ia.configurer(...)`, `app.include_router(gestes_ia.router)`)
- Modify : `packages/secubox-waf-ng/composants/waf/scripts/wafctl` (verbes root `cle-ai-ban ajouter <fichier.pub> | retirer <kid>|--toutes | lister`, audités)
- Modify : `packages/secubox-waf-ng/debian/postinst` (dossiers `/etc/secubox-comptes-service` et `…/ai-ban` root:root 0755, jamais vidés)
- Modify : `.claude/RULES-CODE.md` (une ligne au tableau des exceptions)
- Test : `packages/secubox-waf-ng/composants/waf/tests/test_gestes_ia_3716.py`

**Interfaces :**
- Consumes : `secubox_core.compte_service.require_ai_ban` (Task 3) ; `wafctl ban`/`unban` et `ban-bloc`/`unban-bloc` (Task 2) ; de `main.py` : `_get_bans() -> list[dict]` (`ip`, `reason`), `_audit(action, detail, user)`.
- Produces :
  - `router = APIRouter(prefix="/ai")` ; `JOURNAL_AI = Path("/var/lib/secubox/waf/ai-ban.jsonl")`.
  - `configurer(bans: Callable[[], list[dict]], audit: Callable[[str, str, dict], None]) -> None`.
  - `class GesteBan(BaseModel)` : `cible: str`, `duree_s: int = Field(ge=3600, le=604800)`, `mode: Literal["auto", "clic"]`,
    `conseil: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")`, `motif: str = Field("", max_length=200)` ; `model_config = {"extra": "forbid"}`.
  - `class GesteAnnuler(BaseModel)` : `id: str = Field(pattern=r"^[0-9a-f]{32}$")`, `extra = "forbid"`.
  - `POST /ai/ban` → 200 `{"id", "cible", "fin", "audit": id}` ; 409 `{"detail": {"motif": …}}` avec `motif ∈ {"privee",
    "protegee", "box", "pair", "garde_illisible", "pas_sur", "plafond_auto", "plafond_compte", "duree", "nft", "deja_actif"}` ;
    422 forme (non IPv4, IPv4 non globale, /24 non exact, IPv6). Chaque 409 écrit une ligne d'audit `ai-ban-refus`
    (motif, cible, mode ; jamais le jeton).
  - `POST /ai/unban` → 200 `{"id", "etat": "annule" | "echu" | "deja_annule"}` ; 404 id inconnu.
  - `GET /ai/etat` → `{"actifs": [{"id", "cible", "fin", "mode"}], "compteurs": {"auto_heure", "auto_jour", "compte_heure", "compte_jour"}, "plafonds": {...}}`.
  - Toutes les routes : `user = Depends(require_ai_ban)` ; handlers `def` (pool de fils, § 6).
  - Appels : adresse ⇒ `["sudo", "-n", "/usr/sbin/wafctl", "ban", ip, f"{duree_s}s"]` ; bloc ⇒
    `["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet", "/usr/sbin/wafctl", "ban-bloc", cidr, f"{duree_s}s"]` ;
    `subprocess.run(..., check=False, timeout=30, capture_output=True, text=True)` (code lu, motif tiré de la ligne JSON ou de `refus:<motif>`).
  - Ordre de `POST /ai/ban` : forme → `deja_actif` (même cible active au journal) → durée selon le mode → plafonds →
    recontrôle `auto` (bloc seulement ; adresses de `bans()` dans le bloc ≥ 20, motifs ⊆ `{"scanners","recon_crawler"}`) →
    wafctl → journal → audit ; audit en échec ⇒ wafctl `unban`/`unban-bloc`, 500.

- [ ] **Step 1 : écrire les tests qui échouent** (précédent : `_client` de `test_enforcement.py` ; `require_ai_ban` remplacé
  par `app.dependency_overrides` sauf dans les deux tests de garde ; wafctl simulé par `monkeypatch` de `gestes_ia._executer`)

```python
def test_ban_clic_adresse_appelle_wafctl_et_audite(c): # 200 ; argv ban 198.51.100.7 86400s ; audit action "ai-ban", by "ai-ban"
def test_ban_bloc_clic_passe_par_systemd_run(c):      # argv[2] == "/usr/bin/systemd-run", "ban-bloc", "203.0.113.0/24"
def test_auto_refuse_une_adresse_seule(c):            # 409 pas_sur
def test_auto_bloc_19_adresses_refuse(c):             # 409 pas_sur
def test_auto_bloc_categorie_hors_liste_refuse(c):    # 20 adresses dont une "sqli" ⇒ 409 pas_sur ; motif "waf" ⇒ idem
def test_auto_bloc_sur_applique(c):                   # 20 × "scanners"/"recon_crawler", 86400 ⇒ 200
def test_auto_duree_plus_de_24h_refuse(c):            # 172800 ⇒ 409 duree
@pytest.mark.parametrize("cible", ["10.0.0.0/24", "203.0.113.0/23", "203.0.113.5/24", "2001:db8::1", "x"])
def test_formes_refusees_422(c, cible): ...           # 10.0.0.0/24 ⇒ 422 aussi (IPv4 non globale refusée dès la forme)
def test_duree_clic_plus_de_7j_422(c):
def test_plafond_auto_6e_refuse(c):                   # 5 bans auto < 3600 s au journal ⇒ 409 plafond_auto
def test_plafond_compte_31e_refuse(c):                # 30 bans < 3600 s ⇒ 409 plafond_compte
def test_deja_actif(c):                               # même bloc actif ⇒ 409 deja_actif, aucun appel wafctl
def test_refus_wafctl_protegee_rend_409_motif(c):     # sortie '{"ok": false, "motif": "protegee"}' ⇒ 409 protegee
def test_audit_echoue_le_ban_est_retire_et_500(c):
def test_unban_seulement_un_id_du_journal(c):         # id inconnu ⇒ 404 ; corps {"ip": ...} ⇒ 422
def test_unban_echu_idempotent(c):                    # fin passée ⇒ 200 etat "echu", aucun appel wafctl
def test_etat_rend_actifs_et_compteurs(c):
def test_routes_ai_refusent_session_admin(c_garde):   # Bearer create_token("admin") ⇒ 401
def test_post_ban_refuse_jeton_ai_ban(c_garde):       # POST /ban avec un jeton ai-ban ⇒ 401
def test_exception_rules_code_ecrite():
    t = RULES_CODE.read_text()
    assert "#3716" in t and "require_ai_ban" in t and "test_gestes_ia_3716.py" in t
def test_postinst_cree_le_dossier_des_cles_root():    # chown root:root, chmod 0755, pas de rm
def test_wafctl_cle_ai_ban_verifie_l_empreinte():     # verbe présent ; le nom du fichier posé = empreinte calculée
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `cd packages/secubox-waf-ng/composants/waf && $PY -m pytest tests/test_gestes_ia_3716.py -q` ; Expected : FAIL.

- [ ] **Step 3 : écrire `gestes_ia.py`, le branchement dans `main.py`, les verbes `cle-ai-ban`, le postinst, la ligne de `RULES-CODE.md`**

Ligne d'exception (tableau « Exceptions », § 3 garde) : `POST /ai/ban`, `POST /ai/unban`, `GET /ai/etat` (secubox-waf-ng, #3716)
| compte de service `ai-ban` par `require_ai_ban` : jeton EdDSA ≤ 60 s signé par la clé privée de la box de l'IA (jamais
sur gk2), clé publique root dans `/etc/secubox-comptes-service/ai-ban/`, `aud` = box, portée `waf-ban`, `jti` à usage
unique, empreinte du corps ; IPv4 publique ou /24 exact, durée ≤ 7 j (d'office ≤ 24 h et cas sûr recontrôlé), plafonds,
débannit ses seuls bans, audit | `packages/secubox-waf-ng/composants/waf/tests/test_gestes_ia_3716.py`.
`cle-ai-ban ajouter` : `openssl pkey -pubin -outform DER | sha256sum` ⇒ nom `<kid>.pub`, refuse au-delà de 2 clés,
`install -m 0644 -o root -g root`.

- [ ] **Step 4 : relancer toute la suite du composant** — Run : `$PY -m pytest tests -q` ; Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-waf-ng/composants/waf/api/gestes_ia.py packages/secubox-waf-ng/composants/waf/api/main.py \
        packages/secubox-waf-ng/composants/waf/scripts/wafctl packages/secubox-waf-ng/debian/postinst .claude/RULES-CODE.md \
        packages/secubox-waf-ng/composants/waf/tests/test_gestes_ia_3716.py
git commit -m "feat(waf): routes ai-ban bornées (bannir, débannir ses bans, état), clés gérées par root (ref #3716)"
```

---

### Task 5 : paquets, versions, README

**Files :**
- Modify : `packages/secubox-core/debian/changelog` (1.8.32-1~trixie1), `packages/secubox-waf-ng/debian/changelog` (1.35.0-1~trixie1),
  `packages/secubox-waf-ng/debian/control` (`secubox-core (>= 1.8.32~)`), `packages/secubox-waf-ng/README.md`,
  `packages/secubox-waf-ng/composants/waf/README.md`, `wiki/WAF-FR.md`
- Test : `packages/secubox-waf-ng/tests/test_paquet_3716.py`

**Interfaces :**
- Consumes : tâches 1 à 4.
- Produces : deux `.deb` construits ; README : routes `/ai/*` (corps, motifs), verbes `wafctl ban-bloc|unban-bloc|blocs|cle-ai-ban`,
  table `inet secubox_waf_blocs`, rotation et révocation de la clé ; wiki : section « Bans de bloc et compte ai-ban ».

- [ ] **Step 1 : test qui échoue**

```python
def test_versions_et_dependance():
    assert CHANGELOG_WAF.read_text().startswith("secubox-waf-ng (1.35.0-1~trixie1) trixie;")
    assert "secubox-core (>= 1.8.32~)" in CONTROL_WAF.read_text()
    assert CHANGELOG_CORE.read_text().startswith("secubox-core (1.8.32-1~trixie1) trixie;")
def test_rules_installe_waf_blocs_et_l_unite():
    r = RULES.read_text(); assert "waf-blocs" in r and "secubox-waf-blocs" in r
def test_readme_documente_ai_ban():
    t = README.read_text(); assert "/ai/ban" in t and "cle-ai-ban" in t and "secubox_waf_blocs" in t
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `$PY -m pytest packages/secubox-waf-ng/tests/test_paquet_3716.py -q`.

- [ ] **Step 3 : changelogs (`(ref #3716)`), control, README, wiki ; construire**

Run : `cd packages/secubox-core && dpkg-buildpackage -us -uc -b` puis `cd packages/secubox-waf-ng && dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b`.
Expected : deux `.deb` ; `dpkg -c` du paquet waf-ng contient `usr/sbin/waf-blocs`, `usr/share/secubox/waf/blocs.nft`,
`lib/systemd/system/secubox-waf-blocs.service`, `usr/lib/secubox/waf/api/gestes_ia.py` ; celui de core contient `compte_service.py`.

- [ ] **Step 4 : relancer** — `$PY -m pytest packages/secubox-waf-ng/tests/test_paquet_3716.py -q` ; `scripts/license-headers.py --check` sur les fichiers créés ; Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-core/debian/changelog packages/secubox-waf-ng/debian packages/secubox-waf-ng/README.md \
        packages/secubox-waf-ng/composants/waf/README.md wiki/WAF-FR.md packages/secubox-waf-ng/tests/test_paquet_3716.py
git commit -m "chore(waf,core): versions 1.35.0 et 1.8.32, README et wiki des bans de bloc et d'ai-ban (ref #3716)"
```

---

### Task 6 : POC — `gestes.py` (cas sûr, décision, plafonds, journal, jeton)

Le POC est **hors dépôt** et sans git : avant toute modification, copie `relais.py.avant-gestes` et
`index.html.avant-gestes` (convention du POC). Pas de commit ; l'étape 5 est la copie de sauvegarde + note.

**Files :**
- Create : `/home/reepost/poc-secubox-ai/relais/gestes.py`, `/home/reepost/poc-secubox-ai/relais/gestes.toml.exemple`
- Test : `/home/reepost/poc-secubox-ai/relais/tests/test_gestes.py`

**Interfaces :**
- Consumes : forme des données de gk2 — `/waf/bans` (`bans[].ip`, `bans[].reason`), `/waf/alerts` (`alerts[].client_ip`,
  `category`), `/waf/bans/history` (`tracked[].ip`, `top_categories[].category`) ; propositions de `filtrer_propositions`
  (`{"genre", "cible", "texte", "lien"}`, genres `bloc | ip | campagne | service`).
- Produces :
  - Constantes `SEUIL_BLOC = 20`, `CATEGORIES_SURES = frozenset({"scanners", "recon_crawler"})`, `DUREE_AUTO_S = 86400`,
    `DUREES_CLIC_S = (14400, 86400, 604800)`, `DUREE_CLIC_MAX_S = 604800`, `PLAFOND_HEURE = 5`, `PLAFOND_JOUR = 20`,
    `MODES = ("proposer", "clic", "auto")`, `JOURNAL = Path(__file__).with_name("gestes.jsonl")`,
    `REGLAGES = Path(__file__).with_name("gestes.toml")`, `CLE = Path("/etc/secubox/secrets/ai-ban/ai-ban.key")`.
  - `@dataclass(frozen=True) class Verdict` : `id: str` (SHA-256 hex[:16] de `genre|cible`), `genre`, `cible`,
    `geste: Literal["auto", "clic", "lien"]`, `sur: bool`, `raisons: tuple[str, ...]`, `duree_s: int`.
  - `lire_protegees(chemin: Path = REGLAGES) -> list[ip_network] | None` (`None` = absent ou illisible).
  - `evaluer(prop: dict, bans: list[dict], alertes: list[dict], historique: list[dict], protegees: list | None) -> Verdict`
    — ne lit que `prop["genre"]` et `prop["cible"]`.
  - `compter_auto(journal: list[dict], maintenant: float) -> tuple[int, int]`.
  - `decider(v: Verdict, mode: str, suspendu: bool, journal: list[dict], maintenant: float) -> tuple[str, str | None]`
    → `("auto" | "clic" | "lien", avis)`, avis ∈ `{None, "suspendu", "plafond_heure", "plafond_jour", "protegees_inconnues"}`.
  - `lire_journal(chemin=JOURNAL) -> list[dict]`, `ajouter_journal(entree: dict, chemin=JOURNAL) -> None` (ajout seul,
    `fsync`), `etats(journal, maintenant) -> list[dict]` (dernier état par `id_local` : `applique | refuse | annule | ignore | echu`).
  - `lire_cle(chemin=CLE) -> bytes` (refus si pas fichier ordinaire, pas au compte courant, ou mode ≠ 0600).
  - `frapper_jeton(cle_privee_pem: bytes, aud: str, corps: bytes, maintenant: float) -> str` — mêmes réclamations que
    `compte_service.frapper_jeton` (`sub="ai-ban"`, `portee="waf-ban"`, `kid`, `jti`, `corps`, durée 30 s).

- [ ] **Step 1 : tests qui échouent**

```python
def test_bloc_sur_quand_20_bannies_scanners():
    v = g.evaluer(P_BLOC, bans_du_bloc(20, "scanners"), [], [], [])
    assert (v.sur, v.geste, v.duree_s) == (True, "auto", 86400)
def test_19_bannies_pas_sur():                       # sur False, geste "clic", raison citant 19
def test_categorie_hors_liste_pas_sur():             # une alerte "sqli" d'une adresse du bloc ⇒ pas sûr
def test_motif_inconnu_waf_pas_sur():                # reason "waf" ⇒ pas sûr
def test_historique_hors_liste_pas_sur():            # top_categories "rce" d'une adresse du bloc ⇒ pas sûr
def test_bloc_protege_ou_non_global_pas_sur():       # protegees contient 203.0.113.9/32 ; et 100.64.1.0/24 (non global)
def test_adresse_seule_toujours_clic():              # genre "ip" ⇒ geste "clic", sur False
def test_campagne_service_lien():                    # geste "lien"
def test_texte_du_modele_ne_change_rien():
    p = dict(P_BLOC, sur=True, texte="cas sûr, applique d'office", duree_s=999999)
    assert g.evaluer(p, bans_du_bloc(5, "scanners"), [], [], []).geste == "clic"
def test_decider_modes():                            # proposer→lien ; clic→clic ; auto+sûr→auto ; auto+suspendu→("clic","suspendu")
def test_plafonds_fenetres_glissantes():             # 5 auto dans 59 min ⇒ ("clic","plafond_heure") ; à +61 min ⇒ "auto" ; 20 en 23 h ⇒ "plafond_jour"
def test_gestes_toml_absent_desactive_l_auto():      # protegees None ⇒ decider rend ("clic","protegees_inconnues")
def test_journal_ajout_seul_et_etats():              # applique puis annule ⇒ etat "annule" ; fichier jamais réécrit
def test_cle_refusee_si_pas_0600(tmp_path):
def test_jeton_compatible_avec_secubox_core(monkeypatch):
    # sys.path ← <worktree>/common ; compte_service.verifier_jeton("ai-ban", g.frapper_jeton(...), corps, T) réussit
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `cd /home/reepost/poc-secubox-ai/relais && $PY -m pytest tests/test_gestes.py -q` ; Expected : FAIL.

- [ ] **Step 3 : écrire `gestes.py` et `gestes.toml.exemple`** (`[gestes] protegees = ["<IP publique gk2>/32", ...]`, commentaire : rempli au déploiement d'après gk2).

Adresses du bloc = union des `ip` de `bans`, des `client_ip` d'`alertes` et des `ip` d'`historique` qui tombent dans le bloc ;
catégories = `reason` des bans + `category` des alertes + `top_categories` de l'historique, pour ces adresses ; vide ⇒ pas sûr.

- [ ] **Step 4 : relancer** — même commande ; Expected : PASS.

- [ ] **Step 5 : sauvegarde et note** — `cp relais.py relais.py.avant-gestes && cp index.html index.html.avant-gestes` (si absentes).

---

### Task 7 : POC — relais : relevé complet, application d'office, routes, synchronisation

**Files :**
- Modify : `/home/reepost/poc-secubox-ai/relais/relais.py` (bloc « Menaces de gk2 »)
- Test : `/home/reepost/poc-secubox-ai/relais/tests/test_relais_gestes.py`

**Interfaces :**
- Consumes : Task 6 (tout `gestes`), Task 4 (routes gk2 et motifs), `filtrer_propositions`, `releve_menaces`, `lire_prefs`/`ecrire_prefs`.
- Produces :
  - `DEFAUTS["gestes"] = {"mode": "auto", "suspendu": False}` (section validée par `valider` : `mode ∈ MODES`, `suspendu` booléen).
  - `releve_menaces` garde en cache la liste **complète** `bans`, `alertes` et l'historique (`/waf/bans/history?hours=24&limit=1000`).
  - Chaque proposition gardée porte `id` et `verdict` (`geste`, `sur`, `raisons`, `duree_s`, `avis`).
  - `async def appliquer_d_office(props: list[dict]) -> None` — appelée par `resumer_menaces` et `repondre_menaces` après
    `filtrer_propositions` ; un verrou `asyncio.Lock` sérialise tout geste.
  - `async def poster_gk2(chemin: str, corps: dict) -> tuple[int, dict]` — `httpx.AsyncClient` (vérification TLS normale,
    § 4), `Authorization: Bearer <frapper_jeton(...)>`, corps sérialisé une fois et signé tel quel.
  - Routes (`_local`, en-tête `X-SBX-Geste: 1` sinon 403, `Content-Type: application/json` sinon 415) :
    `GET API/menaces/gestes` → `{"mode", "suspendu", "compteurs": {"heure", "jour"}, "plafonds", "gestes": [...], "avis"}` ;
    `POST API/menaces/appliquer {"id", "duree_s"}` (`duree_s ∈ DUREES_CLIC_S`) ; `POST API/menaces/annuler {"id_local"}` ;
    `POST API/menaces/ignorer {"id"}` ; `POST API/menaces/automatique {"suspendu": bool}` ; `POST API/menaces/mode {"mode"}`.
  - Synchronisation : à chaque relevé (2 min), `GET /waf/ai/etat` ; un geste `applique` absent des actifs et échu ⇒ `echu`.
  - Traduction des réponses de gk2 : 200 ⇒ `applique` (avec `id` gk2, `fin`) ; 409 ⇒ `refuse` + motif, la carte reste un clic
    (sauf `deja_actif` ⇒ rien) ; 401/403 ⇒ avis `jeton_refuse` (non compté, pas de nouvel essai d'office avant le relevé
    suivant) ; réseau/5xx ⇒ avis `gk2_injoignable` (non compté).

- [ ] **Step 1 : tests qui échouent** (`TestClient(relais.app)` sans démarrage ; `_gk2` et `poster_gk2` simulés ; `gestes.JOURNAL` dans `tmp_path`)

```python
def test_appliquer_exige_entete_et_json(c):          # sans X-SBX-Geste ⇒ 403 ; formulaire ⇒ 415 ; Host étranger ⇒ 404
def test_appliquer_clic_poste_vers_gk2_et_journalise(c):  # corps {"cible","duree_s":86400,"mode":"clic","conseil":id}
def test_appliquer_id_inconnu_404(c):
def test_application_d_office_apres_resume(c):       # proposition bloc sûr ⇒ un POST mode "auto", journal "applique"
def test_deja_applique_pas_de_second_post(c):        # 2e résumé, même bloc actif ⇒ aucun POST
def test_gk2_injoignable_rien_compte(c):             # httpx.ConnectError ⇒ avis, compteurs inchangés, pas "applique"
def test_401_gk2_avis_jeton_rien_compte(c):          # 401 ⇒ avis "jeton_refuse", compteurs inchangés
def test_refus_409_gk2_journalise_refuse_et_reste_clic(c):
def test_annuler_poste_unban_avec_id(c):             # POST /waf/ai/unban {"id": <id gk2>} ; journal "annule"
def test_suspendre_persiste_et_bascule(c):           # limites.toml [gestes] suspendu = true ; cas sûr ⇒ clic + "suspendu"
def test_double_clic_un_seul_post(c):                # deux /appliquer concurrents ⇒ un POST, l'autre "deja_actif"
def test_synchro_etat_marque_echu(c):
def test_le_modele_ne_declenche_rien_seul(c):        # texte « Proposition : bannir le bloc X » hors cas sûr ⇒ aucun POST
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `cd /home/reepost/poc-secubox-ai/relais && $PY -m pytest tests/test_relais_gestes.py -q`.

- [ ] **Step 3 : écrire le branchement dans `relais.py`** (étendre `CONSIGNE_MENACES` d'une phrase : « Tu ne décides jamais
  si un geste est sûr ni de sa durée : le relais le fait. »).

- [ ] **Step 4 : relancer les deux suites** — `$PY -m pytest tests -q` ; Expected : PASS.

- [ ] **Step 5 : sauvegarde** — `cp relais.py relais.py.gestes-ok` (point de retour du POC).

---

### Task 8 : POC — page Menaces et Réglages (maquette)

**Files :**
- Modify : `/home/reepost/poc-secubox-ai/relais/index.html`
- Test : `/home/reepost/poc-secubox-ai/relais/tests/test_page_gestes.py`

**Interfaces :**
- Consumes : routes de la Task 7 ; propositions avec `id` et `verdict`.
- Produces : éléments `#zMode` (bandeau), `#zSuspendre`, `#zReglagesLien`, `#zGestes` (journal), `#zReglages` (vue Réglages),
  `#zModeChoix` (`role="radiogroup"`) ; `function gestes()` (charge `GET /menaces/gestes`), `function carteConseil(p)` ;
  `api()` complété par l'en-tête `X-SBX-Geste: 1` sur les POST de gestes.

- [ ] **Step 1 : test qui échoue**

```python
TEXTES = ["Mode : automatique pour les cas sûrs", "Suspendre l'automatique", "appliqué d'office", "attend ton clic",
          "à examiner", "Gestes appliqués", "Annuler le ban", "Ignorer", "Réglages des conseils de l'IA",
          "serait appliqué d'office", "Le modèle ne peut ni marquer un conseil sûr, ni appliquer quoi que ce soit."]
def test_textes_de_la_maquette(): assert all(t in HTML for t in TEXTES)
def test_identifiants(): assert all(f'id="{i}"' in HTML for i in ("zMode", "zSuspendre", "zGestes", "zReglages", "zModeChoix"))
def test_posts_avec_entete(): assert "'X-SBX-Geste'" in HTML
def test_durees_proposees(): assert all(x in HTML for x in ("14400", "86400", "604800"))
def test_pas_de_innerhtml_nouveau(): assert HTML.count("innerHTML") == AVANT.count("innerHTML")   # AVANT = index.html.avant-gestes
```

- [ ] **Step 2 : lancer, constater l'échec** — Run : `$PY -m pytest tests/test_page_gestes.py -q`.

- [ ] **Step 3 : écrire la page** : bandeau (vert actif, orange suspendu ou plafond, compteur « N utilisés » sur 5), cartes
  (trois styles de la maquette ; « fin prévue … · audit gk2 n° <id> » ; `Appliquer · 24 h` + choix 4 h / 24 h / 7 jours),
  colonne « Gestes appliqués », vue Réglages (trois modes, tableau par type, garde-fous en liste, textes de la maquette).

- [ ] **Step 4 : relancer, puis contrôle visuel** — tests PASS ; ouvrir `http://127.0.0.1:8098/`, onglet Menaces, à 1280 px et à 390 px (pas de défilement horizontal).

- [ ] **Step 5 : sauvegarde** — `cp index.html index.html.gestes-ok`.

---

### Task 9 : banc gk6 — exécuté par le CONTRÔLEUR (pas par un sous-agent)

**Files :** aucun dans le dépôt ; constats notés pour `HISTORY.md` (Task 10).

**Interfaces :** Consumes : `.deb` de la Task 5 ; POC des tâches 6 à 8. Produces : un banc vert ou une liste de défauts.

Choix de Claude : le banc installe les `.deb` **sans les publier** (`apt-get install ./secubox-core_….deb ./secubox-waf-ng_….deb`
sur gk6, sans `timeout`) — publier dans `apt.secubox.in` mettrait le code devant tout le parc avant le banc.

- [ ] **Step 1 : installer sur gk6** (192.168.1.2) ; attendre `/health` 200 de l'agrégateur ; `systemctl is-active secubox-waf-blocs`.
- [ ] **Step 2 : blocs en root** : `wafctl ban-bloc 203.0.113.0/24 1h` ⇒ `nft list set inet secubox_waf_blocs blocs4` montre l'élément ;
  `systemctl reload nftables` ⇒ élément revenu (temps restant) ; `systemctl restart secubox-waf-ng` ⇒ table intacte ;
  refus : `10.0.0.0/24` (privee), une plage de `protegees.env` (protegee), le /24 d'une adresse d'interface (box), d'un point de
  terminaison WireGuard (pair) ; `wafctl unban-bloc 203.0.113.0/24`.
- [ ] **Step 3 : clé** : sur gk0, paire de banc dans le scratchpad ; sur gk6 `wafctl cle-ai-ban ajouter` ; jeton de banc avec `aud="gk6"`.
- [ ] **Step 4 : routes** par `https://admin.gk6…/api/v1/waf/ai/*` depuis gk0 : un clic (adresse 198.51.100.7 1 h, bloc
  203.0.113.0/24 4 h), annulation, `auto` refusé hors cas sûr (`pas_sur`), plafonds (6e auto ⇒ `plafond_auto`), rejeu
  (même jeton ⇒ 401), mauvaise audience (`aud="gk2"` ⇒ 403), jeton admin sur `/ai/ban` ⇒ 401, jeton `ai-ban` sur
  `POST /ban` ⇒ 401 ; lignes `ai-ban`/`ai-unban`/`ai-ban-refus` dans `audit.log`.
- [ ] **Step 5 : relais pointé sur gk6** (`MENACES_SRC`, `aud`) : cas sûr simulé par 20 bans manuels `wafctl ban 203.0.113.N 1h`
  aux motifs de banc — vérifier d'office, suspension, plafond, page. `journalctl -k | grep -i apparmor.*DENIED` vide.
  Retirer la clé de banc de gk6 (`cle-ai-ban retirer --toutes`). Banc vert ⇒ Task 10 ; sinon retour aux tâches.

---

### Task 10 : déploiement gk2 et gk0 — exécuté par le CONTRÔLEUR ; automatique laissé SUSPENDU

**Files :** `.claude/HISTORY.md`, `.claude/WIP.md`, `packages/secubox-waf-ng/README.md` (si constat), POC `relais/gestes.toml`, `relais/limites.toml`.

**Interfaces :** Consumes : banc vert (Task 9). Produces : gk2 à jour, `ai-ban` provisionné, relais du POC relié, automatique suspendu.

- [ ] **Step 1 : publier** : `scripts/apt-publier.sh secubox-core_1.8.32-1~trixie1_all.deb secubox-waf-ng_1.35.0-1~trixie1_arm64.deb`.
- [ ] **Step 2 : gk2** : `df -h /` (garde d'espace) ; `apt-get update && apt-get install secubox-core secubox-waf-ng` dans une
  unité `systemd-run --unit=montee-3716 --collect`, sans `timeout`, attendre la fin ; **un seul** redémarrage de l'agrégateur,
  attendre `/health` 200 ; `systemctl is-active secubox-waf-blocs` ; `nft list table inet secubox_waf_blocs`.
- [ ] **Step 3 : protégées** : relever sur gk2 `cat /etc/secubox/waf/protegees.env`, l'adresse publique, `wg show all endpoints` ;
  les reporter dans `relais/gestes.toml` sur gk0 ; compléter `protegees.env` de gk2 s'il manque l'adresse publique (par le
  propriétaire ou avec son accord).
- [ ] **Step 4 : clé de production** : sur gk0 `sudo install -d -m 0700 -o reepost -g reepost /etc/secubox/secrets/ai-ban`, paire
  Ed25519 générée **dans** ce dossier (privée 0600, jamais copiée ailleurs) ; `.pub` copiée sur gk2 puis
  `sudo wafctl cle-ai-ban ajouter /tmp/ai-ban.pub` et suppression de la copie temporaire.
- [ ] **Step 5 : POC** : `relais/limites.toml` `[gestes] mode = "auto"`, **`suspendu = true`** ; `systemctl --user restart poc-relais`.
- [ ] **Step 6 : essai unique sur gk2** : un clic sur `203.0.113.0/24` 1 h depuis la page (plage de documentation), carte et journal
  corrects, ligne `ai-ban` dans `audit.log` de gk2, puis « Annuler le ban » et ligne `ai-unban`. Rien d'autre sur gk2.
- [ ] **Step 7 : suivi** : entrée datée dans `HISTORY.md` (sans `closes`), `WIP.md` (« automatique suspendu, en attente du go
  du propriétaire »), commentaire sur #3716 ; commit `docs(suivi): …  (ref #3716)` ; push.
- [ ] **Step 8 : go du propriétaire** : c'est lui qui clique « Relancer » ; après une journée sans anomalie, `closes #3716`
  dans `HISTORY.md` puis `scripts/sync-issues.sh`.

---

## Note pour le portage dans secubox-ai (#3583, étape ultérieure)

- `gestes.py` du POC devient `packages/secubox-ai/api/gestes.py` **tel quel** (fonctions pures + journal) ; son
  `frapper_jeton` est remplacé par `secubox_core.compte_service.frapper_jeton` (secubox-ai dépend de secubox-core ≥ 1.8.32).
- Clé privée : `/etc/secubox/secrets/ai/ai-ban.key`, `secubox-ai:secubox-ai` 0600, créée par `secubox-aictl` (root) au premier
  usage ; jamais dans un TOML. Rotation : nouvelle paire sur gk3, `cle-ai-ban ajouter` sur gk2, bascule, retrait de l'ancienne
  (celle de gk0 est retirée le jour où gk3 prend le relais).
- Routes : celles de la Task 7 sous `/api/v1/ai/menaces/*`, gardées par `require_jwt` (administrateur réel) au lieu de `_local`
  et `X-SBX-Geste` ; réglages `mode`/`suspendu` dans le TOML de secubox-ai par double tampon ; journal des gestes dans
  `/var/lib/secubox-ai/gestes.jsonl` et chaque geste aussi dans l'`audit.log` local.
- Appels à gk2 : `httpx.AsyncClient` avec la CA normale ; `aud` lu de la configuration (nom de la box cible), pas en dur.
- Profil AppArmor de l'API secubox-ai : lecture de la clé, réseau sortant vers gk2 seulement.
- Les tests `test_gestes.py`, `test_relais_gestes.py`, `test_page_gestes.py` sont repris et adaptés (gardes `require_jwt`).

## Auto-relecture

- **Couverture de la spec** : bloc nft + persistance (T2), gardes box/LAN/pair (T1), compte `ai-ban` + rotation/révocation
  (T3, T4), routes bornées + plafonds serveur + recontrôle auto (T4), exception RULES-CODE (T4), paquets/README (T5), cas sûr,
  plafonds, journal, suspension (T6, T7), page (T8), banc (T9), déploiement automatique suspendu (T10), IPv6 exclu (Global
  Constraints, tests 422 de T4), portage (note). Aucun manque relevé.
- **Cohérence des noms** : `normaliser_bloc`, `motif_refus`, `GardeIllisible` (T1→T2) ; `require_ai_ban`, `frapper_jeton` (T3→T4, T6) ;
  motifs 409 de T4 repris tels quels en T7 ; `DUREES_CLIC_S = (14400, 86400, 604800)` en T6 et T8.
- **Review Focus** : chaque ligne a son test, nommé dans la tâche qui possède le code.
- **Proportion** : signatures, valeurs et assertions ; aucun corps de fonction recopié hors l'ordre des contrôles, que les tests seuls ne fixent pas.
