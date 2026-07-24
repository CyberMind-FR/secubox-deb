import subprocess, os, json, stat, shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def _run(env, *args):
    return subprocess.run(["bash", str(ROOT/"sbin/torctl"), *args],
                          capture_output=True, text=True, env=env)

def _make_share(tmp_path):
    """Reproduit le flatten fait par le packaging : les 3 templates réels du
    dépôt copiés à plat dans un seul répertoire, comme torctl les référence
    via $SHARE/<nom>."""
    share = tmp_path / "share"
    share.mkdir()
    shutil.copy(ROOT / "conf/torrc.d/60-secubox-transparent.conf",
                share / "60-secubox-transparent.conf")
    shutil.copy(ROOT / "conf/unbound/secubox-onion-forward.conf",
                share / "secubox-onion-forward.conf")
    shutil.copy(ROOT / "nft.d/secubox-tor-transparent.nft",
                share / "secubox-tor-transparent.nft")
    return share

def _base_env(tmp_path, share):
    torrc = tmp_path/"torrc.d"; torrc.mkdir(exist_ok=True)
    (tmp_path/"u").mkdir(exist_ok=True); (tmp_path/"n").mkdir(exist_ok=True)
    return {**os.environ,
            "TORCTL_TORRC_D": str(torrc),
            "TORCTL_UNBOUND_D": str(tmp_path/"u"),
            "TORCTL_NFT_D": str(tmp_path/"n"),
            "TORCTL_SHARE_D": str(share),
            "TORCTL_DRYRUN": "1"}, torrc

def test_on_skips_transport_dropin_when_one_already_exists(tmp_path):
    share = _make_share(tmp_path)
    env, torrc = _base_env(tmp_path, share)
    (torrc/"torrc-toolbox-egress.conf").write_text("TransPort 127.0.0.1:9040\nDNSPort 127.0.0.1:9053\n")
    r = _run(env, "transparent", "on")
    assert r.returncode == 0, r.stderr
    assert not (torrc/"60-secubox-transparent.conf").exists(), "ne doit pas dupliquer TransPort"
    # les autres templates (non concernés par l'invariant TransPort) sont
    # toujours posés — preuve que la copie réelle a bien eu lieu
    assert (tmp_path/"u"/"secubox-onion-forward.conf").exists()
    assert (tmp_path/"n"/"secubox-tor-transparent.nft").exists()

def test_on_installs_transport_dropin_when_none_exists(tmp_path):
    share = _make_share(tmp_path)
    env, torrc = _base_env(tmp_path, share)
    r = _run(env, "transparent", "on")
    assert r.returncode == 0, r.stderr
    assert (torrc/"60-secubox-transparent.conf").exists(), \
        "sans TransPort préexistant, torctl DOIT poser son propre dropin"
    assert "TransPort 127.0.0.1:9040" in (torrc/"60-secubox-transparent.conf").read_text()

def test_off_removes_only_our_files(tmp_path):
    share = _make_share(tmp_path)
    env, torrc = _base_env(tmp_path, share)
    ext = torrc/"torrc-toolbox-egress.conf"; ext.write_text("TransPort 127.0.0.1:9040\n")
    (torrc/"60-secubox-transparent.conf").write_text("x")
    _run(env, "transparent", "off")
    assert not (torrc/"60-secubox-transparent.conf").exists()
    assert ext.exists(), "off ne doit jamais retirer le dropin d'un autre paquet"

def test_on_installs_dropin_when_transport_exists_but_dnsport_missing(tmp_path):
    share = _make_share(tmp_path)
    env, torrc = _base_env(tmp_path, share)
    # TransPort seul, SANS DNSPort : ne doit PAS être traité comme "déjà
    # déclaré", sinon Unbound forwarderait vers un DNSPort inexistant.
    (torrc/"torrc-toolbox-egress.conf").write_text("TransPort 127.0.0.1:9040\n")
    r = _run(env, "transparent", "on")
    assert r.returncode == 0, r.stderr
    assert (torrc/"60-secubox-transparent.conf").exists(), \
        "TransPort sans DNSPort ne doit pas être réutilisé — notre dropin doit être posé"

def test_detects_transport_bound_without_ip(tmp_path):
    share = _make_share(tmp_path)
    env, torrc = _base_env(tmp_path, share)
    (torrc/"torrc-toolbox-egress.conf").write_text("TransPort 9040\nDNSPort 127.0.0.1:9053\n")
    r = _run(env, "transparent", "on")
    assert r.returncode == 0, r.stderr
    assert not (torrc/"60-secubox-transparent.conf").exists(), \
        "TransPort 9040 sans IP explicite doit aussi être détecté (déjà déclaré)"
