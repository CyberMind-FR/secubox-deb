"""jitsictl — the confined ctl the WebUI delegates to (#985).

The 1.0.0 module drove docker/podman straight from the FastAPI request path.
This pins the replacement's contract, and in particular the two places where a
value coming from a request reaches a privileged action: the public address
(written into a properties file a service reads) and the unit name (passed to
`systemctl` inside the container). Both are validated here rather than trusted.

Also pinned: `status` reports the four Jitsi services SEPARATELY. A Jitsi
deployment fails in ways that are distinguishable — prosody down means nobody
connects, jicofo down means people connect but no conference forms, the
videobridge down means the conference forms and stays silent. Collapsing that
into one boolean would discard exactly the signal that tells you where to look.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "jitsictl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _mock_lxc(tmp_path: Path, capture: Path, state: str = "RUNNING") -> None:
    _write_exec(tmp_path / "lxc-info", f"""#!/bin/bash
echo "State: {state}"
exit 0
""")
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
# Record everything after `-n <name> -P <path> --`, one invocation per line.
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-P) shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
printf '%s\\n' "$*" >> "{capture}"
# `systemctl is-active` is called for each service by `status`.
case "$*" in
  *"is-active"*) echo "active" ;;
esac
exit 0
""".format(capture=capture))
    # curl: status probes the web tier. Fail fast so the test needs no network.
    _write_exec(tmp_path / "curl", "#!/bin/bash\nexit 7\n")


def _env(tmp_path, conf, state_dir):
    return {
        "PATH": "{}:/usr/bin:/bin:/usr/sbin:/sbin".format(tmp_path),
        "SECUBOX_JITSI_CONFIG": str(conf),
        "SECUBOX_JITSI_STATE_DIR": str(state_dir),
        "SECUBOX_LXC_PATH": str(tmp_path / "lxc"),
    }


def _setup(tmp_path, container=True):
    conf = tmp_path / "jitsi.toml"
    conf.write_text('lxc_name = "jitsi"\nlxc_ip = "10.100.0.190"\n'
                    'domain = "meet.example.com"\njvb_port = 10000\nweb_port = 80\n')
    state_dir = tmp_path / "state"; state_dir.mkdir()
    if container:
        (tmp_path / "lxc" / "jitsi" / "rootfs").mkdir(parents=True)
    return conf, state_dir


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def test_status_reports_each_service_separately(tmp_path):
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    r = _run(["status"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)

    assert data["container"] == "running"
    assert set(data["services"]) == {"prosody", "jicofo", "videobridge", "web"}
    assert data["services"]["videobridge"] == "active"
    assert data["media"]["udp_port"] == 10000
    # No public address recorded yet — the field must say so rather than being
    # absent, because "media will not traverse NAT" is a diagnosis, not a gap.
    assert data["media"]["public_address_set"] is False


def test_status_on_a_stopped_container_does_not_report_services_as_dead(tmp_path):
    """A stopped container is one fact, not four failures. Reporting
    'inactive' per service would read as four broken daemons."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture, state="STOPPED")

    r = _run(["status"], _env(tmp_path, conf, state_dir))
    data = json.loads(r.stdout)
    assert data["container"] == "stopped"
    assert data["services"]["prosody"] == "container-down"


def test_set_public_ip_rejects_a_non_address(tmp_path):
    """This value is written into a properties file a service parses. A
    rejected string must never reach it."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    for bad in ["", "not-an-ip", "1.2.3", "1.2.3.4.5",
                "$(id)", "10.0.0.1; systemctl stop prosody"]:
        r = _run(["set-public-ip", bad], _env(tmp_path, conf, state_dir))
        assert r.returncode == 2, f"{bad!r} accepted (rc={r.returncode})"
        assert not (state_dir / "public-ip").exists(), f"{bad!r} was recorded"


def test_set_public_ip_rejects_an_out_of_range_octet(tmp_path):
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    r = _run(["set-public-ip", "10.0.0.999"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 2, r.stdout
    assert not (state_dir / "public-ip").exists()


def test_set_public_ip_records_and_applies_a_valid_address(tmp_path):
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    r = _run(["set-public-ip", "82.67.100.75"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["public_address"] == "82.67.100.75"
    assert (state_dir / "public-ip").read_text().strip() == "82.67.100.75"

    captured = capture.read_text()
    assert "NAT_HARVESTER_PUBLIC_ADDRESS" in captured
    assert "NAT_HARVESTER_LOCAL_ADDRESS" in captured, (
        "the local address must be declared alongside the public one — behind "
        "two NATs the bridge needs both")
    assert "restart jitsi-videobridge2" in captured


def test_service_restart_refuses_a_unit_outside_the_allow_list(tmp_path):
    """The unit name reaches `systemctl` inside the container. Only the four
    services this module owns are addressable through it."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    for bad in ["sshd", "", "prosody nginx", "prosody;reboot"]:
        r = _run(["service-restart", bad], _env(tmp_path, conf, state_dir))
        assert r.returncode == 2, f"{bad!r} accepted"
    captured = capture.read_text() if capture.exists() else ""
    assert "restart" not in captured, captured


def test_service_restart_accepts_an_owned_unit(tmp_path):
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    r = _run(["service-restart", "jicofo"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["success"] is True
    assert "systemctl restart jicofo" in capture.read_text()


def test_logs_refuses_a_unit_outside_the_allow_list(tmp_path):
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)

    r = _run(["logs", "sshd"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 2


def test_start_on_a_missing_container_fails_cleanly(tmp_path):
    conf, state_dir = _setup(tmp_path, container=False)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture, state="")

    r = _run(["start"], _env(tmp_path, conf, state_dir))
    assert r.returncode == 1
    assert json.loads(r.stdout)["success"] is False


def _mock_nft(tmp_path: Path, capture: Path, ok: bool = True) -> None:
    _write_exec(tmp_path / "nft", """#!/bin/bash
printf '%s\\n' "$*" >> "{capture}"
exit {rc}
""".format(capture=capture, rc=0 if ok else 1))


def test_media_expose_without_argument_reports_without_changing_anything(tmp_path):
    """Un verbe d'exposition doit pouvoir etre INTERROGE sans risque. Sans
    argument il rapporte l'etat et ne touche ni au fichier ni aux regles."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)
    _mock_nft(tmp_path, capture)
    dst = tmp_path / "nftables.d" / "secubox-jitsi-dnat.nft"

    env = _env(tmp_path, conf, state_dir)
    env["SECUBOX_JITSI_NFT_DST"] = str(dst)
    r = _run(["media-expose"], env)

    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["file_installed"] is False
    assert data["udp_port"] == 10000
    assert not dst.exists(), "l'interrogation ne doit rien installer"


def test_media_expose_apply_installs_the_packaged_rule(tmp_path):
    """La regle est EMPAQUETEE, pas ecrite ici : ce verbe la depose ou nftables
    la charge au demarrage. Sans ca, la regle vit a la main sur la board et
    disparait sans que personne le voie — la derive meme que ce depot passe
    son temps a reparer."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)
    _mock_nft(tmp_path, capture)
    src = tmp_path / "jitsi.nft"
    src.write_text("table inet secubox-jitsi {}\n")
    dst = tmp_path / "nftables.d" / "secubox-jitsi-dnat.nft"

    env = _env(tmp_path, conf, state_dir)
    env["SECUBOX_JITSI_NFT_SRC"] = str(src)
    env["SECUBOX_JITSI_NFT_DST"] = str(dst)
    r = _run(["media-expose", "--apply"], env)

    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["success"] is True
    assert dst.exists(), "la regle empaquetee doit etre deposee"
    assert dst.read_text() == src.read_text(), "le contenu doit venir du paquet"


def test_media_expose_apply_leaves_nothing_behind_when_nft_refuses(tmp_path):
    """Une regle refusee par nft ne doit pas rester sur le disque : au prochain
    demarrage elle serait rechargee et echouerait de nouveau, silencieusement."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)
    _mock_nft(tmp_path, capture, ok=False)
    src = tmp_path / "jitsi.nft"
    src.write_text("table inet secubox-jitsi {}\n")
    dst = tmp_path / "nftables.d" / "secubox-jitsi-dnat.nft"

    env = _env(tmp_path, conf, state_dir)
    env["SECUBOX_JITSI_NFT_SRC"] = str(src)
    env["SECUBOX_JITSI_NFT_DST"] = str(dst)
    r = _run(["media-expose", "--apply"], env)

    assert r.returncode == 1
    assert not dst.exists(), "un echec ne doit rien laisser derriere lui"


def test_media_expose_apply_is_idempotent(tmp_path):
    """`nft -f` AJOUTE les regles, il ne remplace pas la table : sans
    suppression prealable, un second --apply empile une DNAT identique.
    Mesure sur la board avant correctif : deux regles pour un seul appel de
    trop. Inoffensif pour le trafic (la premiere gagne) mais le compteur
    devient illisible — et c'est lui qui sert a diagnostiquer un media qui ne
    passe pas."""
    conf, state_dir = _setup(tmp_path)
    capture = tmp_path / "cap.txt"
    _mock_lxc(tmp_path, capture)
    nft_calls = tmp_path / "nft.txt"
    _mock_nft(tmp_path, nft_calls)
    src = tmp_path / "jitsi.nft"
    src.write_text("table inet secubox-jitsi {}\n")
    dst = tmp_path / "nftables.d" / "secubox-jitsi-dnat.nft"

    env = _env(tmp_path, conf, state_dir)
    env["SECUBOX_JITSI_NFT_SRC"] = str(src)
    env["SECUBOX_JITSI_NFT_DST"] = str(dst)
    _run(["media-expose", "--apply"], env)

    calls = nft_calls.read_text()
    assert "delete table inet secubox-jitsi" in calls, (
        "la table doit etre supprimee avant rechargement, sinon --apply empile"
    )
    assert calls.index("delete table") < calls.index("-f "), (
        "la suppression doit preceder le chargement"
    )
