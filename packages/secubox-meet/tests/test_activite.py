# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3182 — activité de la visio : sessions tirées du journal de LiveKit, réunions, en direct, statistiques."""
import base64
import hashlib
import hmac
import json

import pytest

from api import activite as A

T0 = 1793002354  # 26/10/2026 08:12:34 UTC (journal de gk1)
SALLE = "2c8ef9e1-ba03-407e-b506-339c292c7573"
GANDALF = "4fef80d3-ebdd-431d-b225-a6d30cdeca8e"
INVITE = "a4fe2f07-8901-4fed-9afc-ae4d7497f334"
FIREFOX = {"sdk": "JS", "os": "Linux", "deviceModel": "Other", "browser": "Firefox", "browserVersion": "156.0"}
SAFARI = {"sdk": "JS", "os": "iOS", "deviceModel": "iPhone", "browser": "Safari", "browserVersion": "26.0"}
N = [0]


def entree(ts, evenement, champs, fichier="rtc/room.go:1284"):
    """Une entrée de `journalctl -o json` telle que LiveKit l'écrit (horodatage en µs, message tabulé + JSON)."""
    N[0] += 1
    iso = "2026-10-26T08:12:34.917Z"
    return json.dumps({"__CURSOR": f"s=abc;i={N[0]:x}", "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000)),
                       "MESSAGE": f"{iso}\tINFO\tlivekit\t{fichier}\t{evenement}\t" + json.dumps(champs)})


def debut(ts, sid, ident=GANDALF, salle=SALLE):
    return entree(ts, "starting RTC session", {"room": salle, "participant": ident, "participantID": sid, "numParticipants": 0},
                  "service/roommanager.go:433")


def actif(ts, sid, ident=GANDALF, salle=SALLE, transport="udp", client=FIREFOX):
    return entree(ts, "participant active", {"room": salle, "participant": ident, "participantID": sid, "connectionType": transport,
                                             "clientInfo": client, "connectTime": "131ms",
                                             "publisherCandidates": ["udp4 host 192.0.2.10:51000"]})


def fin(ts, sid, raison="CLIENT_INITIATED", ident=GANDALF, salle=SALLE, reprise=False, pays="FR", client=FIREFOX):
    return entree(ts, "participant closing", {"room": salle, "participant": ident, "participantID": sid, "reason": raison,
                                              "isExpectedToResume": reprise, "clientInfo": client, "country": pays,
                                              "sessionDuration": "1m0s"}, "rtc/participant.go:1550")


def sans_connexion(ts, sid, ident=GANDALF, salle=SALLE):
    return entree(ts, "removing participant without connection", {"room": salle, "participant": ident, "participantID": sid,
                                                                    "connectionType": "unknown", "reason": "SIGNAL_SOURCE_CLOSE"})


@pytest.fixture
def base(tmp_path):
    cx = A.ouvrir(tmp_path / "activite.db")
    yield cx, tmp_path / "activite.db"
    cx.close()


def sessions(cx):
    return {r["sid"]: r for r in A.historique(cx, jours=3650, maintenant=T0 + 86400)}


# ── Lignes réelles du journal de gk1 (2026-10-26), adresses retirées ────────────────────────────────────────────────────
REELLES = [
    '{"__CURSOR": "s=b100;i=344", "__REALTIME_TIMESTAMP": "1793002354918148", "MESSAGE": "2026-10-26T08:12:34.917Z\\tINFO\\tlivekit\\tservice/roommanager.go:433\\tstarting RTC session\\t{\\"room\\": \\"2c8ef9e1-ba03-407e-b506-339c292c7573\\", \\"roomID\\": \\"RM_HTBMqEaJA2cz\\", \\"participant\\": \\"4fef80d3-ebdd-431d-b225-a6d30cdeca8e\\", \\"participantID\\": \\"PA_x4zWiiLFSExP\\", \\"remote\\": false, \\"nodeID\\": \\"ND_4HuA4VvnpqcJ\\", \\"numParticipants\\": 0}"}',
    '{"__CURSOR": "s=b100;i=346", "__REALTIME_TIMESTAMP": "1793002370170459", "MESSAGE": "2026-10-26T08:12:50.169Z\\tINFO\\tlivekit\\trtc/participant.go:1550\\tparticipant closing\\t{\\"room\\": \\"2c8ef9e1-ba03-407e-b506-339c292c7573\\", \\"roomID\\": \\"RM_HTBMqEaJA2cz\\", \\"participant\\": \\"4fef80d3-ebdd-431d-b225-a6d30cdeca8e\\", \\"participantID\\": \\"PA_x4zWiiLFSExP\\", \\"remote\\": false, \\"sendLeave\\": false, \\"reason\\": \\"SIGNAL_SOURCE_CLOSE\\", \\"isExpectedToResume\\": false, \\"clientInfo\\": {\\"sdk\\": \\"JS\\", \\"os\\": \\"Linux\\", \\"deviceModel\\": \\"Other\\", \\"browser\\": \\"Firefox\\", \\"browserVersion\\": \\"156.0\\"}, \\"kind\\": \\"STANDARD\\", \\"country\\": \\"\\", \\"sessionDuration\\": \\"0s\\"}"}',
    '{"__CURSOR": "s=b100;i=348", "__REALTIME_TIMESTAMP": "1793002370176669", "MESSAGE": "2026-10-26T08:12:50.175Z\\tINFO\\tlivekit\\trtc/room.go:1465\\tremoving participant without connection\\t{\\"room\\": \\"2c8ef9e1-ba03-407e-b506-339c292c7573\\", \\"roomID\\": \\"RM_HTBMqEaJA2cz\\", \\"participant\\": \\"4fef80d3-ebdd-431d-b225-a6d30cdeca8e\\", \\"participantID\\": \\"PA_x4zWiiLFSExP\\", \\"remote\\": false, \\"connectionType\\": \\"unknown\\", \\"reason\\": \\"SIGNAL_SOURCE_CLOSE\\"}"}',
    '{"__CURSOR": "s=b100;i=3be", "__REALTIME_TIMESTAMP": "1793002923506691", "MESSAGE": "2026-10-26T08:22:03.506Z\\tINFO\\tlivekit\\trtc/room.go:1284\\tparticipant active\\t{\\"room\\": \\"2c8ef9e1-ba03-407e-b506-339c292c7573\\", \\"roomID\\": \\"RM_Ngh6MNWEUCZD\\", \\"participant\\": \\"4fef80d3-ebdd-431d-b225-a6d30cdeca8e\\", \\"participantID\\": \\"PA_jRbmTtB87TxV\\", \\"remote\\": false, \\"connectionType\\": \\"udp\\", \\"clientInfo\\": {\\"sdk\\": \\"JS\\", \\"os\\": \\"Linux\\", \\"deviceModel\\": \\"Other\\", \\"browser\\": \\"Firefox\\", \\"browserVersion\\": \\"156.0\\"}, \\"connectTime\\": \\"131.124254ms\\"}"}',
]


def test_lignes_reelles_un_echec_puis_une_session_en_cours(base):
    cx, _ = base
    assert A.collecter(cx, REELLES) == 4
    s = sessions(cx)
    assert s["PA_x4zWiiLFSExP"]["issue"] == "echec" and s["PA_x4zWiiLFSExP"]["motif"] == "aucun chemin média"
    assert s["PA_jRbmTtB87TxV"]["issue"] == "en_cours" and s["PA_jRbmTtB87TxV"]["transport"] == "UDP"
    assert s["PA_jRbmTtB87TxV"]["appareil"] == "Linux · Firefox"
    assert A.curseur(cx) == "s=b100;i=3be"


def test_session_aboutie_duree_motif_pays_et_aucune_adresse(base):
    cx, chemin = base
    A.collecter(cx, [debut(T0, "PA_1"), actif(T0 + 2, "PA_1"), fin(T0 + 602, "PA_1")])
    s = sessions(cx)["PA_1"]
    assert (s["issue"], s["motif"], s["duree"], s["pays"]) == ("aboutie", "a quitté", 600, "FR")
    assert b"192.0.2.10" not in chemin.read_bytes()                      # les candidats ICE ne sont jamais lus


@pytest.mark.parametrize("raison,motif", [("DUPLICATE_IDENTITY", "rejoint ailleurs"), ("SIGNAL_SOURCE_CLOSE", "connexion perdue"),
                                          ("ROOM_DELETED", "réunion close"), ("INCONNUE_X", "inconnue x"),
                                          # noms réels relevés sur gk1 le 2026-10-26
                                          ("CLIENT_REQUEST_LEAVE", "a quitté"), ("PEER_CONNECTION_DISCONNECTED", "connexion perdue"),
                                          ("SERVICE_REQUEST_DELETE_ROOM", "réunion close"),
                                          ("SERVICE_REQUEST_REMOVE_PARTICIPANT", "retiré")])
def test_motifs_de_fin(base, raison, motif):
    cx, _ = base
    A.collecter(cx, [debut(T0, "PA_2"), actif(T0 + 1, "PA_2"), fin(T0 + 61, "PA_2", raison)])
    assert sessions(cx)["PA_2"]["motif"] == motif


def test_une_fermeture_avec_reprise_n_est_pas_une_fin(base):
    cx, _ = base
    A.collecter(cx, [debut(T0, "PA_3"), actif(T0 + 1, "PA_3"), fin(T0 + 30, "PA_3", "SIGNAL_SOURCE_CLOSE", reprise=True)])
    assert sessions(cx)["PA_3"]["issue"] == "en_cours"


def test_fermeture_sans_activite_et_sans_retrait_est_un_abandon(base):
    cx, _ = base
    A.collecter(cx, [debut(T0, "PA_4"), fin(T0 + 1, "PA_4", "CLIENT_INITIATED")])
    s = sessions(cx)["PA_4"]
    assert s["issue"] == "abandon" and s["duree"] == 0


def test_relire_les_memes_lignes_ne_compte_rien_deux_fois(base):
    cx, _ = base
    lignes = [debut(T0, "PA_5"), actif(T0 + 1, "PA_5"), fin(T0 + 121, "PA_5")]
    A.collecter(cx, lignes)
    A.collecter(cx, lignes)
    assert len(sessions(cx)) == 1 and sessions(cx)["PA_5"]["duree"] == 120


def test_lignes_etrangeres_ou_mal_formees_ignorees(base):
    cx, _ = base
    autres = ["pas du json", json.dumps({"MESSAGE": "texte libre", "__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1"}),
              json.dumps({"MESSAGE": "2026\tINFO\tlivekit\tx.go\tparticipant active\t{pas du json", "__CURSOR": "c2",
                          "__REALTIME_TIMESTAMP": "2"})]
    assert A.collecter(cx, autres) == 0 and sessions(cx) == {}


def test_compte_sous_son_pseudo_les_autres_invites(base):
    cx, _ = base
    A.comptes(cx, [f"{GANDALF}\x1fgandalf", "ligne invalide"])
    A.collecter(cx, [debut(T0, "PA_6"), actif(T0 + 1, "PA_6"), debut(T0, "PA_7", INVITE), actif(T0 + 1, "PA_7", INVITE, client=SAFARI)])
    s = sessions(cx)
    assert (s["PA_6"]["participant"], s["PA_6"]["compte"]) == ("gandalf", True)
    assert (s["PA_7"]["participant"], s["PA_7"]["compte"]) == ("invité", False)
    assert s["PA_7"]["appareil"] == "iOS · Safari"
    assert "identite" not in s["PA_7"]                                    # l'identité technique ne sort pas


def test_purge_trente_jours_et_totaux_par_jour_conserves(base):
    cx, _ = base
    vieux = T0 - 40 * 86400
    A.collecter(cx, [debut(vieux, "PA_8"), actif(vieux + 1, "PA_8"), fin(vieux + 301, "PA_8"),
                     debut(vieux + 10, "PA_9"), fin(vieux + 11, "PA_9"), sans_connexion(vieux + 11, "PA_9"),
                     debut(T0, "PA_10"), actif(T0 + 1, "PA_10"), fin(T0 + 61, "PA_10")])
    A.purger(cx, maintenant=T0)
    assert set(sessions(cx)) == {"PA_10"}
    st = A.stats(cx, periode=365, maintenant=T0 + 100)
    assert st["sessions_abouties"] == 2 and st["echecs"] == 1 and st["secondes"] == 360


def test_stats_sept_jours(base):
    cx, _ = base
    A.comptes(cx, [f"{GANDALF}\x1fgandalf"])
    A.collecter(cx, [debut(T0, "PA_a"), actif(T0 + 1, "PA_a"), fin(T0 + 601, "PA_a"),
                     debut(T0 + 60, "PA_b", INVITE), actif(T0 + 61, "PA_b", INVITE, transport="tcp", client=SAFARI),
                     fin(T0 + 361, "PA_b", "DUPLICATE_IDENTITY", INVITE),
                     debut(T0 + 900, "PA_c"), fin(T0 + 901, "PA_c", "SIGNAL_SOURCE_CLOSE"), sans_connexion(T0 + 901, "PA_c")])
    st = A.stats(cx, periode=7, maintenant=T0 + 1000)
    assert st["reunions"] == 1 and st["secondes"] == 900 and st["echecs"] == 1 and st["sessions"] == 3
    assert st["participants"] == {"comptes": 1, "invites": 1}
    assert st["pic"]["nombre"] == 2 and st["mediane"] == 450
    assert st["transport"] == {"UDP": 1, "TCP": 1}
    assert st["motifs"]["aucun chemin média"] == 1 and st["motifs"]["rejoint ailleurs"] == 1
    assert st["appareils"] == {"Linux · Firefox": 1, "iOS · Safari": 1}
    assert st["salles"] == {SALLE: 900}
    jour = [j for j in st["par_jour"] if j["abouties"] or j["echecs"]]
    assert jour == [{"jour": "2026-10-26", "abouties": 2, "echecs": 1}] and len(st["par_jour"]) == 7


def test_jeton_hs256_verifiable(base):
    j = A.jeton("meet", "s3cr3t", {"roomList": True}, maintenant=T0, ttl=60)
    t, c, sig = j.split(".")
    attendu = base64.urlsafe_b64encode(hmac.new(b"s3cr3t", f"{t}.{c}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    charge = json.loads(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
    assert sig == attendu and charge["iss"] == "meet" and charge["exp"] == T0 + 60 and charge["video"] == {"roomList": True}


def faux_livekit(salles):
    """API Twirp simulée : ListRooms, ListParticipants. Les appels sont notés."""
    appels = []

    def appel(methode, corps, video):
        appels.append((methode, corps, video))
        if methode == "ListRooms":
            return {"rooms": [{"sid": "RM_1", "name": n, "creation_time": str(T0), "turn_password": "TURN-SECRET",
                               "num_participants": len(ps)} for n, ps in salles.items()]}
        if methode == "ListParticipants":
            return {"participants": salles[corps["room"]]}
        if methode == "DeleteRoom":
            return {}
        raise AssertionError(methode)
    return appel, appels


def test_en_direct_pseudo_ou_invite_jamais_le_nom_tape_ni_le_secret_turn(base):
    cx, _ = base
    A.comptes(cx, [f"{GANDALF}\x1fgandalf"])
    A.collecter(cx, [debut(T0, "PA_g"), actif(T0 + 1, "PA_g"), debut(T0, "PA_i", INVITE), actif(T0 + 1, "PA_i", INVITE, client=SAFARI)])
    appel, appels = faux_livekit({SALLE: [
        {"sid": "PA_g", "identity": GANDALF, "name": "gek", "state": "ACTIVE", "joined_at": str(T0),
         "tracks": [{"type": "AUDIO", "source": "MICROPHONE", "muted": True}, {"type": "VIDEO", "source": "CAMERA", "muted": False}]},
        {"sid": "PA_i", "identity": INVITE, "name": "Gerald Kerma", "state": "ACTIVE", "joined_at": str(T0 + 30),
         "tracks": [{"type": "VIDEO", "source": "SCREEN_SHARE", "muted": False}]}]})
    d = A.en_direct(appel, cx)
    texte = json.dumps(d)
    assert "TURN-SECRET" not in texte and "Gerald Kerma" not in texte and "gek" not in texte and INVITE not in texte
    ps = d["salles"][0]["participants"]
    assert [p["participant"] for p in ps] == ["gandalf", "invité"]
    assert ps[0]["medias"] == {"son": False, "image": True, "ecran": False} and ps[1]["medias"]["ecran"] is True
    assert ps[1]["appareil"] == "iOS · Safari" and ps[0]["transport"] == "UDP" and ps[1]["depuis"] == T0 + 30
    assert appels[1] == ("ListParticipants", {"room": SALLE}, {"roomAdmin": True, "room": SALLE})


def test_reunions_depuis_la_base_de_meet_et_le_direct(base):
    cx, _ = base
    A.collecter(cx, [debut(T0 - 3600, "PA_r", salle="autre-salle"), actif(T0 - 3599, "PA_r", salle="autre-salle"),
                     fin(T0 - 3000, "PA_r", salle="autre-salle")])
    F = "\x1f"
    lignes = [F.join([SALLE, "gii-cbvo-lpe", "gii-cbvo-lpe", "public", "gandalf", str(T0 - 600), str(T0 - 300)]),
              F.join(["autre-salle", "Équipe | « nuit »\nsuite", "yjw-dcvf-cja", "trusted", "", str(T0 - 7200), str(T0 - 3600)]),
              F.join(["ligne", "tronquée"])]
    appel, _ = faux_livekit({SALLE: [{"sid": "PA_x", "identity": GANDALF, "state": "ACTIVE", "tracks": []}]})
    r = A.reunions(lignes, A.en_direct(appel, cx), cx)
    assert [x["slug"] for x in r] == ["gii-cbvo-lpe", "yjw-dcvf-cja"]
    assert r[0]["en_cours"] is True and r[0]["presents"] == 1 and r[0]["acces"] == "public" and r[0]["proprietaire"] == "gandalf"
    assert r[1]["en_cours"] is False and r[1]["proprietaire"] is None and r[1]["nom"] == "Équipe | « nuit »\nsuite"
    assert r[1]["derniere"] == {"debut": T0 - 3600, "participants": 1, "secondes": 599}


def test_clore_appelle_delete_room(base):
    appel, appels = faux_livekit({SALLE: []})
    assert A.clore(appel, SALLE) == {"success": True, "salle": SALLE}
    assert appels == [("DeleteRoom", {"room": SALLE}, {"roomCreate": True})]


def test_clore_refuse_un_nom_de_salle_invalide(base):
    appel, appels = faux_livekit({})
    with pytest.raises(ValueError):
        A.clore(appel, "../../etc")
    assert appels == []


def test_enregistrements_psql_separateurs_ascii():
    import io
    flux = io.StringIO("a\x1fb\x1ec\x1fd\ne\x1e\n")
    assert A.enregistrements(flux) == ["a\x1fb", "c\x1fd\ne"]
