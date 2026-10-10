# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2236 : détection de l'OS et du type fin d'un appareil — chaque réponse porte sa PREUVE (`os_source`), sans preuve rien (None)."""
from api.osdetect import detecter, est_conteneur_lxc, mac_aleatoire, DeviceEvidence


def test_sans_aucune_preuve_rien_n_est_invente():
    d = detecter(DeviceEvidence())
    assert d == {"os": None, "os_source": None, "device_subtype": None}


def test_le_fabricant_seul_ne_donne_pas_d_os():
    d = detecter(DeviceEvidence(vendor="Apple, Inc.", mac="3c:22:fb:00:00:01"))
    assert d["os"] is None and d["os_source"] is None          # un OUI Apple peut être un Mac, un iPhone, une Apple TV


def test_classe_vendeur_dhcp_android_avec_version():
    d = detecter(DeviceEvidence(dhcp_vendor_class="android-dhcp-13"))
    assert d["os"] == "Android 13" and d["os_source"] == "dhcp-vendor-class:android-dhcp-13"


def test_classe_vendeur_dhcp_windows_et_busybox():
    assert detecter(DeviceEvidence(dhcp_vendor_class="MSFT 5.0"))["os"] == "Windows"
    d = detecter(DeviceEvidence(dhcp_vendor_class="udhcp 1.35.0"))
    assert d["os"] == "Linux" and d["os_source"].startswith("dhcp-vendor-class:")


def test_user_agent_donne_l_os_et_sa_version():
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15"
    d = detecter(DeviceEvidence(user_agents=[ua]))
    assert d["os"] == "iOS 17" and d["os_source"].startswith("user-agent:") and d["device_subtype"] == "smartphone"
    d = detecter(DeviceEvidence(user_agents=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"]))
    assert d["os"] == "Windows 10/11"
    d = detecter(DeviceEvidence(user_agents=["Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120 Mobile"]))
    assert d["os"] == "Android 14" and d["device_subtype"] == "smartphone"


def test_domaines_dns_de_connectivite():
    d = detecter(DeviceEvidence(dns_domains=["example.org", "connectivitycheck.gstatic.com"]))
    assert d["os"] == "Android" and d["os_source"] == "dns:connectivitycheck.gstatic.com"
    d = detecter(DeviceEvidence(dns_domains=["www.msftconnecttest.com"]))
    assert d["os"] == "Windows" and d["os_source"] == "dns:www.msftconnecttest.com"
    d = detecter(DeviceEvidence(dns_domains=["captive.apple.com"]))
    assert d["os"] == "Apple (iOS / macOS)"                      # le DNS ne départage pas iOS de macOS : on ne prétend pas le faire
    assert detecter(DeviceEvidence(dns_domains=["lgtvsdp.com"]))["os"] == "webOS (LG)"
    assert detecter(DeviceEvidence(dns_domains=["lgtvsdp.com"]))["device_subtype"] == "télévision"


def test_nom_de_l_appareil():
    d = detecter(DeviceEvidence(hostname="iPhone-de-Marie"))
    assert (d["os"], d["device_subtype"]) == ("iOS", "smartphone") and d["os_source"] == "hostname:iPhone-de-Marie"
    assert detecter(DeviceEvidence(hostname="DESKTOP-4F2K9"))["os"] == "Windows"
    assert detecter(DeviceEvidence(hostname="android-8f2a1c"))["os"] == "Android"
    assert detecter(DeviceEvidence(hostname="MacBook-Pro-de-Paul"))["os"] == "macOS"
    d = detecter(DeviceEvidence(hostname="Redmi-A3"))
    assert d["os"] == "Android" and d["device_subtype"] == "smartphone"


def test_un_nom_banal_ne_prouve_rien():
    assert detecter(DeviceEvidence(hostname="salon"))["os"] is None
    assert detecter(DeviceEvidence(hostname="gk3"))["os"] is None


def test_la_preuve_la_plus_forte_l_emporte():
    # DHCP > user-agent > DNS > nom
    d = detecter(DeviceEvidence(hostname="DESKTOP-1", dns_domains=["connectivitycheck.gstatic.com"], user_agents=["Mozilla/5.0 (Linux; Android 14)"],
                                dhcp_vendor_class="android-dhcp-14"))
    assert d["os_source"] == "dhcp-vendor-class:android-dhcp-14"
    d = detecter(DeviceEvidence(hostname="DESKTOP-1", dns_domains=["connectivitycheck.gstatic.com"]))
    assert d["os_source"].startswith("dns:")


def test_openwrt_et_secubox_viennent_de_l_empreinte_du_nac():
    d = detecter(DeviceEvidence(is_openwrt=True))
    assert d["os"] == "OpenWrt (Linux)" and d["os_source"] == "empreinte-nac:openwrt"
    d = detecter(DeviceEvidence(is_secubox=True))
    assert d["os"] == "Linux (SecuBox)" and d["os_source"] == "empreinte-nac:secubox"


def test_type_fin_par_nom_ou_service():
    assert detecter(DeviceEvidence(hostname="Chromecast-Ultra"))["device_subtype"] == "streaming"
    assert detecter(DeviceEvidence(hostname="HP-LaserJet-M404"))["device_subtype"] == "imprimante"
    assert detecter(DeviceEvidence(hostname="ESP_8A2B3C"))["device_subtype"] == "objet connecté"
    assert detecter(DeviceEvidence(hostname="Freebox-Player"))["device_subtype"] == "décodeur"
    assert detecter(DeviceEvidence(mdns=["_ipp._tcp.local"]))["device_subtype"] == "imprimante"
    assert detecter(DeviceEvidence(mdns=["_airplay._tcp.local"]))["device_subtype"] == "récepteur multimédia"


def test_mac_aleatoire_bit_localement_administre():
    assert mac_aleatoire("da:a1:19:00:00:01") is True           # 0xda : bit 0x02 posé
    assert mac_aleatoire("3c:22:fb:00:00:01") is False
    assert mac_aleatoire("") is False and mac_aleatoire("zz") is False


def test_une_mac_aleatoire_n_est_pas_typee_par_son_fabricant():
    d = detecter(DeviceEvidence(vendor="Apple, Inc.", mac="da:a1:19:00:00:01", hostname="iPhone"))
    assert d["os"] == "iOS"                                      # le NOM reste une preuve
    d = detecter(DeviceEvidence(vendor="Samsung Electronics", mac="da:a1:19:00:00:01"))
    assert d["os"] is None and d["device_subtype"] is None


def test_conteneurs_lxc():
    assert est_conteneur_lxc("00:16:3e:12:34:56", "", "") is True      # OUI Xensource/LXC
    assert est_conteneur_lxc("aa:bb:cc:dd:ee:ff", "10.100.0.150", "") is True
    assert est_conteneur_lxc("aa:bb:cc:dd:ee:ff", "192.168.1.20", "br-lxc") is True
    assert est_conteneur_lxc("aa:bb:cc:dd:ee:ff", "192.168.1.20", "eth1") is False
    assert est_conteneur_lxc("aa:bb:cc:dd:ee:ff", "", "") is False
