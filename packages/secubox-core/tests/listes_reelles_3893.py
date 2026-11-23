# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Échantillon des VRAIES sources de gk2 (23/11/2026), ancien format, pour #3893 : 93 (trois vues wf-*, dont deux de mêmes
zones), 95, 96 (huit adresses exemptées, une dérogation par domaine et par adresse). Domaines tirés au hasard (graine 3893)
dans chaque groupe de vues, paires apex/sous-domaine, noms présents dans plusieurs listes ; adresses IPv6 anonymisées en
2001:db8:c4e0::/64 (l'appareil exempté ::3 est aussi dans la vue wf-22a262de, comme sur gk2). Généré, ne pas éditer."""
# ruff: noqa: E501

SOURCES = {}
SOURCES["93-secubox-webfilter.conf"] = """\
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# GÉNÉRÉ par secubox-webfilter-ctl — ne pas éditer à la main (#1962).
server:
    access-control-view: 192.168.1.0/24 wf-defaut
    access-control-view: 2001:db8:c4e0::/64 wf-defaut
    access-control-view: 192.168.1.9/32 wf-915c124c
    access-control-view: 2001:db8:c4e0::1/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::2/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::3/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::4/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::5/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::6/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::7/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::8/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::9/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::a/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::b/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::c/128 wf-22a262de
    access-control-view: 2001:db8:c4e0::d/128 wf-22a262de
view:
    name: "wf-22a262de"
    view-first: yes
    local-zone: "10casino-8.buzz." always_nxdomain
    local-zone: "18lixi.casino." always_nxdomain
    local-zone: "1goldenstar-casino.com." always_nxdomain
    local-zone: "223bet.casino." always_nxdomain
    local-zone: "24casino.ie." always_nxdomain
    local-zone: "52truvabet.com." always_nxdomain
    local-zone: "5u.com." always_nxdomain
    local-zone: "74bet32.net." always_nxdomain
    local-zone: "aadesign-webwinkel.nl." always_nxdomain
    local-zone: "ae888work.casino." always_nxdomain
    local-zone: "aerobets-canada.ca." always_nxdomain
    local-zone: "assoct.ga." always_nxdomain
    local-zone: "betarcticacasinos-de.com." always_nxdomain
    local-zone: "betarcticacasinos.com." always_nxdomain
    local-zone: "betnacional-pix-br.com." always_nxdomain
    local-zone: "betsieriverrockcabin.shop." always_nxdomain
    local-zone: "bk807.lol." always_nxdomain
    local-zone: "bobsleddomesticglandular.com." always_nxdomain
    local-zone: "butterflyeventstyling.com." always_nxdomain
    local-zone: "capndr.com." always_nxdomain
    local-zone: "casinoratingca.pro." always_nxdomain
    local-zone: "chaturbate-tokens.com." always_nxdomain
    local-zone: "coinurl.com." always_nxdomain
    local-zone: "confirm-verification-process.systems." always_nxdomain
    local-zone: "daveola.com." always_nxdomain
    local-zone: "dezcom.com." always_nxdomain
    local-zone: "dhdservices.com.au." always_nxdomain
    local-zone: "eldorado-casino-naj.buzz." always_nxdomain
    local-zone: "englands.localbox.org." always_nxdomain
    local-zone: "eoslots.com." always_nxdomain
    local-zone: "eth-request.org." always_nxdomain
    local-zone: "eytancohen.com." always_nxdomain
    local-zone: "facebookchenxi.blogspot.ru." always_nxdomain
    local-zone: "freemobile-service.cf." always_nxdomain
    local-zone: "gateway-studentstaffaccess-owa.my-free.website." always_nxdomain
    local-zone: "gbbet.casino." always_nxdomain
    local-zone: "glow.wek.co.il." always_nxdomain
    local-zone: "gsz.name.my." always_nxdomain
    local-zone: "hellspincasinos-slot.com." always_nxdomain
    local-zone: "hogdekempen.nl." always_nxdomain
    local-zone: "house-bets.app." always_nxdomain
    local-zone: "icecasinos-pl.com." always_nxdomain
    local-zone: "itunes-signup.performancehorizon.com." always_nxdomain
    local-zone: "kiu77.info." always_nxdomain
    local-zone: "kroll8568-my.sharepoint.com." always_nxdomain
    local-zone: "level-upcasinoau.com." always_nxdomain
    local-zone: "login.microsoftonline.com.ms365.live." always_nxdomain
    local-zone: "macauslot188hh.com." always_nxdomain
    local-zone: "marcomundarain.com.ve." always_nxdomain
    local-zone: "mm88bet-casino.com." always_nxdomain
    local-zone: "moosejaw.casino." always_nxdomain
    local-zone: "mydietjournal.com." always_nxdomain
    local-zone: "olimp.com." always_nxdomain
    local-zone: "pagsegurofake.blogspot.ru." always_nxdomain
    local-zone: "palacebet-casino-south-africa.app." always_nxdomain
    local-zone: "pb88-baji.casino." always_nxdomain
    local-zone: "perso.wanadoo.es." always_nxdomain
    local-zone: "pokerdom-u3avhb.top." always_nxdomain
    local-zone: "premierbet-ml.com." always_nxdomain
    local-zone: "prirodalieci.sk." always_nxdomain
    local-zone: "qfhcmb.site." always_nxdomain
    local-zone: "rightrespect.org." always_nxdomain
    local-zone: "secure.runescape.com-gzg.icu." always_nxdomain
    local-zone: "servicegroupesmsetmms.comli.com." always_nxdomain
    local-zone: "sh217582.website.pl." always_nxdomain
    local-zone: "slot-gacor.ink." always_nxdomain
    local-zone: "smhlawoffice.com." always_nxdomain
    local-zone: "socia-lytics.com." always_nxdomain
    local-zone: "squally-seal.000webhostapp.com." always_nxdomain
    local-zone: "stargames.com." always_nxdomain
    local-zone: "static.zongheng.com." always_nxdomain
    local-zone: "stellahouse.gr." always_nxdomain
    local-zone: "sunilmaharjan.com.np." always_nxdomain
    local-zone: "swiss1l.dancingfeatswfl.com." always_nxdomain
    local-zone: "th.tubetruck.com." always_nxdomain
    local-zone: "theheritagetour.com." always_nxdomain
    local-zone: "themobilecasino.com." always_nxdomain
    local-zone: "top-online-casino-australia.com." always_nxdomain
    local-zone: "valleyvirtualtours.com." always_nxdomain
    local-zone: "valuebets.uk." always_nxdomain
    local-zone: "vetmelbet-tun.top." always_nxdomain
    local-zone: "webpushstat-sgp.engagelab.com." always_nxdomain
    local-zone: "winabet365.org." always_nxdomain
    local-zone: "winshark.link." always_nxdomain
    local-zone: "wjkydkcxtkkoflu.nut.cc." always_nxdomain
    local-zone: "www.psnzone.com." always_nxdomain
    local-zone: "www4.match.com." always_nxdomain
    local-zone: "zoccercasino-italy.it." always_nxdomain
    local-zone: "zoccerslots.com." always_nxdomain
    local-zone: "chaturbate.com." transparent
view:
    name: "wf-915c124c"
    view-first: yes
    local-zone: "001office.cn." always_nxdomain
    local-zone: "10casino-8.buzz." always_nxdomain
    local-zone: "18lixi.casino." always_nxdomain
    local-zone: "1goldenstar-casino.com." always_nxdomain
    local-zone: "223bet.casino." always_nxdomain
    local-zone: "24casino.ie." always_nxdomain
    local-zone: "3corenergy.com." always_nxdomain
    local-zone: "52truvabet.com." always_nxdomain
    local-zone: "5u.com." always_nxdomain
    local-zone: "74bet32.net." always_nxdomain
    local-zone: "aadesign-webwinkel.nl." always_nxdomain
    local-zone: "adult-bank.jp." always_nxdomain
    local-zone: "adultchat7.com." always_nxdomain
    local-zone: "adultchaturbate.com." always_nxdomain
    local-zone: "adultjoy.net." always_nxdomain
    local-zone: "adultlinks.top." always_nxdomain
    local-zone: "ae888work.casino." always_nxdomain
    local-zone: "aerobets-canada.ca." always_nxdomain
    local-zone: "amateurfetishist.com." always_nxdomain
    local-zone: "amoxicilx.com." always_nxdomain
    local-zone: "analbest.com." always_nxdomain
    local-zone: "analxxx.one." always_nxdomain
    local-zone: "ankaraworld.website." always_nxdomain
    local-zone: "asiantvporn.com." always_nxdomain
    local-zone: "assoct.ga." always_nxdomain
    local-zone: "asstraffic.com." always_nxdomain
    local-zone: "azporncomics.com." always_nxdomain
    local-zone: "bestiality.video." always_nxdomain
    local-zone: "betarcticacasinos-de.com." always_nxdomain
    local-zone: "betarcticacasinos.com." always_nxdomain
    local-zone: "betnacional-pix-br.com." always_nxdomain
    local-zone: "betsieriverrockcabin.shop." always_nxdomain
    local-zone: "big-tits-pics.com." always_nxdomain
    local-zone: "bk807.lol." always_nxdomain
    local-zone: "bobsleddomesticglandular.com." always_nxdomain
    local-zone: "boink.st." always_nxdomain
    local-zone: "bondagevalley.cc." always_nxdomain
    local-zone: "bongacams.com." always_nxdomain
    local-zone: "butterflyeventstyling.com." always_nxdomain
    local-zone: "calleve.com." always_nxdomain
    local-zone: "cams.chaturbatego.com." always_nxdomain
    local-zone: "camvideos.tv." always_nxdomain
    local-zone: "capndr.com." always_nxdomain
    local-zone: "cartoonpornvids.com." always_nxdomain
    local-zone: "casinoratingca.pro." always_nxdomain
    local-zone: "casualsexring.co.uk." always_nxdomain
    local-zone: "chaturbate-female.com." always_nxdomain
    local-zone: "chaturbate-me.su." always_nxdomain
    local-zone: "chaturbate-ru.com." always_nxdomain
    local-zone: "chaturbate-tokens.com." always_nxdomain
    local-zone: "chaturbate-video.xyz." always_nxdomain
    local-zone: "chaturbate.adult." always_nxdomain
    local-zone: "chaturbate.camera." always_nxdomain
    local-zone: "chaturbate.co." always_nxdomain
    local-zone: "chaturbate.cz." always_nxdomain
    local-zone: "chaturbate.deals." always_nxdomain
    local-zone: "chaturbate.eu." always_nxdomain
    local-zone: "chaturbate.eu.com." always_nxdomain
    local-zone: "chaturbate.fit." always_nxdomain
    local-zone: "chaturbate.global." always_nxdomain
    local-zone: "chaturbate.lat." always_nxdomain
    local-zone: "chaturbate.lu." always_nxdomain
    local-zone: "chaturbate.lv." always_nxdomain
    local-zone: "chaturbate.md." always_nxdomain
    local-zone: "chaturbate.me." always_nxdomain
    local-zone: "chaturbate.net." always_nxdomain
    local-zone: "chaturbate.nl." always_nxdomain
    local-zone: "chaturbate.onl." always_nxdomain
    local-zone: "chaturbate.pro." always_nxdomain
    local-zone: "chaturbate.sx." always_nxdomain
    local-zone: "chaturbate.watch." always_nxdomain
    local-zone: "chaturbate18.com." always_nxdomain
    local-zone: "chaturbate18.ru." always_nxdomain
    local-zone: "chaturbate2.com." always_nxdomain
    local-zone: "chaturbate24.com." always_nxdomain
    local-zone: "chaturbateapp.com." always_nxdomain
    local-zone: "chaturbatecams.com." always_nxdomain
    local-zone: "chaturbatecamsexe.fr." always_nxdomain
    local-zone: "chaturbategay.com." always_nxdomain
    local-zone: "chaturbategirls.club." always_nxdomain
    local-zone: "chaturbategirls.com." always_nxdomain
    local-zone: "chaturbateinhd.com." always_nxdomain
    local-zone: "chaturbatemodel.net." always_nxdomain
    local-zone: "chaturbatenow.com." always_nxdomain
    local-zone: "chaturbaterooms.com." always_nxdomain
    local-zone: "chaturbatesex.ru." always_nxdomain
    local-zone: "chaturbatesexmodels.com." always_nxdomain
    local-zone: "chaturbatesy.com." always_nxdomain
    local-zone: "coinurl.com." always_nxdomain
    local-zone: "confirm-verification-process.systems." always_nxdomain
    local-zone: "counter-strike.gay." always_nxdomain
    local-zone: "craxpro.io." always_nxdomain
    local-zone: "cumshotti.com." always_nxdomain
    local-zone: "daveola.com." always_nxdomain
    local-zone: "desi-sex-video.com." always_nxdomain
    local-zone: "dezcom.com." always_nxdomain
    local-zone: "dhdservices.com.au." always_nxdomain
    local-zone: "drdeanlombardo.com." always_nxdomain
    local-zone: "eboruss.click." always_nxdomain
    local-zone: "eldorado-casino-naj.buzz." always_nxdomain
    local-zone: "englands.localbox.org." always_nxdomain
    local-zone: "eoslots.com." always_nxdomain
    local-zone: "epornerpics.com." always_nxdomain
    local-zone: "eromyporn.info." always_nxdomain
    local-zone: "estiloporno.com." always_nxdomain
    local-zone: "eth-request.org." always_nxdomain
    local-zone: "evalinxxx.com." always_nxdomain
    local-zone: "experienceusvirginislands.com." always_nxdomain
    local-zone: "eytancohen.com." always_nxdomain
    local-zone: "favgayporn.com." always_nxdomain
    local-zone: "feraluex-dolls.com." always_nxdomain
    local-zone: "fetishmegastore.com." always_nxdomain
    local-zone: "freemobile-service.cf." always_nxdomain
    local-zone: "freepornolinks.com." always_nxdomain
    local-zone: "freexxxhindi.com." always_nxdomain
    local-zone: "freshpornclips.mobi." always_nxdomain
    local-zone: "gateway-studentstaffaccess-owa.my-free.website." always_nxdomain
    local-zone: "gay4asian.com." always_nxdomain
    local-zone: "gayandlesbianhomestays.com." always_nxdomain
    local-zone: "gaymaletube.yachts." always_nxdomain
    local-zone: "gbbet.casino." always_nxdomain
    local-zone: "geile-luder.com." always_nxdomain
    local-zone: "girlslovewinners.com." always_nxdomain
    local-zone: "gizlihikaye.com." always_nxdomain
    local-zone: "glow.wek.co.il." always_nxdomain
    local-zone: "gogogaytube.cc." always_nxdomain
    local-zone: "gsz.name.my." always_nxdomain
    local-zone: "gzlandao.cn." always_nxdomain
    local-zone: "hellspincasinos-slot.com." always_nxdomain
    local-zone: "hogdekempen.nl." always_nxdomain
    local-zone: "hotzxgirl.com." always_nxdomain
    local-zone: "house-bets.app." always_nxdomain
    local-zone: "icecasinos-pl.com." always_nxdomain
    local-zone: "ipornu.com." always_nxdomain
    local-zone: "irxclip.com." always_nxdomain
    local-zone: "itunes-signup.performancehorizon.com." always_nxdomain
    local-zone: "japan-porns.com." always_nxdomain
    local-zone: "javhd.icu." always_nxdomain
    local-zone: "kaashkode.com." always_nxdomain
    local-zone: "kenyapornvideos.com." always_nxdomain
    local-zone: "kiu77.info." always_nxdomain
    local-zone: "kroll8568-my.sharepoint.com." always_nxdomain
    local-zone: "level-upcasinoau.com." always_nxdomain
    local-zone: "lifelovestyle.com." always_nxdomain
    local-zone: "lindseyleigh.fans." always_nxdomain
    local-zone: "livejasmin.com." always_nxdomain
    local-zone: "login.microsoftonline.com.ms365.live." always_nxdomain
    local-zone: "lovedmom.com." always_nxdomain
    local-zone: "lovelyblog.com." always_nxdomain
    local-zone: "macauslot188hh.com." always_nxdomain
    local-zone: "manga2025.com." always_nxdomain
    local-zone: "marcomundarain.com.ve." always_nxdomain
    local-zone: "marrieddance.com." always_nxdomain
    local-zone: "maturesluts.tv." always_nxdomain
    local-zone: "milfslesbian.com." always_nxdomain
    local-zone: "mm88bet-casino.com." always_nxdomain
    local-zone: "moosejaw.casino." always_nxdomain
    local-zone: "myangelsescorts.com." always_nxdomain
    local-zone: "mydietjournal.com." always_nxdomain
    local-zone: "netporn.net." always_nxdomain
    local-zone: "nickshotcams.com." always_nxdomain
    local-zone: "nudehairygirls.com." always_nxdomain
    local-zone: "nudeteenorgy.com." always_nxdomain
    local-zone: "nutten.at." always_nxdomain
    local-zone: "nuvid.club." always_nxdomain
    local-zone: "olimp.com." always_nxdomain
    local-zone: "ourdream.ai." always_nxdomain
    local-zone: "p4455.com." always_nxdomain
    local-zone: "palacebet-casino-south-africa.app." always_nxdomain
    local-zone: "pb88-baji.casino." always_nxdomain
    local-zone: "perso.wanadoo.es." always_nxdomain
    local-zone: "petlovencare.com." always_nxdomain
    local-zone: "pinaypie.ph." always_nxdomain
    local-zone: "pokerdom-u3avhb.top." always_nxdomain
    local-zone: "porn.org." always_nxdomain
    local-zone: "porn00.com." always_nxdomain
    local-zone: "porn4k.to." always_nxdomain
    local-zone: "pornamigo.com." always_nxdomain
    local-zone: "pornbutler.com." always_nxdomain
    local-zone: "pornolabe.cc." always_nxdomain
    local-zone: "pornomeg.com." always_nxdomain
    local-zone: "pornvideos-tour.com." always_nxdomain
    local-zone: "premierbet-ml.com." always_nxdomain
    local-zone: "prirodalieci.sk." always_nxdomain
    local-zone: "pussypornpics.com." always_nxdomain
    local-zone: "pytana.ru." always_nxdomain
    local-zone: "qfhcmb.site." always_nxdomain
    local-zone: "rapeinass.com." always_nxdomain
    local-zone: "rapeporn.tv." always_nxdomain
    local-zone: "rightrespect.org." always_nxdomain
    local-zone: "rodneyflix.com." always_nxdomain
    local-zone: "romemajorcams.com." always_nxdomain
    local-zone: "ruhub.me." always_nxdomain
    local-zone: "salyhumojerky.com." always_nxdomain
    local-zone: "secure.runescape.com-gzg.icu." always_nxdomain
    local-zone: "selfiesuck.com." always_nxdomain
    local-zone: "servicegroupesmsetmms.comli.com." always_nxdomain
    local-zone: "sexadept.com." always_nxdomain
    local-zone: "sexdollcenter.vip." always_nxdomain
    local-zone: "sexnrace.com." always_nxdomain
    local-zone: "sexy-egirls-leaked.com." always_nxdomain
    local-zone: "sexycn.pw." always_nxdomain
    local-zone: "sexyxart.com." always_nxdomain
    local-zone: "sh217582.website.pl." always_nxdomain
    local-zone: "skingoddesslb.info." always_nxdomain
    local-zone: "slot-gacor.ink." always_nxdomain
    local-zone: "smhlawoffice.com." always_nxdomain
    local-zone: "smutdude.com." always_nxdomain
    local-zone: "socia-lytics.com." always_nxdomain
    local-zone: "sohot.cyou." always_nxdomain
    local-zone: "solotouch.com." always_nxdomain
    local-zone: "squally-seal.000webhostapp.com." always_nxdomain
    local-zone: "stargames.com." always_nxdomain
    local-zone: "stellahouse.gr." always_nxdomain
    local-zone: "streamate.com." always_nxdomain
    local-zone: "sunilmaharjan.com.np." always_nxdomain
    local-zone: "swiss1l.dancingfeatswfl.com." always_nxdomain
    local-zone: "teenfuckhd.com." always_nxdomain
    local-zone: "teenpornxxx.net." always_nxdomain
    local-zone: "thechaturbate.com." always_nxdomain
    local-zone: "theheritagetour.com." always_nxdomain
    local-zone: "themobilecasino.com." always_nxdomain
    local-zone: "therealworkout.com." always_nxdomain
    local-zone: "thrillamateurs.xyz." always_nxdomain
    local-zone: "top-online-casino-australia.com." always_nxdomain
    local-zone: "tubent.com." always_nxdomain
    local-zone: "tubevideoshd.xxx." always_nxdomain
    local-zone: "tyishasellschicago.com." always_nxdomain
    local-zone: "ufym.info." always_nxdomain
    local-zone: "uzbak.ru." always_nxdomain
    local-zone: "valleyvirtualtours.com." always_nxdomain
    local-zone: "valuebets.uk." always_nxdomain
    local-zone: "vetmelbet-tun.top." always_nxdomain
    local-zone: "vlsexhihi.pro." always_nxdomain
    local-zone: "webpushstat-sgp.engagelab.com." always_nxdomain
    local-zone: "whentai.com." always_nxdomain
    local-zone: "winabet365.org." always_nxdomain
    local-zone: "winshark.link." always_nxdomain
    local-zone: "wjkydkcxtkkoflu.nut.cc." always_nxdomain
    local-zone: "www.psnzone.com." always_nxdomain
    local-zone: "x-chaturbate.ru." always_nxdomain
    local-zone: "xhname.com." always_nxdomain
    local-zone: "xnpornvidz.com." always_nxdomain
    local-zone: "xtorjack.com." always_nxdomain
    local-zone: "xvideoslive.com." always_nxdomain
    local-zone: "xxxvideo.skin." always_nxdomain
    local-zone: "yaporn.biz." always_nxdomain
    local-zone: "zazporn.com." always_nxdomain
    local-zone: "zoccercasino-italy.it." always_nxdomain
    local-zone: "zoccerslots.com." always_nxdomain
    local-zone: "zoig1.com." always_nxdomain
    local-zone: "zoofilialovers.com." always_nxdomain
    local-zone: "chaturbate.com." transparent
view:
    name: "wf-defaut"
    view-first: yes
    local-zone: "001office.cn." always_nxdomain
    local-zone: "10casino-8.buzz." always_nxdomain
    local-zone: "18lixi.casino." always_nxdomain
    local-zone: "1goldenstar-casino.com." always_nxdomain
    local-zone: "223bet.casino." always_nxdomain
    local-zone: "24casino.ie." always_nxdomain
    local-zone: "3corenergy.com." always_nxdomain
    local-zone: "52truvabet.com." always_nxdomain
    local-zone: "5u.com." always_nxdomain
    local-zone: "74bet32.net." always_nxdomain
    local-zone: "aadesign-webwinkel.nl." always_nxdomain
    local-zone: "adult-bank.jp." always_nxdomain
    local-zone: "adultchat7.com." always_nxdomain
    local-zone: "adultchaturbate.com." always_nxdomain
    local-zone: "adultjoy.net." always_nxdomain
    local-zone: "adultlinks.top." always_nxdomain
    local-zone: "ae888work.casino." always_nxdomain
    local-zone: "aerobets-canada.ca." always_nxdomain
    local-zone: "amateurfetishist.com." always_nxdomain
    local-zone: "amoxicilx.com." always_nxdomain
    local-zone: "analbest.com." always_nxdomain
    local-zone: "analxxx.one." always_nxdomain
    local-zone: "ankaraworld.website." always_nxdomain
    local-zone: "asiantvporn.com." always_nxdomain
    local-zone: "assoct.ga." always_nxdomain
    local-zone: "asstraffic.com." always_nxdomain
    local-zone: "azporncomics.com." always_nxdomain
    local-zone: "bestiality.video." always_nxdomain
    local-zone: "betarcticacasinos-de.com." always_nxdomain
    local-zone: "betarcticacasinos.com." always_nxdomain
    local-zone: "betnacional-pix-br.com." always_nxdomain
    local-zone: "betsieriverrockcabin.shop." always_nxdomain
    local-zone: "big-tits-pics.com." always_nxdomain
    local-zone: "bk807.lol." always_nxdomain
    local-zone: "bobsleddomesticglandular.com." always_nxdomain
    local-zone: "boink.st." always_nxdomain
    local-zone: "bondagevalley.cc." always_nxdomain
    local-zone: "bongacams.com." always_nxdomain
    local-zone: "butterflyeventstyling.com." always_nxdomain
    local-zone: "calleve.com." always_nxdomain
    local-zone: "cams.chaturbatego.com." always_nxdomain
    local-zone: "camvideos.tv." always_nxdomain
    local-zone: "capndr.com." always_nxdomain
    local-zone: "cartoonpornvids.com." always_nxdomain
    local-zone: "casinoratingca.pro." always_nxdomain
    local-zone: "casualsexring.co.uk." always_nxdomain
    local-zone: "chaturbate-female.com." always_nxdomain
    local-zone: "chaturbate-me.su." always_nxdomain
    local-zone: "chaturbate-ru.com." always_nxdomain
    local-zone: "chaturbate-tokens.com." always_nxdomain
    local-zone: "chaturbate-video.xyz." always_nxdomain
    local-zone: "chaturbate.adult." always_nxdomain
    local-zone: "chaturbate.camera." always_nxdomain
    local-zone: "chaturbate.co." always_nxdomain
    local-zone: "chaturbate.com." always_nxdomain
    local-zone: "chaturbate.cz." always_nxdomain
    local-zone: "chaturbate.deals." always_nxdomain
    local-zone: "chaturbate.eu." always_nxdomain
    local-zone: "chaturbate.eu.com." always_nxdomain
    local-zone: "chaturbate.fit." always_nxdomain
    local-zone: "chaturbate.global." always_nxdomain
    local-zone: "chaturbate.lat." always_nxdomain
    local-zone: "chaturbate.lu." always_nxdomain
    local-zone: "chaturbate.lv." always_nxdomain
    local-zone: "chaturbate.md." always_nxdomain
    local-zone: "chaturbate.me." always_nxdomain
    local-zone: "chaturbate.net." always_nxdomain
    local-zone: "chaturbate.nl." always_nxdomain
    local-zone: "chaturbate.onl." always_nxdomain
    local-zone: "chaturbate.pro." always_nxdomain
    local-zone: "chaturbate.sx." always_nxdomain
    local-zone: "chaturbate.watch." always_nxdomain
    local-zone: "chaturbate18.com." always_nxdomain
    local-zone: "chaturbate18.ru." always_nxdomain
    local-zone: "chaturbate2.com." always_nxdomain
    local-zone: "chaturbate24.com." always_nxdomain
    local-zone: "chaturbateapp.com." always_nxdomain
    local-zone: "chaturbatecams.com." always_nxdomain
    local-zone: "chaturbatecamsexe.fr." always_nxdomain
    local-zone: "chaturbategay.com." always_nxdomain
    local-zone: "chaturbategirls.club." always_nxdomain
    local-zone: "chaturbategirls.com." always_nxdomain
    local-zone: "chaturbateinhd.com." always_nxdomain
    local-zone: "chaturbatemodel.net." always_nxdomain
    local-zone: "chaturbatenow.com." always_nxdomain
    local-zone: "chaturbaterooms.com." always_nxdomain
    local-zone: "chaturbatesex.ru." always_nxdomain
    local-zone: "chaturbatesexmodels.com." always_nxdomain
    local-zone: "chaturbatesy.com." always_nxdomain
    local-zone: "coinurl.com." always_nxdomain
    local-zone: "confirm-verification-process.systems." always_nxdomain
    local-zone: "counter-strike.gay." always_nxdomain
    local-zone: "craxpro.io." always_nxdomain
    local-zone: "cumshotti.com." always_nxdomain
    local-zone: "daveola.com." always_nxdomain
    local-zone: "desi-sex-video.com." always_nxdomain
    local-zone: "dezcom.com." always_nxdomain
    local-zone: "dhdservices.com.au." always_nxdomain
    local-zone: "drdeanlombardo.com." always_nxdomain
    local-zone: "eboruss.click." always_nxdomain
    local-zone: "eldorado-casino-naj.buzz." always_nxdomain
    local-zone: "englands.localbox.org." always_nxdomain
    local-zone: "eoslots.com." always_nxdomain
    local-zone: "epornerpics.com." always_nxdomain
    local-zone: "eromyporn.info." always_nxdomain
    local-zone: "estiloporno.com." always_nxdomain
    local-zone: "eth-request.org." always_nxdomain
    local-zone: "evalinxxx.com." always_nxdomain
    local-zone: "experienceusvirginislands.com." always_nxdomain
    local-zone: "eytancohen.com." always_nxdomain
    local-zone: "favgayporn.com." always_nxdomain
    local-zone: "feraluex-dolls.com." always_nxdomain
    local-zone: "fetishmegastore.com." always_nxdomain
    local-zone: "freemobile-service.cf." always_nxdomain
    local-zone: "freepornolinks.com." always_nxdomain
    local-zone: "freexxxhindi.com." always_nxdomain
    local-zone: "freshpornclips.mobi." always_nxdomain
    local-zone: "gateway-studentstaffaccess-owa.my-free.website." always_nxdomain
    local-zone: "gay4asian.com." always_nxdomain
    local-zone: "gayandlesbianhomestays.com." always_nxdomain
    local-zone: "gaymaletube.yachts." always_nxdomain
    local-zone: "gbbet.casino." always_nxdomain
    local-zone: "geile-luder.com." always_nxdomain
    local-zone: "girlslovewinners.com." always_nxdomain
    local-zone: "gizlihikaye.com." always_nxdomain
    local-zone: "glow.wek.co.il." always_nxdomain
    local-zone: "gogogaytube.cc." always_nxdomain
    local-zone: "gsz.name.my." always_nxdomain
    local-zone: "gzlandao.cn." always_nxdomain
    local-zone: "hellspincasinos-slot.com." always_nxdomain
    local-zone: "hogdekempen.nl." always_nxdomain
    local-zone: "hotzxgirl.com." always_nxdomain
    local-zone: "house-bets.app." always_nxdomain
    local-zone: "icecasinos-pl.com." always_nxdomain
    local-zone: "ipornu.com." always_nxdomain
    local-zone: "irxclip.com." always_nxdomain
    local-zone: "itunes-signup.performancehorizon.com." always_nxdomain
    local-zone: "japan-porns.com." always_nxdomain
    local-zone: "javhd.icu." always_nxdomain
    local-zone: "kaashkode.com." always_nxdomain
    local-zone: "kenyapornvideos.com." always_nxdomain
    local-zone: "kiu77.info." always_nxdomain
    local-zone: "kroll8568-my.sharepoint.com." always_nxdomain
    local-zone: "level-upcasinoau.com." always_nxdomain
    local-zone: "lifelovestyle.com." always_nxdomain
    local-zone: "lindseyleigh.fans." always_nxdomain
    local-zone: "livejasmin.com." always_nxdomain
    local-zone: "login.microsoftonline.com.ms365.live." always_nxdomain
    local-zone: "lovedmom.com." always_nxdomain
    local-zone: "lovelyblog.com." always_nxdomain
    local-zone: "macauslot188hh.com." always_nxdomain
    local-zone: "manga2025.com." always_nxdomain
    local-zone: "marcomundarain.com.ve." always_nxdomain
    local-zone: "marrieddance.com." always_nxdomain
    local-zone: "maturesluts.tv." always_nxdomain
    local-zone: "milfslesbian.com." always_nxdomain
    local-zone: "mm88bet-casino.com." always_nxdomain
    local-zone: "moosejaw.casino." always_nxdomain
    local-zone: "myangelsescorts.com." always_nxdomain
    local-zone: "mydietjournal.com." always_nxdomain
    local-zone: "netporn.net." always_nxdomain
    local-zone: "nickshotcams.com." always_nxdomain
    local-zone: "nudehairygirls.com." always_nxdomain
    local-zone: "nudeteenorgy.com." always_nxdomain
    local-zone: "nutten.at." always_nxdomain
    local-zone: "nuvid.club." always_nxdomain
    local-zone: "olimp.com." always_nxdomain
    local-zone: "ourdream.ai." always_nxdomain
    local-zone: "p4455.com." always_nxdomain
    local-zone: "palacebet-casino-south-africa.app." always_nxdomain
    local-zone: "pb88-baji.casino." always_nxdomain
    local-zone: "perso.wanadoo.es." always_nxdomain
    local-zone: "petlovencare.com." always_nxdomain
    local-zone: "pinaypie.ph." always_nxdomain
    local-zone: "pokerdom-u3avhb.top." always_nxdomain
    local-zone: "porn.org." always_nxdomain
    local-zone: "porn00.com." always_nxdomain
    local-zone: "porn4k.to." always_nxdomain
    local-zone: "pornamigo.com." always_nxdomain
    local-zone: "pornbutler.com." always_nxdomain
    local-zone: "pornolabe.cc." always_nxdomain
    local-zone: "pornomeg.com." always_nxdomain
    local-zone: "pornvideos-tour.com." always_nxdomain
    local-zone: "premierbet-ml.com." always_nxdomain
    local-zone: "prirodalieci.sk." always_nxdomain
    local-zone: "pussypornpics.com." always_nxdomain
    local-zone: "pytana.ru." always_nxdomain
    local-zone: "qfhcmb.site." always_nxdomain
    local-zone: "rapeinass.com." always_nxdomain
    local-zone: "rapeporn.tv." always_nxdomain
    local-zone: "rightrespect.org." always_nxdomain
    local-zone: "rodneyflix.com." always_nxdomain
    local-zone: "romemajorcams.com." always_nxdomain
    local-zone: "ruhub.me." always_nxdomain
    local-zone: "salyhumojerky.com." always_nxdomain
    local-zone: "secure.runescape.com-gzg.icu." always_nxdomain
    local-zone: "selfiesuck.com." always_nxdomain
    local-zone: "servicegroupesmsetmms.comli.com." always_nxdomain
    local-zone: "sexadept.com." always_nxdomain
    local-zone: "sexdollcenter.vip." always_nxdomain
    local-zone: "sexnrace.com." always_nxdomain
    local-zone: "sexy-egirls-leaked.com." always_nxdomain
    local-zone: "sexycn.pw." always_nxdomain
    local-zone: "sexyxart.com." always_nxdomain
    local-zone: "sh217582.website.pl." always_nxdomain
    local-zone: "skingoddesslb.info." always_nxdomain
    local-zone: "slot-gacor.ink." always_nxdomain
    local-zone: "smhlawoffice.com." always_nxdomain
    local-zone: "smutdude.com." always_nxdomain
    local-zone: "socia-lytics.com." always_nxdomain
    local-zone: "sohot.cyou." always_nxdomain
    local-zone: "solotouch.com." always_nxdomain
    local-zone: "squally-seal.000webhostapp.com." always_nxdomain
    local-zone: "stargames.com." always_nxdomain
    local-zone: "stellahouse.gr." always_nxdomain
    local-zone: "streamate.com." always_nxdomain
    local-zone: "sunilmaharjan.com.np." always_nxdomain
    local-zone: "swiss1l.dancingfeatswfl.com." always_nxdomain
    local-zone: "teenfuckhd.com." always_nxdomain
    local-zone: "teenpornxxx.net." always_nxdomain
    local-zone: "thechaturbate.com." always_nxdomain
    local-zone: "theheritagetour.com." always_nxdomain
    local-zone: "themobilecasino.com." always_nxdomain
    local-zone: "therealworkout.com." always_nxdomain
    local-zone: "thrillamateurs.xyz." always_nxdomain
    local-zone: "top-online-casino-australia.com." always_nxdomain
    local-zone: "tubent.com." always_nxdomain
    local-zone: "tubevideoshd.xxx." always_nxdomain
    local-zone: "tyishasellschicago.com." always_nxdomain
    local-zone: "ufym.info." always_nxdomain
    local-zone: "uzbak.ru." always_nxdomain
    local-zone: "valleyvirtualtours.com." always_nxdomain
    local-zone: "valuebets.uk." always_nxdomain
    local-zone: "vetmelbet-tun.top." always_nxdomain
    local-zone: "vlsexhihi.pro." always_nxdomain
    local-zone: "webpushstat-sgp.engagelab.com." always_nxdomain
    local-zone: "whentai.com." always_nxdomain
    local-zone: "winabet365.org." always_nxdomain
    local-zone: "winshark.link." always_nxdomain
    local-zone: "wjkydkcxtkkoflu.nut.cc." always_nxdomain
    local-zone: "www.psnzone.com." always_nxdomain
    local-zone: "x-chaturbate.ru." always_nxdomain
    local-zone: "xhname.com." always_nxdomain
    local-zone: "xnpornvidz.com." always_nxdomain
    local-zone: "xtorjack.com." always_nxdomain
    local-zone: "xvideoslive.com." always_nxdomain
    local-zone: "xxxvideo.skin." always_nxdomain
    local-zone: "yaporn.biz." always_nxdomain
    local-zone: "zazporn.com." always_nxdomain
    local-zone: "zoccercasino-italy.it." always_nxdomain
    local-zone: "zoccerslots.com." always_nxdomain
    local-zone: "zoig1.com." always_nxdomain
    local-zone: "zoofilialovers.com." always_nxdomain
"""

SOURCES["95-secubox-adblock.conf"] = """\
# Managed by secubox-adblock-sync (#740). DO NOT EDIT BY HAND.
# Regenerate: secubox-adblock-sync sync
server:
    local-zone: "1025kmgi.rocks." always_nxdomain
    local-zone: "17746183664520db71d564833bff22169ae2b5b12b7402c437539787.trk.sensic.net." always_nxdomain
    local-zone: "1784827726598b9a34099f4f9920e1fa72ecd1040b0ed0978855db71.trk.sensic.net." always_nxdomain
    local-zone: "1goldenstar-casino.com." always_nxdomain
    local-zone: "3e888f65aad8d2c22f1d60102200ca04.safeframe.googlesyndication.com." always_nxdomain
    local-zone: "5327834.fls.doubleclick.net." always_nxdomain
    local-zone: "5u.com." always_nxdomain
    local-zone: "76568fe015f4e521d8ffcbedbdb21147.safeframe.googlesyndication.com." always_nxdomain
    local-zone: "85a534957d864e5a6fa4506755534657.safeframe.googlesyndication.com." always_nxdomain
    local-zone: "9700b3f0337cf55a70939b6ae683c80f.safeframe.googlesyndication.com." always_nxdomain
    local-zone: "a107.casalemedia.com." always_nxdomain
    local-zone: "a8clk.reserve.retty.me." always_nxdomain
    local-zone: "a8clk.www.workport.co.jp." always_nxdomain
    local-zone: "a8cv.english-village.net." always_nxdomain
    local-zone: "abtracker.adultbouncer.com." always_nxdomain
    local-zone: "ads2.contentabc.com." always_nxdomain
    local-zone: "adultmoneymakers.com." always_nxdomain
    local-zone: "adviseaffair.com." always_nxdomain
    local-zone: "affiliation.porn.fr." always_nxdomain
    local-zone: "analytics-api.whitestuff.com." always_nxdomain
    local-zone: "api.ero-advertising.com." always_nxdomain
    local-zone: "app.trustami.com." always_nxdomain
    local-zone: "appsflyersdk.com." always_nxdomain
    local-zone: "aptrinsic.com." always_nxdomain
    local-zone: "awanzi.com." always_nxdomain
    local-zone: "awemdia.com." always_nxdomain
    local-zone: "banganet.com." always_nxdomain
    local-zone: "bannerrotation.sexmoney.com." always_nxdomain
    local-zone: "banners.gayfriendfinder.com." always_nxdomain
    local-zone: "betterxxx.org." always_nxdomain
    local-zone: "bmjvorszopmks.online." always_nxdomain
    local-zone: "bobsleddomesticglandular.com." always_nxdomain
    local-zone: "boffoadsapi.com." always_nxdomain
    local-zone: "bondagevalley.cc." always_nxdomain
    local-zone: "bongacams.com." always_nxdomain
    local-zone: "bouzup.go-static.info." always_nxdomain
    local-zone: "br.meetlocals.com." always_nxdomain
    local-zone: "camvideos.tv." always_nxdomain
    local-zone: "capndr.com." always_nxdomain
    local-zone: "cdn.optimizely.com." always_nxdomain
    local-zone: "citypass.api.useinsider.com." always_nxdomain
    local-zone: "clicker.chiaki.vn." always_nxdomain
    local-zone: "coinurl.com." always_nxdomain
    local-zone: "crdjpq.conversions.appsflyersdk.com." always_nxdomain
    local-zone: "dezcom.com." always_nxdomain
    local-zone: "dj-updates.com." always_nxdomain
    local-zone: "dkonto.pl." always_nxdomain
    local-zone: "elle-relay.iocnt.net." always_nxdomain
    local-zone: "enter.sexlist.com." always_nxdomain
    local-zone: "eroadvertising.com." always_nxdomain
    local-zone: "fetishmegastore.com." always_nxdomain
    local-zone: "flirt.com." always_nxdomain
    local-zone: "fncash.com." always_nxdomain
    local-zone: "g0a9mkllu79zij9g7dusvx15hmjtz1781181727.uaid.nmrodam.com." always_nxdomain
    local-zone: "gateway-studentstaffaccess-owa.my-free.website." always_nxdomain
    local-zone: "ge1uz5f1kunke5i010rsp0imtqrt51783451448.uaid.nmrodam.com." always_nxdomain
    local-zone: "gldrdr.com." always_nxdomain
    local-zone: "globus-inter.com." always_nxdomain
    local-zone: "grahammedia-tagan.adlightning.com." always_nxdomain
    local-zone: "hornymatches.com." always_nxdomain
    local-zone: "hotzxgirl.com." always_nxdomain
    local-zone: "hphyzdfdoh.com." always_nxdomain
    local-zone: "ht-cdn2.contentabc.com." always_nxdomain
    local-zone: "hw-cdn2.contentabc.com." always_nxdomain
    local-zone: "ifa.maxpornlive.com." always_nxdomain
    local-zone: "inostappro.store." always_nxdomain
    local-zone: "integryssjc.d1.sc.omtrdc.net." always_nxdomain
    local-zone: "ixtzad.fetch.co.uk." always_nxdomain
    local-zone: "jackheywood.com." always_nxdomain
    local-zone: "lguvihbqjegvi.website." always_nxdomain
    local-zone: "livecamgirls.streamray.com." always_nxdomain
    local-zone: "livejasmin.com." always_nxdomain
    local-zone: "login.leoyard.com." always_nxdomain
    local-zone: "m2183u.cdn-settings.appsflyersdk.com." always_nxdomain
    local-zone: "marketing.staffboom.com." always_nxdomain
    local-zone: "matomo.research.software." always_nxdomain
    local-zone: "members.sexroulette.com." always_nxdomain
    local-zone: "mt83.mtree.com." always_nxdomain
    local-zone: "mysnap.top." always_nxdomain
    local-zone: "nedderborides.cfd." always_nxdomain
    local-zone: "network.nutaku.net." always_nxdomain
    local-zone: "nuid.nmrodam.com." always_nxdomain
    local-zone: "olimp.com." always_nxdomain
    local-zone: "ourdream.ai." always_nxdomain
    local-zone: "perso.wanadoo.es." always_nxdomain
    local-zone: "plausible.srijn.net." always_nxdomain
    local-zone: "politicalplanets.com." always_nxdomain
    local-zone: "pornamigo.com." always_nxdomain
    local-zone: "preibisch.pl." always_nxdomain
    local-zone: "qvm8ywmayfmr9cgh0gs0gkloqnwwk1774013046.nuid.nmrodam.com." always_nxdomain
    local-zone: "realbiathlon.sportsontheweb.net." always_nxdomain
    local-zone: "safeframe.googlesyndication.com." always_nxdomain
    local-zone: "smetrics.europafm.com." always_nxdomain
    local-zone: "sn-vgqskn6z.c.2mdn.net." always_nxdomain
    local-zone: "st.kompoz2.com." always_nxdomain
    local-zone: "stargames.com." always_nxdomain
    local-zone: "stat.kiwibank.co.nz." always_nxdomain
    local-zone: "streamate.com." always_nxdomain
    local-zone: "strikingdates.com." always_nxdomain
    local-zone: "teenfuckhd.com." always_nxdomain
    local-zone: "tr.bigfuck.tv." always_nxdomain
    local-zone: "ultrapartners.com." always_nxdomain
    local-zone: "vulkan777.net." always_nxdomain
    local-zone: "webpushstat-sgp.engagelab.com." always_nxdomain
    local-zone: "webstatistics.sbg.ac.at." always_nxdomain
    local-zone: "winshark.link." always_nxdomain
    local-zone: "witamina.c.pl." always_nxdomain
    local-zone: "www.bureaucracyembargo.com." always_nxdomain
    local-zone: "www.extremetracking.com." always_nxdomain
    local-zone: "www.fernierragi.shop." always_nxdomain
    local-zone: "www.flylinks.pw." always_nxdomain
    local-zone: "www.jboztgcwxnvoc.website." always_nxdomain
    local-zone: "www.navigablepiercing.com." always_nxdomain
    local-zone: "www.newstopspi.shop." always_nxdomain
    local-zone: "www.potisje.xyz." always_nxdomain
    local-zone: "www.psnzone.com." always_nxdomain
    local-zone: "www.relict.media." always_nxdomain
    local-zone: "www.segoservices.ca." always_nxdomain
    local-zone: "www.sexmoney.com." always_nxdomain
    local-zone: "www.signalayer.com." always_nxdomain
    local-zone: "www.steyrtracteursgmbh.at." always_nxdomain
    local-zone: "www.streamray.com." always_nxdomain
    local-zone: "www.vinted.52535.sbs." always_nxdomain
    local-zone: "www.x4363.com." always_nxdomain
    local-zone: "www.xnqxocz.icu." always_nxdomain
    local-zone: "xbwelj.dreemluv.com." always_nxdomain
    local-zone: "xvideoslive.com." always_nxdomain
    local-zone: "yardaravvi.store." always_nxdomain
    local-zone: "yhy.mybluehost.me." always_nxdomain
    local-zone: "zazporn.com." always_nxdomain
    local-zone: "zdd7r7tnag8jacj1tjjqjlmeiiq461781875904.darnuid.imrworldwide.com." always_nxdomain
    local-zone: "zp.amxpjkhscj24.idy360.com." always_nxdomain
    local-zone: "zz75jt.cdn-settings.appsflyersdk.com." always_nxdomain
    local-zone: "download.db-ip.com." always_transparent
"""

SOURCES["96-secubox-adult.conf"] = """\
# Managed by secubox-adguard-adult-sync (#2964, #2979). DO NOT EDIT BY HAND.
# Regenerate: secubox-adguard-adult-sync sync
server:
    local-zone: "4sex4.com." always_nxdomain
    local-zone: "adult-bank.jp." always_nxdomain
    local-zone: "adultjoy.net." always_nxdomain
    local-zone: "allmaturepornpics.analpleasures.org." always_nxdomain
    local-zone: "amateurfetishist.com." always_nxdomain
    local-zone: "analbest.com." always_nxdomain
    local-zone: "analxxx.one." always_nxdomain
    local-zone: "asstraffic.com." always_nxdomain
    local-zone: "azporncomics.com." always_nxdomain
    local-zone: "bestiality.video." always_nxdomain
    local-zone: "boycam.net." always_nxdomain
    local-zone: "bustymaturemom.com." always_nxdomain
    local-zone: "cartoonpornvids.com." always_nxdomain
    local-zone: "cdn03.porn-fap.com." always_nxdomain
    local-zone: "cdn1-static-cf.gotporn.com." always_nxdomain
    local-zone: "cdn1.18teen-tube.com." always_nxdomain
    local-zone: "cdn1.pornv.xxx." always_nxdomain
    local-zone: "cdn6.porn-hd.xxx." always_nxdomain
    local-zone: "cdn6.youngsexer.com." always_nxdomain
    local-zone: "cn.eroticxgirl.com." always_nxdomain
    local-zone: "desi-sex-video.com." always_nxdomain
    local-zone: "epornerpics.com." always_nxdomain
    local-zone: "eroticxpic.com." always_nxdomain
    local-zone: "estiloporno.com." always_nxdomain
    local-zone: "fakboi.org." always_nxdomain
    local-zone: "favgayporn.com." always_nxdomain
    local-zone: "foxxx.hu." always_nxdomain
    local-zone: "freepornolinks.com." always_nxdomain
    local-zone: "freeteenworld.com." always_nxdomain
    local-zone: "freexxxhindi.com." always_nxdomain
    local-zone: "g.ebalka.nl." always_nxdomain
    local-zone: "gatasdovale.com." always_nxdomain
    local-zone: "getsexgames.com." always_nxdomain
    local-zone: "gifcandy-net.ru." always_nxdomain
    local-zone: "gizlihikaye.com." always_nxdomain
    local-zone: "gooxh.life." always_nxdomain
    local-zone: "hdpornm.com." always_nxdomain
    local-zone: "hdpornos.deutschporner.com." always_nxdomain
    local-zone: "hr.hanime.tv." always_nxdomain
    local-zone: "icpornvids.com." always_nxdomain
    local-zone: "img5.cutexgirl.com." always_nxdomain
    local-zone: "imgr4.sakuraxgirl.com." always_nxdomain
    local-zone: "imgr7.thongxxx.com." always_nxdomain
    local-zone: "imgre.perfectxbody.com." always_nxdomain
    local-zone: "ipornu.com." always_nxdomain
    local-zone: "irxclip.com." always_nxdomain
    local-zone: "javhd.icu." always_nxdomain
    local-zone: "kittysbeast.com." always_nxdomain
    local-zone: "landers.cam4.de.com." always_nxdomain
    local-zone: "manymv.com." always_nxdomain
    local-zone: "maturesluts.tv." always_nxdomain
    local-zone: "media.kolyomfilm.com." always_nxdomain
    local-zone: "milfslesbian.com." always_nxdomain
    local-zone: "mk.bimbolive.com." always_nxdomain
    local-zone: "mupvl.org." always_nxdomain
    local-zone: "netporn.net." always_nxdomain
    local-zone: "nikki-brooks.ru." always_nxdomain
    local-zone: "nlv14.hdsex.org." always_nxdomain
    local-zone: "nudehairygirls.com." always_nxdomain
    local-zone: "nutten.at." always_nxdomain
    local-zone: "ok.fapnado.com." always_nxdomain
    local-zone: "outinpublic.com." always_nxdomain
    local-zone: "p173084119.ahcdn.com." always_nxdomain
    local-zone: "pinkteenseries.com." always_nxdomain
    local-zone: "plexxxx.org." always_nxdomain
    local-zone: "porhubvideo.com." always_nxdomain
    local-zone: "porn.org." always_nxdomain
    local-zone: "pornmd.click." always_nxdomain
    local-zone: "pornoktube.com." always_nxdomain
    local-zone: "pornomeg.com." always_nxdomain
    local-zone: "provencart.com." always_nxdomain
    local-zone: "pussypornpics.com." always_nxdomain
    local-zone: "rapeinass.com." always_nxdomain
    local-zone: "razvratnoe.pro." always_nxdomain
    local-zone: "ruleporn-com.pornproxy.app." always_nxdomain
    local-zone: "seattlehairygirls.com." always_nxdomain
    local-zone: "sex.chupando.org." always_nxdomain
    local-zone: "sexadept.com." always_nxdomain
    local-zone: "sexdollcenter.vip." always_nxdomain
    local-zone: "sexpornasian.com." always_nxdomain
    local-zone: "sexymetas.com." always_nxdomain
    local-zone: "sexyxart.com." always_nxdomain
    local-zone: "sohot.cyou." always_nxdomain
    local-zone: "striplivecams.com." always_nxdomain
    local-zone: "tlsext.com." always_nxdomain
    local-zone: "toppornovideo.link." always_nxdomain
    local-zone: "trailers.spritzz.com." always_nxdomain
    local-zone: "tubent.com." always_nxdomain
    local-zone: "tubevideoshd.xxx." always_nxdomain
    local-zone: "ufym.info." always_nxdomain
    local-zone: "uzbak.ru." always_nxdomain
    local-zone: "vintage-sex.pro." always_nxdomain
    local-zone: "whentai.com." always_nxdomain
    local-zone: "www.54647.io." always_nxdomain
    local-zone: "www.arabyneek.com." always_nxdomain
    local-zone: "www.bdsmpichunter.com." always_nxdomain
    local-zone: "www.cartoonxxxpics.com." always_nxdomain
    local-zone: "www.dirtyshack.com." always_nxdomain
    local-zone: "www.doctorvoluptua.com." always_nxdomain
    local-zone: "www.equine.gq." always_nxdomain
    local-zone: "www.freesexgame.net." always_nxdomain
    local-zone: "www.g-1.ch." always_nxdomain
    local-zone: "www.laura-angel.com." always_nxdomain
    local-zone: "www.phimsexs.net." always_nxdomain
    local-zone: "www.porndish.com." always_nxdomain
    local-zone: "www.porneskimo.com." always_nxdomain
    local-zone: "www.pornfree.beauty." always_nxdomain
    local-zone: "www.porno-wonder.com." always_nxdomain
    local-zone: "www.pornvideoboom.com." always_nxdomain
    local-zone: "www.propertysex.com." always_nxdomain
    local-zone: "www.seneporno.com." always_nxdomain
    local-zone: "www.sharpporn.com." always_nxdomain
    local-zone: "www.static.filestube.com." always_nxdomain
    local-zone: "www.tube4ace.com." always_nxdomain
    local-zone: "www.yetiporntube.com." always_nxdomain
    local-zone: "xhname.com." always_nxdomain
    local-zone: "xnpornvidz.com." always_nxdomain
    local-zone: "xtorjack.com." always_nxdomain
    local-zone: "xxx-video.mobi." always_nxdomain
    local-zone: "zoofilialovers.com." always_nxdomain
    local-zone-override: "4sex4.com." 192.168.1.3 always_transparent
    local-zone-override: "ads2.contentabc.com." 192.168.1.3 always_transparent
    local-zone-override: "adult-bank.jp." 192.168.1.3 always_transparent
    local-zone-override: "adultjoy.net." 192.168.1.3 always_transparent
    local-zone-override: "adultmoneymakers.com." 192.168.1.3 always_transparent
    local-zone-override: "affiliation.porn.fr." 192.168.1.3 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 192.168.1.3 always_transparent
    local-zone-override: "amateurfetishist.com." 192.168.1.3 always_transparent
    local-zone-override: "analbest.com." 192.168.1.3 always_transparent
    local-zone-override: "analxxx.one." 192.168.1.3 always_transparent
    local-zone-override: "api.ero-advertising.com." 192.168.1.3 always_transparent
    local-zone-override: "asstraffic.com." 192.168.1.3 always_transparent
    local-zone-override: "awemdia.com." 192.168.1.3 always_transparent
    local-zone-override: "azporncomics.com." 192.168.1.3 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 192.168.1.3 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 192.168.1.3 always_transparent
    local-zone-override: "bestiality.video." 192.168.1.3 always_transparent
    local-zone-override: "betterxxx.org." 192.168.1.3 always_transparent
    local-zone-override: "bondagevalley.cc." 192.168.1.3 always_transparent
    local-zone-override: "bongacams.com." 192.168.1.3 always_transparent
    local-zone-override: "boycam.net." 192.168.1.3 always_transparent
    local-zone-override: "br.meetlocals.com." 192.168.1.3 always_transparent
    local-zone-override: "bustymaturemom.com." 192.168.1.3 always_transparent
    local-zone-override: "camvideos.tv." 192.168.1.3 always_transparent
    local-zone-override: "cartoonpornvids.com." 192.168.1.3 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 192.168.1.3 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 192.168.1.3 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 192.168.1.3 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 192.168.1.3 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 192.168.1.3 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 192.168.1.3 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 192.168.1.3 always_transparent
    local-zone-override: "desi-sex-video.com." 192.168.1.3 always_transparent
    local-zone-override: "enter.sexlist.com." 192.168.1.3 always_transparent
    local-zone-override: "epornerpics.com." 192.168.1.3 always_transparent
    local-zone-override: "eroadvertising.com." 192.168.1.3 always_transparent
    local-zone-override: "eroticxpic.com." 192.168.1.3 always_transparent
    local-zone-override: "estiloporno.com." 192.168.1.3 always_transparent
    local-zone-override: "fakboi.org." 192.168.1.3 always_transparent
    local-zone-override: "favgayporn.com." 192.168.1.3 always_transparent
    local-zone-override: "flirt.com." 192.168.1.3 always_transparent
    local-zone-override: "fncash.com." 192.168.1.3 always_transparent
    local-zone-override: "foxxx.hu." 192.168.1.3 always_transparent
    local-zone-override: "freepornolinks.com." 192.168.1.3 always_transparent
    local-zone-override: "freeteenworld.com." 192.168.1.3 always_transparent
    local-zone-override: "freexxxhindi.com." 192.168.1.3 always_transparent
    local-zone-override: "g.ebalka.nl." 192.168.1.3 always_transparent
    local-zone-override: "gatasdovale.com." 192.168.1.3 always_transparent
    local-zone-override: "getsexgames.com." 192.168.1.3 always_transparent
    local-zone-override: "gifcandy-net.ru." 192.168.1.3 always_transparent
    local-zone-override: "gizlihikaye.com." 192.168.1.3 always_transparent
    local-zone-override: "gldrdr.com." 192.168.1.3 always_transparent
    local-zone-override: "gooxh.life." 192.168.1.3 always_transparent
    local-zone-override: "hdpornm.com." 192.168.1.3 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 192.168.1.3 always_transparent
    local-zone-override: "hornymatches.com." 192.168.1.3 always_transparent
    local-zone-override: "hotzxgirl.com." 192.168.1.3 always_transparent
    local-zone-override: "hr.hanime.tv." 192.168.1.3 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 192.168.1.3 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 192.168.1.3 always_transparent
    local-zone-override: "icpornvids.com." 192.168.1.3 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 192.168.1.3 always_transparent
    local-zone-override: "img5.cutexgirl.com." 192.168.1.3 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 192.168.1.3 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 192.168.1.3 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 192.168.1.3 always_transparent
    local-zone-override: "ipornu.com." 192.168.1.3 always_transparent
    local-zone-override: "irxclip.com." 192.168.1.3 always_transparent
    local-zone-override: "javhd.icu." 192.168.1.3 always_transparent
    local-zone-override: "kittysbeast.com." 192.168.1.3 always_transparent
    local-zone-override: "landers.cam4.de.com." 192.168.1.3 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 192.168.1.3 always_transparent
    local-zone-override: "livejasmin.com." 192.168.1.3 always_transparent
    local-zone-override: "manymv.com." 192.168.1.3 always_transparent
    local-zone-override: "maturesluts.tv." 192.168.1.3 always_transparent
    local-zone-override: "media.kolyomfilm.com." 192.168.1.3 always_transparent
    local-zone-override: "members.sexroulette.com." 192.168.1.3 always_transparent
    local-zone-override: "milfslesbian.com." 192.168.1.3 always_transparent
    local-zone-override: "mk.bimbolive.com." 192.168.1.3 always_transparent
    local-zone-override: "mt83.mtree.com." 192.168.1.3 always_transparent
    local-zone-override: "mupvl.org." 192.168.1.3 always_transparent
    local-zone-override: "mysnap.top." 192.168.1.3 always_transparent
    local-zone-override: "netporn.net." 192.168.1.3 always_transparent
    local-zone-override: "network.nutaku.net." 192.168.1.3 always_transparent
    local-zone-override: "nikki-brooks.ru." 192.168.1.3 always_transparent
    local-zone-override: "nlv14.hdsex.org." 192.168.1.3 always_transparent
    local-zone-override: "nudehairygirls.com." 192.168.1.3 always_transparent
    local-zone-override: "nutten.at." 192.168.1.3 always_transparent
    local-zone-override: "ok.fapnado.com." 192.168.1.3 always_transparent
    local-zone-override: "ourdream.ai." 192.168.1.3 always_transparent
    local-zone-override: "outinpublic.com." 192.168.1.3 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 192.168.1.3 always_transparent
    local-zone-override: "pinkteenseries.com." 192.168.1.3 always_transparent
    local-zone-override: "plexxxx.org." 192.168.1.3 always_transparent
    local-zone-override: "porhubvideo.com." 192.168.1.3 always_transparent
    local-zone-override: "porn.org." 192.168.1.3 always_transparent
    local-zone-override: "pornamigo.com." 192.168.1.3 always_transparent
    local-zone-override: "pornmd.click." 192.168.1.3 always_transparent
    local-zone-override: "pornoktube.com." 192.168.1.3 always_transparent
    local-zone-override: "pornomeg.com." 192.168.1.3 always_transparent
    local-zone-override: "provencart.com." 192.168.1.3 always_transparent
    local-zone-override: "pussypornpics.com." 192.168.1.3 always_transparent
    local-zone-override: "rapeinass.com." 192.168.1.3 always_transparent
    local-zone-override: "razvratnoe.pro." 192.168.1.3 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 192.168.1.3 always_transparent
    local-zone-override: "seattlehairygirls.com." 192.168.1.3 always_transparent
    local-zone-override: "sex.chupando.org." 192.168.1.3 always_transparent
    local-zone-override: "sexadept.com." 192.168.1.3 always_transparent
    local-zone-override: "sexdollcenter.vip." 192.168.1.3 always_transparent
    local-zone-override: "sexpornasian.com." 192.168.1.3 always_transparent
    local-zone-override: "sexymetas.com." 192.168.1.3 always_transparent
    local-zone-override: "sexyxart.com." 192.168.1.3 always_transparent
    local-zone-override: "sohot.cyou." 192.168.1.3 always_transparent
    local-zone-override: "st.kompoz2.com." 192.168.1.3 always_transparent
    local-zone-override: "streamate.com." 192.168.1.3 always_transparent
    local-zone-override: "striplivecams.com." 192.168.1.3 always_transparent
    local-zone-override: "teenfuckhd.com." 192.168.1.3 always_transparent
    local-zone-override: "tlsext.com." 192.168.1.3 always_transparent
    local-zone-override: "toppornovideo.link." 192.168.1.3 always_transparent
    local-zone-override: "tr.bigfuck.tv." 192.168.1.3 always_transparent
    local-zone-override: "trailers.spritzz.com." 192.168.1.3 always_transparent
    local-zone-override: "tubent.com." 192.168.1.3 always_transparent
    local-zone-override: "tubevideoshd.xxx." 192.168.1.3 always_transparent
    local-zone-override: "ufym.info." 192.168.1.3 always_transparent
    local-zone-override: "ultrapartners.com." 192.168.1.3 always_transparent
    local-zone-override: "uzbak.ru." 192.168.1.3 always_transparent
    local-zone-override: "vintage-sex.pro." 192.168.1.3 always_transparent
    local-zone-override: "whentai.com." 192.168.1.3 always_transparent
    local-zone-override: "www.54647.io." 192.168.1.3 always_transparent
    local-zone-override: "www.arabyneek.com." 192.168.1.3 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 192.168.1.3 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 192.168.1.3 always_transparent
    local-zone-override: "www.dirtyshack.com." 192.168.1.3 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 192.168.1.3 always_transparent
    local-zone-override: "www.equine.gq." 192.168.1.3 always_transparent
    local-zone-override: "www.extremetracking.com." 192.168.1.3 always_transparent
    local-zone-override: "www.freesexgame.net." 192.168.1.3 always_transparent
    local-zone-override: "www.g-1.ch." 192.168.1.3 always_transparent
    local-zone-override: "www.laura-angel.com." 192.168.1.3 always_transparent
    local-zone-override: "www.phimsexs.net." 192.168.1.3 always_transparent
    local-zone-override: "www.porndish.com." 192.168.1.3 always_transparent
    local-zone-override: "www.porneskimo.com." 192.168.1.3 always_transparent
    local-zone-override: "www.pornfree.beauty." 192.168.1.3 always_transparent
    local-zone-override: "www.porno-wonder.com." 192.168.1.3 always_transparent
    local-zone-override: "www.pornvideoboom.com." 192.168.1.3 always_transparent
    local-zone-override: "www.propertysex.com." 192.168.1.3 always_transparent
    local-zone-override: "www.seneporno.com." 192.168.1.3 always_transparent
    local-zone-override: "www.sexmoney.com." 192.168.1.3 always_transparent
    local-zone-override: "www.sharpporn.com." 192.168.1.3 always_transparent
    local-zone-override: "www.static.filestube.com." 192.168.1.3 always_transparent
    local-zone-override: "www.streamray.com." 192.168.1.3 always_transparent
    local-zone-override: "www.tube4ace.com." 192.168.1.3 always_transparent
    local-zone-override: "www.yetiporntube.com." 192.168.1.3 always_transparent
    local-zone-override: "xhname.com." 192.168.1.3 always_transparent
    local-zone-override: "xnpornvidz.com." 192.168.1.3 always_transparent
    local-zone-override: "xtorjack.com." 192.168.1.3 always_transparent
    local-zone-override: "xvideoslive.com." 192.168.1.3 always_transparent
    local-zone-override: "xxx-video.mobi." 192.168.1.3 always_transparent
    local-zone-override: "zoofilialovers.com." 192.168.1.3 always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::3 always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::e always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::e always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::e always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::e always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::e always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::e always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::e always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::e always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::e always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::e always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::e always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::e always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::e always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::e always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::e always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::e always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::e always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::e always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::e always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::e always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::e always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::e always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::f always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::f always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::f always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::f always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::f always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::f always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::f always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::f always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::f always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::f always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::f always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::f always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::f always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::f always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::f always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::f always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::f always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::f always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::f always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::f always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::f always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::f always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::10 always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::11 always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::12 always_transparent
    local-zone-override: "4sex4.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ads2.contentabc.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "adult-bank.jp." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "adultjoy.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "adultmoneymakers.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "affiliation.porn.fr." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "allmaturepornpics.analpleasures.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "amateurfetishist.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "analbest.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "analxxx.one." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "api.ero-advertising.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "asstraffic.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "awemdia.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "azporncomics.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "bannerrotation.sexmoney.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "banners.gayfriendfinder.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "bestiality.video." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "betterxxx.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "bondagevalley.cc." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "bongacams.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "boycam.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "br.meetlocals.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "bustymaturemom.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "camvideos.tv." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cartoonpornvids.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn03.porn-fap.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn1-static-cf.gotporn.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn1.18teen-tube.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn1.pornv.xxx." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn6.porn-hd.xxx." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cdn6.youngsexer.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "cn.eroticxgirl.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "desi-sex-video.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "enter.sexlist.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "epornerpics.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "eroadvertising.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "eroticxpic.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "estiloporno.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "fakboi.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "favgayporn.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "flirt.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "fncash.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "foxxx.hu." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "freepornolinks.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "freeteenworld.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "freexxxhindi.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "g.ebalka.nl." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "gatasdovale.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "getsexgames.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "gifcandy-net.ru." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "gizlihikaye.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "gldrdr.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "gooxh.life." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hdpornm.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hdpornos.deutschporner.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hornymatches.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hotzxgirl.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hr.hanime.tv." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ht-cdn2.contentabc.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "hw-cdn2.contentabc.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "icpornvids.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ifa.maxpornlive.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "img5.cutexgirl.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "imgr4.sakuraxgirl.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "imgr7.thongxxx.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "imgre.perfectxbody.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ipornu.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "irxclip.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "javhd.icu." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "kittysbeast.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "landers.cam4.de.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "livecamgirls.streamray.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "livejasmin.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "manymv.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "maturesluts.tv." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "media.kolyomfilm.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "members.sexroulette.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "milfslesbian.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "mk.bimbolive.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "mt83.mtree.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "mupvl.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "mysnap.top." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "netporn.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "network.nutaku.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "nikki-brooks.ru." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "nlv14.hdsex.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "nudehairygirls.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "nutten.at." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ok.fapnado.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ourdream.ai." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "outinpublic.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "p173084119.ahcdn.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pinkteenseries.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "plexxxx.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "porhubvideo.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "porn.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pornamigo.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pornmd.click." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pornoktube.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pornomeg.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "provencart.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "pussypornpics.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "rapeinass.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "razvratnoe.pro." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ruleporn-com.pornproxy.app." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "seattlehairygirls.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sex.chupando.org." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sexadept.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sexdollcenter.vip." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sexpornasian.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sexymetas.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sexyxart.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "sohot.cyou." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "st.kompoz2.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "streamate.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "striplivecams.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "teenfuckhd.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "tlsext.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "toppornovideo.link." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "tr.bigfuck.tv." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "trailers.spritzz.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "tubent.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "tubevideoshd.xxx." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ufym.info." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "ultrapartners.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "uzbak.ru." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "vintage-sex.pro." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "whentai.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.54647.io." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.arabyneek.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.bdsmpichunter.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.cartoonxxxpics.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.dirtyshack.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.doctorvoluptua.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.equine.gq." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.extremetracking.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.freesexgame.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.g-1.ch." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.laura-angel.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.phimsexs.net." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.porndish.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.porneskimo.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.pornfree.beauty." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.porno-wonder.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.pornvideoboom.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.propertysex.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.seneporno.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.sexmoney.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.sharpporn.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.static.filestube.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.streamray.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.tube4ace.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "www.yetiporntube.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "xhname.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "xnpornvidz.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "xtorjack.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "xvideoslive.com." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "xxx-video.mobi." 2001:db8:c4e0::13 always_transparent
    local-zone-override: "zoofilialovers.com." 2001:db8:c4e0::13 always_transparent
"""

ADULTE = [
    "4sex4.com",
    "ads2.contentabc.com",
    "adult-bank.jp",
    "adultjoy.net",
    "adultmoneymakers.com",
    "affiliation.porn.fr",
    "allmaturepornpics.analpleasures.org",
    "amateurfetishist.com",
    "analbest.com",
    "analxxx.one",
    "api.ero-advertising.com",
    "asstraffic.com",
    "awemdia.com",
    "azporncomics.com",
    "bannerrotation.sexmoney.com",
    "banners.gayfriendfinder.com",
    "bestiality.video",
    "betterxxx.org",
    "bondagevalley.cc",
    "bongacams.com",
    "boycam.net",
    "br.meetlocals.com",
    "bustymaturemom.com",
    "camvideos.tv",
    "cartoonpornvids.com",
    "cdn03.porn-fap.com",
    "cdn1-static-cf.gotporn.com",
    "cdn1.18teen-tube.com",
    "cdn1.pornv.xxx",
    "cdn6.porn-hd.xxx",
    "cdn6.youngsexer.com",
    "cn.eroticxgirl.com",
    "desi-sex-video.com",
    "enter.sexlist.com",
    "epornerpics.com",
    "eroadvertising.com",
    "eroticxpic.com",
    "estiloporno.com",
    "fakboi.org",
    "favgayporn.com",
    "flirt.com",
    "fncash.com",
    "foxxx.hu",
    "freepornolinks.com",
    "freeteenworld.com",
    "freexxxhindi.com",
    "g.ebalka.nl",
    "gatasdovale.com",
    "getsexgames.com",
    "gifcandy-net.ru",
    "gizlihikaye.com",
    "gldrdr.com",
    "gooxh.life",
    "hdpornm.com",
    "hdpornos.deutschporner.com",
    "hornymatches.com",
    "hotzxgirl.com",
    "hr.hanime.tv",
    "ht-cdn2.contentabc.com",
    "hw-cdn2.contentabc.com",
    "icpornvids.com",
    "ifa.maxpornlive.com",
    "img5.cutexgirl.com",
    "imgr4.sakuraxgirl.com",
    "imgr7.thongxxx.com",
    "imgre.perfectxbody.com",
    "ipornu.com",
    "irxclip.com",
    "javhd.icu",
    "kittysbeast.com",
    "landers.cam4.de.com",
    "livecamgirls.streamray.com",
    "livejasmin.com",
    "manymv.com",
    "maturesluts.tv",
    "media.kolyomfilm.com",
    "members.sexroulette.com",
    "milfslesbian.com",
    "mk.bimbolive.com",
    "mt83.mtree.com",
    "mupvl.org",
    "mysnap.top",
    "netporn.net",
    "network.nutaku.net",
    "nikki-brooks.ru",
    "nlv14.hdsex.org",
    "nudehairygirls.com",
    "nutten.at",
    "ok.fapnado.com",
    "ourdream.ai",
    "outinpublic.com",
    "p173084119.ahcdn.com",
    "pinkteenseries.com",
    "plexxxx.org",
    "porhubvideo.com",
    "porn.org",
    "pornamigo.com",
    "pornmd.click",
    "pornoktube.com",
    "pornomeg.com",
    "provencart.com",
    "pussypornpics.com",
    "rapeinass.com",
    "razvratnoe.pro",
    "ruleporn-com.pornproxy.app",
    "seattlehairygirls.com",
    "sex.chupando.org",
    "sexadept.com",
    "sexdollcenter.vip",
    "sexpornasian.com",
    "sexymetas.com",
    "sexyxart.com",
    "sohot.cyou",
    "st.kompoz2.com",
    "streamate.com",
    "striplivecams.com",
    "teenfuckhd.com",
    "tlsext.com",
    "toppornovideo.link",
    "tr.bigfuck.tv",
    "trailers.spritzz.com",
    "tubent.com",
    "tubevideoshd.xxx",
    "ufym.info",
    "ultrapartners.com",
    "uzbak.ru",
    "vintage-sex.pro",
    "whentai.com",
    "www.54647.io",
    "www.arabyneek.com",
    "www.bdsmpichunter.com",
    "www.cartoonxxxpics.com",
    "www.dirtyshack.com",
    "www.doctorvoluptua.com",
    "www.equine.gq",
    "www.extremetracking.com",
    "www.freesexgame.net",
    "www.g-1.ch",
    "www.laura-angel.com",
    "www.phimsexs.net",
    "www.porndish.com",
    "www.porneskimo.com",
    "www.pornfree.beauty",
    "www.porno-wonder.com",
    "www.pornvideoboom.com",
    "www.propertysex.com",
    "www.seneporno.com",
    "www.sexmoney.com",
    "www.sharpporn.com",
    "www.static.filestube.com",
    "www.streamray.com",
    "www.tube4ace.com",
    "www.yetiporntube.com",
    "xhname.com",
    "xnpornvidz.com",
    "xtorjack.com",
    "xvideoslive.com",
    "xxx-video.mobi",
    "zoofilialovers.com",
]

GENERAL = [
    "1025kmgi.rocks",
    "17746183664520db71d564833bff22169ae2b5b12b7402c437539787.trk.sensic.net",
    "1784827726598b9a34099f4f9920e1fa72ecd1040b0ed0978855db71.trk.sensic.net",
    "1goldenstar-casino.com",
    "3e888f65aad8d2c22f1d60102200ca04.safeframe.googlesyndication.com",
    "5327834.fls.doubleclick.net",
    "5u.com",
    "76568fe015f4e521d8ffcbedbdb21147.safeframe.googlesyndication.com",
    "85a534957d864e5a6fa4506755534657.safeframe.googlesyndication.com",
    "9700b3f0337cf55a70939b6ae683c80f.safeframe.googlesyndication.com",
    "a107.casalemedia.com",
    "a8clk.reserve.retty.me",
    "a8clk.www.workport.co.jp",
    "a8cv.english-village.net",
    "abtracker.adultbouncer.com",
    "ads2.contentabc.com",
    "adultmoneymakers.com",
    "adviseaffair.com",
    "affiliation.porn.fr",
    "analytics-api.whitestuff.com",
    "api.ero-advertising.com",
    "app.trustami.com",
    "appsflyersdk.com",
    "aptrinsic.com",
    "awanzi.com",
    "awemdia.com",
    "banganet.com",
    "bannerrotation.sexmoney.com",
    "banners.gayfriendfinder.com",
    "betterxxx.org",
    "bmjvorszopmks.online",
    "bobsleddomesticglandular.com",
    "boffoadsapi.com",
    "bondagevalley.cc",
    "bongacams.com",
    "bouzup.go-static.info",
    "br.meetlocals.com",
    "camvideos.tv",
    "capndr.com",
    "cdn.optimizely.com",
    "citypass.api.useinsider.com",
    "clicker.chiaki.vn",
    "coinurl.com",
    "crdjpq.conversions.appsflyersdk.com",
    "dezcom.com",
    "dj-updates.com",
    "dkonto.pl",
    "download.db-ip.com",
    "elle-relay.iocnt.net",
    "enter.sexlist.com",
    "eroadvertising.com",
    "fetishmegastore.com",
    "flirt.com",
    "fncash.com",
    "g0a9mkllu79zij9g7dusvx15hmjtz1781181727.uaid.nmrodam.com",
    "gateway-studentstaffaccess-owa.my-free.website",
    "ge1uz5f1kunke5i010rsp0imtqrt51783451448.uaid.nmrodam.com",
    "gldrdr.com",
    "globus-inter.com",
    "grahammedia-tagan.adlightning.com",
    "hornymatches.com",
    "hotzxgirl.com",
    "hphyzdfdoh.com",
    "ht-cdn2.contentabc.com",
    "hw-cdn2.contentabc.com",
    "ifa.maxpornlive.com",
    "inostappro.store",
    "integryssjc.d1.sc.omtrdc.net",
    "ixtzad.fetch.co.uk",
    "jackheywood.com",
    "lguvihbqjegvi.website",
    "livecamgirls.streamray.com",
    "livejasmin.com",
    "login.leoyard.com",
    "m2183u.cdn-settings.appsflyersdk.com",
    "marketing.staffboom.com",
    "matomo.research.software",
    "members.sexroulette.com",
    "mt83.mtree.com",
    "mysnap.top",
    "nedderborides.cfd",
    "network.nutaku.net",
    "nuid.nmrodam.com",
    "olimp.com",
    "ourdream.ai",
    "perso.wanadoo.es",
    "plausible.srijn.net",
    "politicalplanets.com",
    "pornamigo.com",
    "preibisch.pl",
    "qvm8ywmayfmr9cgh0gs0gkloqnwwk1774013046.nuid.nmrodam.com",
    "realbiathlon.sportsontheweb.net",
    "safeframe.googlesyndication.com",
    "smetrics.europafm.com",
    "sn-vgqskn6z.c.2mdn.net",
    "st.kompoz2.com",
    "stargames.com",
    "stat.kiwibank.co.nz",
    "streamate.com",
    "strikingdates.com",
    "teenfuckhd.com",
    "tr.bigfuck.tv",
    "ultrapartners.com",
    "vulkan777.net",
    "webpushstat-sgp.engagelab.com",
    "webstatistics.sbg.ac.at",
    "winshark.link",
    "witamina.c.pl",
    "www.bureaucracyembargo.com",
    "www.extremetracking.com",
    "www.fernierragi.shop",
    "www.flylinks.pw",
    "www.jboztgcwxnvoc.website",
    "www.navigablepiercing.com",
    "www.newstopspi.shop",
    "www.potisje.xyz",
    "www.psnzone.com",
    "www.relict.media",
    "www.segoservices.ca",
    "www.sexmoney.com",
    "www.signalayer.com",
    "www.steyrtracteursgmbh.at",
    "www.streamray.com",
    "www.vinted.52535.sbs",
    "www.x4363.com",
    "www.xnqxocz.icu",
    "xbwelj.dreemluv.com",
    "xvideoslive.com",
    "yardaravvi.store",
    "yhy.mybluehost.me",
    "zazporn.com",
    "zdd7r7tnag8jacj1tjjqjlmeiiq461781875904.darnuid.imrworldwide.com",
    "zp.amxpjkhscj24.idy360.com",
    "zz75jt.cdn-settings.appsflyersdk.com",
]

EXEMPTES = [
    "192.168.1.3",
    "2001:db8:c4e0::3",
    "2001:db8:c4e0::e",
    "2001:db8:c4e0::f",
    "2001:db8:c4e0::10",
    "2001:db8:c4e0::11",
    "2001:db8:c4e0::12",
    "2001:db8:c4e0::13",
]
