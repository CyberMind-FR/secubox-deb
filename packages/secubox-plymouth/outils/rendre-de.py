# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Hors construction : régénère les images du thème depuis le vrai moteur sbx-dice.js (#3525).
import base64,sys,math,functools,http.server,threading,os
from playwright.sync_api import sync_playwright
hall,out=sys.argv[1],sys.argv[2]; N=90; TAILLE=880; SORTIE=260
os.chdir(hall)
srv=http.server.ThreadingHTTPServer(("127.0.0.1",8767),http.server.SimpleHTTPRequestHandler); threading.Thread(target=srv.serve_forever,daemon=True).start()
with sync_playwright() as p:
    b=p.chromium.launch(); g=b.new_page(viewport={"width":1000,"height":1000},device_scale_factor=1)
    g.route("**/rendu.html",lambda r:r.fulfill(content_type="text/html",body=f'<!doctype html><body style="background:transparent"><script src="/sbx-dice.js"></script><sbx-dice id=d size="{TAILLE}" speed="4" fov="40"></sbx-dice></body>'))
    g.goto("http://127.0.0.1:8767/rendu.html")
    g.wait_for_timeout(1500)
    print(g.evaluate("(()=>{const d=document.getElementById('d');return [!!d._dessine,d._cv&&d._cv.width]})()"))
    for k in range(N):
        a=2*math.pi*k/N
        u=g.evaluate("""([ax,ay,az])=>{const d=document.getElementById('d');cancelAnimationFrame(d._raf);d._ax=ax;d._ay=ay;d._az=az;d._dessine();const W=d._cv.width,x=W*0.04,t=W*0.92,c=document.createElement('canvas');c.width=c.height=SORTIE;const q=c.getContext('2d');q.imageSmoothingQuality='high';q.filter='brightness(1.9) saturate(1.1)';q.drawImage(d._cv,x,x,t,t,0,0,SORTIE,SORTIE);return c.toDataURL('image/png')}""".replace("SORTIE",str(SORTIE)),[a,2*a,a])
        open(f"{out}/de-{k:02d}.png","wb").write(base64.b64decode(u.split(",")[1]))
    g2=b.new_page(viewport={"width":1620,"height":275})
    g2.goto("about:blank")
    import base64 as B
    tags="".join(f'<img src="data:image/png;base64,{B.b64encode(open(f"{out}/de-{k:02d}.png","rb").read()).decode()}">' for k in range(0,N,15))
    g2.set_content(f'<body style="margin:6px;background:#060d1b">{tags}</body>'); g2.wait_for_timeout(300); g2.screenshot(path=f"{out}/../planche.png")
srv.shutdown()
