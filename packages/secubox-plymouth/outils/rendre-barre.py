# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Hors construction : régénère les images du thème depuis le vrai moteur sbx-dice.js (#3525).
import base64,sys
from playwright.sync_api import sync_playwright
out=sys.argv[1]
JS="""([w,h,kind])=>{const c=document.createElement('canvas');c.width=w;c.height=h;const q=c.getContext('2d');q.beginPath();q.roundRect(0,0,w,h,h/2);
if(kind==='fond'){q.fillStyle='rgba(159,179,214,.16)';q.fill();q.strokeStyle='rgba(86,150,255,.38)';q.stroke();}
else{const g=q.createLinearGradient(0,0,w,0);g.addColorStop(0,'#29b6f6');g.addColorStop(1,'#3b82f6');q.fillStyle=g;q.fill();}
return c.toDataURL('image/png')}"""
with sync_playwright() as p:
    g=p.chromium.launch().new_page()
    for n,w,h,k in (("barre-fond",360,8,"fond"),("barre",360,8,"plein")):
        open(f"{out}/{n}.png","wb").write(base64.b64decode(g.evaluate(JS,[w,h,k]).split(",")[1]))
