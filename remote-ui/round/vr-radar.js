// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Virtual Round - TRUE HEXAGON layout (60° spacing)
const VR_CX = 160, VR_CY = 160;

// Rings outer to inner
const VR_RINGS = [
  {color:'#ff3030', r:145, w:5, key:'cpu'},   // RED - AUTH
  {color:'#ff8800', r:132, w:5, key:'mem'},   // ORANGE - WALL
  {color:'#ffdd00', r:119, w:5, key:'disk'},  // YELLOW - BOOT
  {color:'#00dd66', r:106, w:5, key:'temp'},  // GREEN - ROOT
  {color:'#0099ff', r:93,  w:5, key:'net'},   // BLUE - MESH
  {color:'#9944ff', r:80,  w:5, key:'load'},  // VIOLET - MIND
];

// TRUE HEXAGON - 60° intervals, starting from top (-90°)
const POD_R = 52;
const VR_PODS = [
  {id:'boot',  a: -90,  color:'#ffdd00'},  // TOP - yellow
  {id:'auth',  a: -30,  color:'#ff3030'},  // TOP-RIGHT - red
  {id:'wall',  a:  30,  color:'#ff8800'},  // BOTTOM-RIGHT - orange
  {id:'root',  a:  90,  color:'#00dd66'},  // BOTTOM - green
  {id:'mesh',  a: 150,  color:'#0099ff'},  // BOTTOM-LEFT - blue
  {id:'mind',  a: 210,  color:'#9944ff'},  // TOP-LEFT - violet
];

let vrCanvas, vrCtx, vrAngle = 0;
let vrM = {cpu:25, mem:60, disk:35, load:0.5, temp:48, net:-55};

function vrInit() {
  vrCanvas = document.getElementById('vr-canvas');
  if (!vrCanvas) return;
  vrCtx = vrCanvas.getContext('2d');
  
  // Position pods in TRUE hexagon
  VR_PODS.forEach(p => {
    const el = document.getElementById('vr-pod-' + p.id);
    if (!el) return;
    const rad = p.a * Math.PI / 180;
    const x = VR_CX + POD_R * Math.cos(rad);
    const y = VR_CY + POD_R * Math.sin(rad);
    el.style.cssText = `position:absolute; left:${x}px; top:${y}px; transform:translate(-50%,-50%); z-index:5;`;
  });
  
  ['vr-time','vr-date'].forEach(id => {
    const e = document.getElementById(id);
    if (e) e.style.display = 'none';
  });
  
  vrCanvas.style.cssText = 'position:absolute; top:0; left:0; width:320px; height:320px;';
  
  vrAnimate();
  setInterval(vrLoadData, 3000);
  vrLoadData();
}

function vrAnimate() {
  vrDraw();
  vrAngle += 0.018;
  if (vrAngle > Math.PI * 2) vrAngle = 0;
  requestAnimationFrame(vrAnimate);
}

function vrDraw() {
  const ctx = vrCtx;
  ctx.clearRect(0, 0, 320, 320);
  ctx.save();
  ctx.beginPath();
  ctx.arc(VR_CX, VR_CY, 158, 0, Math.PI*2);
  ctx.clip();
  
  // Grid
  ctx.strokeStyle = 'rgba(80,120,200,0.04)';
  ctx.lineWidth = 1;
  for (let r = 15; r < 155; r += 11) {
    ctx.beginPath();
    ctx.arc(VR_CX, VR_CY, r, 0, Math.PI*2);
    ctx.stroke();
  }
  
  // Rings - each starts at its pod angle
  VR_RINGS.forEach((ring, i) => {
    let pct;
    switch(ring.key) {
      case 'cpu': pct = vrM.cpu/100; break;
      case 'mem': pct = vrM.mem/100; break;
      case 'disk': pct = vrM.disk/100; break;
      case 'load': pct = Math.min(1, vrM.load/4); break;
      case 'temp': pct = Math.min(1, Math.max(0, (vrM.temp-35)/50)); break;
      case 'net': pct = Math.min(1, Math.max(0, (vrM.net+90)/70)); break;
      default: pct = 0;
    }
    // Start angle aligned with corresponding pod
    const sa = VR_PODS[i].a * Math.PI / 180;
    
    ctx.beginPath();
    ctx.arc(VR_CX, VR_CY, ring.r, 0, Math.PI*2);
    ctx.strokeStyle = '#0a0a12';
    ctx.lineWidth = ring.w + 2;
    ctx.stroke();
    
    if (pct > 0.01) {
      ctx.beginPath();
      ctx.arc(VR_CX, VR_CY, ring.r, sa, sa + Math.PI*2*pct);
      ctx.strokeStyle = ring.color;
      ctx.lineWidth = ring.w;
      ctx.lineCap = 'round';
      ctx.shadowColor = ring.color;
      ctx.shadowBlur = 10;
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.lineCap = 'butt';
    }
  });
  
  // Draw circles around icons
  const deg = (vrAngle * 180 / Math.PI + 360) % 360;
  VR_PODS.forEach(p => {
    const rad = p.a * Math.PI / 180;
    const x = VR_CX + POD_R * Math.cos(rad);
    const y = VR_CY + POD_R * Math.sin(rad);
    
    const pa = (p.a + 360) % 360;
    const diff = Math.min(Math.abs(deg - pa), 360 - Math.abs(deg - pa));
    const isHit = diff < 30;
    
    ctx.beginPath();
    ctx.arc(x, y, 20, 0, Math.PI * 2);
    ctx.strokeStyle = p.color;
    ctx.lineWidth = isHit ? 3 : 2;
    ctx.globalAlpha = isHit ? 1 : 0.4;
    if (isHit) {
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 15;
    }
    ctx.stroke();
    ctx.shadowBlur = 0;
    ctx.globalAlpha = 1;
    
    const el = document.getElementById('vr-pod-' + p.id);
    if (el) el.classList.toggle('radar-active', isHit);
  });
  
  // Rainbow radar sweep
  const ex = VR_CX + 155*Math.cos(vrAngle);
  const ey = VR_CY + 155*Math.sin(vrAngle);
  
  const lineGrad = ctx.createLinearGradient(VR_CX, VR_CY, ex, ey);
  lineGrad.addColorStop(0, '#9944ff');
  lineGrad.addColorStop(0.17, '#0099ff');
  lineGrad.addColorStop(0.33, '#00dd66');
  lineGrad.addColorStop(0.5, '#ffdd00');
  lineGrad.addColorStop(0.67, '#ff8800');
  lineGrad.addColorStop(0.85, '#ff3030');
  lineGrad.addColorStop(1, '#ffffff');
  
  const trailGrad = ctx.createConicGradient(vrAngle, VR_CX, VR_CY);
  trailGrad.addColorStop(0, 'rgba(100,180,255,0.3)');
  trailGrad.addColorStop(0.1, 'rgba(80,140,255,0.15)');
  trailGrad.addColorStop(0.25, 'rgba(50,100,200,0.05)');
  trailGrad.addColorStop(0.4, 'rgba(30,60,150,0)');
  trailGrad.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = trailGrad;
  ctx.fillRect(0, 0, 320, 320);
  
  ctx.beginPath();
  ctx.moveTo(VR_CX, VR_CY);
  ctx.lineTo(ex, ey);
  ctx.strokeStyle = lineGrad;
  ctx.lineWidth = 3;
  ctx.shadowColor = '#88ccff';
  ctx.shadowBlur = 12;
  ctx.stroke();
  ctx.shadowBlur = 0;
  
  ctx.restore();
}

async function vrLoadData() {
  try {
    const t = localStorage.getItem('sbx_token');
    const h = t ? {'Authorization': 'Bearer ' + t} : {};
    const r = await fetch('/api/v1/hub/dashboard', {headers: h});
    if (!r.ok) return;
    const d = await r.json();
    vrM.cpu = d.cpu_percent || 25;
    vrM.mem = d.memory_percent || 50;
    vrM.disk = d.disk_percent || 30;
    vrM.load = (d.load_avg || [0.5])[0];
    vrM.temp = d.cpu_temp || 45;
    vrM.net = d.wifi_rssi || -55;
    
    const u = (id, v) => { const e = document.querySelector('#vr-pod-' + id + ' .vr-val'); if(e) e.textContent = v; };
    u('auth', Math.round(vrM.cpu) + '%');
    u('wall', Math.round(vrM.mem) + '%');
    u('boot', Math.round(vrM.disk) + '%');
    u('mind', vrM.load.toFixed(1));
    u('root', Math.round(vrM.temp) + '°');
    u('mesh', Math.round(vrM.net) + 'dB');
    
    if (d.hostname) { const h = document.getElementById('vr-hostname'); if(h) h.textContent = d.hostname; }
  } catch(e) {}
}

document.addEventListener('DOMContentLoaded', vrInit);
