// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/sim.js
//
// Simulation drift generator — produces plausible /api/v1/system/metrics
// shaped output via bounded random walk when no SecuBox host responds.
// Activated by CFG.SIMULATE=true or when TransportManager probe falls back to 'SIM'.
//
// Depends on CFG.REFRESH_INTERVAL (load config.js BEFORE this file).

const SIM={cpu:14,mem:42,disk:28,net:-63,load:.18,temp:44,uptime:0,hostname:'secubox-zero'};
function simStep(){
  const r=(v,d,mn,mx)=>Math.min(mx,Math.max(mn,v+(Math.random()-.5)*d));
  SIM.cpu=r(SIM.cpu,12,0,100);SIM.mem=r(SIM.mem,3,20,95);
  SIM.disk=r(SIM.disk,.7,5,95);SIM.net=r(SIM.net,5,-90,-20);
  SIM.load=r(SIM.load,.12,0,4);SIM.temp=r(SIM.temp,1.5,35,82);
  SIM.uptime+=CFG.REFRESH_INTERVAL/1000;
  return SIM;
}

if (typeof window !== 'undefined') {
  window.SIM = SIM;
  window.simStep = simStep;
}
