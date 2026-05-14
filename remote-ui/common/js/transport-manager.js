// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/transport-manager.js
//
// Probe OTG (10.55.0.1) → WiFi (secubox.local) → SIM (drift mode).
// Single JWT per transport, renewed automatically 30s before expiry.
//
// Depends on CFG (loaded by config.js — must precede this file in <script> order).
//
// Optional hooks for embedding contexts (e.g. square/'s right column over
// a loopback WebSocket bridge):
//   TM.onModuleTap        = (moduleName)=>{};   // default no-op
//   TM.onTransportChange  = (active)=>{};       // default no-op
//
// Use _setActive(newActive) instead of direct `this.active = X` so the
// onTransportChange hook fires on real transitions only (deduped).

const TM = {
  active:'SIM', jwt:null, jwtExp:0, otgFails:0,
  onModuleTap:       (moduleName)=>{},
  onTransportChange: (active)=>{},
  get base(){ return this.active==='OTG'?CFG.API_OTG_BASE:this.active==='WiFi'?CFG.API_WIFI_BASE:null; },
  async probe(){
    if(CFG.SIMULATE){this._setActive('SIM');return;}
    for(const [n,b] of [['OTG',CFG.API_OTG_BASE],['WiFi',CFG.API_WIFI_BASE]]){
      try{const r=await fetch(b+'/api/v1/health',{signal:AbortSignal.timeout(2000)});
        if(r.ok){if(this.active!==n){this._setActive(n);this.jwt=null;}this.otgFails=0;return;}
      }catch(_){if(n==='OTG')this.otgFails++;}
    }
    this._setActive('SIM');
  },
  async login(){
    if(CFG.SIMULATE||!this.base){this.jwt='SIM';this.jwtExp=Date.now()+3600000;return true;}
    try{
      const r=await fetch(this.base+CFG.ENDPOINT_LOGIN,{method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({username:CFG.LOGIN_USER,password:CFG.LOGIN_PASS,grant_type:'password'}),
        signal:AbortSignal.timeout(3000)});
      if(!r.ok)throw new Error(r.status);
      const d=await r.json();this.jwt=d.access_token;
      const p=JSON.parse(atob(d.access_token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
      this.jwtExp=p.exp*1000;return true;
    }catch(e){return false;}
  },
  async ensureJwt(){
    if(!this.jwt||Date.now()>=this.jwtExp-CFG.JWT_RENEW_BEFORE_MS)return this.login();
    return true;
  },
  async fetchMetrics(){
    if(CFG.SIMULATE||this.active==='SIM')return null;
    await this.ensureJwt();
    try{
      const r=await fetch(this.base+CFG.ENDPOINT_METRICS,
        {headers:{'Authorization':'Bearer '+this.jwt},signal:AbortSignal.timeout(3000)});
      if(!r.ok)throw new Error(r.status);
      return await r.json();
    }catch(e){
      if(this.active==='OTG'){this.otgFails++;if(this.otgFails>=CFG.OTG_FAILOVER_THRESHOLD)await this.probe();}
      return null;
    }
  },
  _setActive(newActive){
    if(this.active!==newActive){
      this.active=newActive;
      try{this.onTransportChange(newActive);}catch(e){console.warn(e);}
    }
  },
};

if (typeof window !== 'undefined') { window.TM = TM; }
