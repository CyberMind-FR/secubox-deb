/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   Source-Disclosed License — All rights reserved except as expressly granted.
   See LICENCE-CMSD-1.0.md for terms.

   SecuBox #3938 — dé SecuBox en 3D réelle (WebGL 2, sans bibliothèque) sur un échiquier : lancer de rayons sur un cube arrondi,
   faces en relief stéréo, reflets holographiques, ombre douce, rebond élastique.

   SbxDe3d.demarrer(canvas, urls[6], {pret, charge, repli, vitesse}) : pret(aise) après la première image (aise : GPU
   matériel rapide) ; charge() une fois quand le rendu peine (la page s'allège) ; repli(raison) UNE fois si la 3D
   est impossible ou le devient (pas de WebGL 2, shader refusé, image absente, contexte perdu non rendu, rendu trop lent).
   Rotation sans fin : angles et temps repliés sur leur période (aucune dérive) ; au quart de vitesse, sans rebond ni parallaxe sous
   prefers-reduced-motion ; figée seulement par localStorage sbx_de=fige. En pause si l'onglet est caché ou le canvas hors écran. */
(function(w){
'use strict';
var VS='#version 300 es\nvoid main(){vec2 p=vec2((gl_VertexID<<1)&2,gl_VertexID&2);gl_Position=vec4(p*2.-1.,0.,1.);}';
/* T va de 0 à 100 s puis reprend : tous ses facteurs sont des multiples de 0,01 (irise a pour période 1), le raccord est exact. */
var FS=`#version 300 es
precision highp float;precision highp int;precision highp sampler2D;precision highp sampler2DArray;
uniform vec2 R;uniform float T;uniform mat3 M;uniform vec3 C;uniform vec2 S;uniform vec2 P;uniform sampler2DArray F;uniform sampler2D E;
out vec4 o;
const float H=.8,r=.17,BORD=5.2,ENV=1.36;
vec3 loc(vec3 p){p-=C;p.y/=S.y;p.xz/=S.x;return p*M;}          // monde → dé (M orthonormée : p*M = transposée)
float de(vec3 p){vec3 q=abs(loc(p))-(H-r);return (length(max(q,0.))+min(max(q.x,max(q.y,q.z)),0.)-r)*min(S.y,S.x);}
vec3 norme(vec3 p){vec2 e=vec2(.0012,0);return normalize(vec3(de(p+e.xyy)-de(p-e.xyy),de(p+e.yxy)-de(p-e.yxy),de(p+e.yyx)-de(p-e.yyx)));}
vec2 pres;
float marche(vec3 a,vec3 d,int n,float max_){pres=vec2(9.,0.);float t=0.;float b=dot(C-a,d);float c2=dot(C-a,C-a)-b*b;
 if(c2>2.1)return -1.;t=max(0.,b-1.46);for(int i=0;i<n;i++){float k=de(a+d*t);if(k<.0012)return t;if(k/t<pres.x)pres=vec2(k/t,t);t+=k*.92;if(t>max_||t>b+1.46)break;}return -1.;}
// Hors de la sphère ENV élargie, 9k/t dépasse 1 : aucune ombre. On ne marche que là où elle est possible.
float ombre(vec3 a,vec3 l){float b=dot(C-a,l),c2=dot(C-a,C-a)-b*b;
 if(b<-ENV||sqrt(max(c2,0.))-ENV>(b+ENV)/9.)return 1.;
 float s=1.,t=max(.05,b-2.25),f=b+2.25;for(int i=0;i<26;i++){float k=de(a+l*t);s=min(s,9.*k/t);t+=clamp(k,.03,.35);if(s<.004||t>7.||t>f)break;}s=clamp(s,0.,1.);return s*s*(3.-2.*s);}
const vec3 L1=vec3(-.46,.80,-.38),L2=vec3(.74,.45,.50);
vec3 ciel(vec3 d){vec3 c=mix(vec3(.012,.03,.075),vec3(.05,.12,.28),smoothstep(-.2,1.,d.y));
 c+=vec3(.75,.95,1.25)*1.5*smoothstep(.93,.985,dot(d,normalize(L1)))*(.55+.45*step(.18,fract(d.x*5.)));  // boîte à lumière froide
 c+=vec3(1.1,.35,.95)*smoothstep(.86,.98,dot(d,normalize(L2)));                               // contre-jour magenta
 c+=vec3(.1,.7,1.)*.55*(1.-smoothstep(0.,.06,abs(d.y-.22)))*smoothstep(-.2,.9,d.z);return c;}  // néon d'horizon
vec3 irise(float x){return .5+.5*cos(6.2831853*(x+vec3(0.,.33,.67)));}
vec4 sol(vec3 p){vec2 u=p.xz/BORD;float m=max(abs(u.x),abs(u.y));if(m>1.)return vec4(.01,.022,.05,.25);
 float g=.0016+.0007*length(p.xz);return vec4(textureGrad(E,u*.5*vec2(1,-1)+.5,vec2(g,0),vec2(0,g)).rgb,1.);}
vec3 eclaireSol(vec3 p,vec4 s){float o1=ombre(p+vec3(0,.004,0),normalize(L1)),o2=ombre(p+vec3(0,.004,0),normalize(L2));
 float h=max(C.y-.9,0.),ao=1.-.62*exp(-dot(p.xz-C.xz,p.xz-C.xz)/(.5+.8*h))*exp(-h*.8);
 vec3 c=s.rgb*(vec3(.16,.2,.3)+vec3(.95,1.02,1.15)*o1*.92+vec3(.55,.2,.5)*o2*.55)*ao;
 float a=exp(-abs(length(p.xz-C.xz)-1.15)*2.2)*(.25+.2*sin(T*.8796459));
 return c+s.a*a*irise(atan(p.z-C.z,p.x-C.x)/6.2831853+T*.04)*.10*o1;}                         // caustique holographique
// q, n, v en repère du dé (x droite, y BAS, z fond, comme le moteur 2D). rgb = couleur de la face, a = part du motif.
vec4 face(vec3 q,vec3 n,vec3 v){
 vec3 a=abs(n);int k;vec3 tu,tv;vec3 N;
 if(a.x>a.y&&a.x>a.z){N=vec3(sign(n.x),0,0);k=n.x>0.?2:4;tu=vec3(0,0,-1);tv=vec3(0,1,0);}
 else if(a.y>a.z){N=vec3(0,sign(n.y),0);tv=vec3(0,0,1);if(n.y>0.){k=1;tu=vec3(1,0,0);}else{k=3;tu=vec3(-1,0,0);}}
 else{N=vec3(0,0,sign(n.z));tv=vec3(0,-1,0);if(n.z>0.){k=5;tu=vec3(1,0,0);}else{k=0;tu=vec3(-1,0,0);}}
 float g=max(.28,-dot(v,N));vec2 pen=vec2(dot(v,tu),dot(v,tv))/g;vec2 u=vec2(dot(q,tu),dot(q,tv))/H;
 vec2 uF=(u+pen*.34)*.5+.5,uA=(u+pen*.11)*.5+.5;                    // deux profondeurs : fond loin, motif près
 vec2 st=vec2(.0065)*(.35+.65*length(pen));                          // écart stéréo : les deux yeux
 float lod=max(0.,log2(1330./R.y)-.6);                               // motif lisible et sans scintillement aux petites tailles
 vec3 A=vec3(textureLod(F,vec3(uA-st,k),lod).r,textureLod(F,vec3(uA,k),lod).g,textureLod(F,vec3(uA+st,k),lod).b);
 vec3 O=textureLod(F,vec3(uA+vec2(.012,.016),k),lod+1.5).rgb;        // ombre propre du motif
 float m=smoothstep(.03,.14,max(A.r,max(A.g,A.b))-min(min(A.r,A.g),A.b)+.35*dot(A,vec3(.33))),mo=smoothstep(.05,.20,max(O.r,max(O.g,O.b))-min(min(O.r,O.g),O.b)+.35*dot(O,vec3(.33)));
 vec2 gr=abs(fract(uF*9.)-.5);float li=smoothstep(.46,.5,max(gr.x,gr.y));
 vec3 fond=vec3(.012,.03,.07)+irise(uF.x*.7+uF.y*.5+T*.05)*li*.20+irise(length(uF-.5)*2.-T*.08)*.035;
 fond*=1.-.65*mo;
 float bd=smoothstep(.80,.93,max(abs(u.x),abs(u.y)));
 return mix(vec4(mix(fond,A*1.15,m),m),vec4(.30,.34,.42,0.),bd);}
vec3 eclaireDe(vec3 p,vec3 d,out float fr){vec3 n=norme(p),q=loc(p);vec3 nl=normalize((n*S.xyx)*M),vl=normalize((d/S.xyx)*M);
 vec3 f=vec3(1,-1,1);vec4 fa=face(q*f,nl*f,vl*f);vec3 alb=fa.rgb;
 vec3 l1=normalize(L1),l2=normalize(L2);float o1=ombre(p+n*.02,l1);float d1=max(dot(n,l1),0.)*o1,d2=max(dot(n,l2),0.);
 float rim=clamp(1.-max(-dot(n,d),0.),0.,1.);fr=.05+.95*pow(rim,5.);
 vec3 c=alb*(vec3(.34,.40,.54)+vec3(1.25,1.3,1.4)*d1+vec3(.8,.25,.7)*d2*.6+vec3(.1,.3,.5)*max(-n.y,0.)*.5);
 // Plancher émissif du motif : sa propre teinte, relevée quand elle est sombre (violet, bleu) et que la face est dans l'ombre.
 float hc=max(alb.r,max(alb.g,alb.b));c+=fa.a*alb*clamp(.42/max(hc,.05),.55,2.6)*(1.-.8*min(d1,1.));
 vec3 rf=reflect(d,n);vec3 ev=ciel(rf);if(rf.y<-.02){float t=-p.y/rf.y;vec3 s=p+rf*t;vec4 e=sol(s);ev=mix(e.rgb*.9,vec3(.01,.02,.05),smoothstep(2.,9.,t));}
 vec3 ir=irise(dot(n,d)*1.6+dot(q,vec3(.5,.35,.2))+T*.06);
 float sp=pow(max(dot(rf,l1),0.),160.)*o1*.55+pow(max(dot(rf,l2),0.),70.)*.3;
 c+=(min(ev,vec3(.85))*(min(fr,.26)*.8+.04)+ir*pow(rim,2.2)*.34)*(1.-.75*fa.a)+ir*.03+vec3(sp)*mix(.6,.2,fa.a);   // vernis plafonné : jamais de face blanche
 vec3 aq=abs(q);c+=irise(T*.07+q.x*.4+q.y*.4)*smoothstep(H-r*.9,H,max(min(aq.x,aq.y),max(min(aq.y,aq.z),min(aq.x,aq.z))))*.22;
 return c;}
vec3 scene(vec2 uv,float px){vec3 ro=vec3(P.x*.7,4.25+P.y*.45,-6.6),ci=vec3(0,.78,.15);vec3 f=normalize(ci-ro),x=normalize(cross(vec3(0,1,0),f)),y=cross(f,x);
 vec3 d=normalize(f*2.35+x*uv.x+y*uv.y);float fr;float t=marche(ro,d,64,30.);
 if(t>0.)return eclaireDe(ro+d*t,d,fr);
 vec3 bo=vec3(0);float cv=0.;if(pres.x<px){cv=.5*(1.-pres.x/px);bo=eclaireDe(ro+d*pres.y,d,fr);}
 if(d.y>-.02)return mix(ciel(d)*.25,bo,cv);
 float g=-ro.y/d.y;vec3 p=ro+d*g;vec4 s=sol(p);vec3 c=eclaireSol(p,s);
 vec3 rd=reflect(d,vec3(0,1,0));float z=.04+.5*pow(1.-max(-d.y,0.),4.);float t2=marche(p+vec3(0,.01,0),rd,30,8.);float f2;
 vec3 rc=t2>0.?eclaireDe(p+rd*t2,rd,f2)*exp(-t2*.45):ciel(rd)*.35;c+=rc*(z+.10)*s.a;
 return mix(mix(c,vec3(.012,.026,.06),smoothstep(6.5,13.,length(p.xz))),bo,cv);}
void main(){vec2 uv=(gl_FragCoord.xy*2.-R)/R.y;float l=length(uv);o=vec4(0);if(l>1.)return;
 vec3 c=scene(uv,1.3/R.y);
 c=c*(2.51*c+.03)/(c*(2.43*c+.59)+.14);c=pow(clamp(c,0.,1.),vec3(.4545*1.08));
 float a=1.-smoothstep(.93,1.,l);c*=1.-.35*smoothstep(.55,1.,l);c*=1.-.62*smoothstep(.5,.82,-uv.y);c+=(fract(sin(dot(gl_FragCoord.xy,vec2(12.9,78.2)))*43758.5)-.5)/255.;
 o=vec4(max(c,0.)*a,a);}`;
var TAU=Math.PI*2, NIVEAUX=[1,.82,.67,.55,.45], BAS=NIVEAUX.length-1, IS=320, TROP_LENT=120;

function maintenant(){ return performance.now(); }
function image(u){ return new Promise(function(ok,ko){ var i=new Image(); i.onload=function(){ ok(i); }; i.onerror=function(){ ko(new Error('image')); }; i.src=u; }); }
function plateau(){
  var n=1024,c=document.createElement('canvas'),x,b=78,q=(n-2*b)/8,i,j; c.width=c.height=n; x=c.getContext('2d');
  x.fillStyle='#0a1730'; x.fillRect(0,0,n,n);
  for(i=0;i<8;i++) for(j=0;j<8;j++){
    var X=b+i*q,Y=b+j*q,gr=x.createLinearGradient(X,Y,X+q,Y+q),cl=(i+j)%2===0;
    gr.addColorStop(0,cl?'#4f7cc2':'#0f2348'); gr.addColorStop(1,cl?'#33599c':'#0a1835');
    x.fillStyle=gr; x.fillRect(X,Y,q,q);
  }
  x.strokeStyle='rgba(41,182,246,.85)'; x.lineWidth=5; x.strokeRect(b-3,b-3,n-2*b+6,n-2*b+6);
  x.strokeStyle='rgba(86,150,255,.5)'; x.lineWidth=3; x.strokeRect(10,10,n-20,n-20);
  x.fillStyle='#a9cdfb'; x.font='600 38px system-ui,sans-serif'; x.textAlign='center'; x.textBaseline='middle';
  for(i=0;i<8;i++){ var l='abcdefgh'[i],m=b+(i+.5)*q; x.fillText(l,m,n-b/2); x.fillText(l,m,b/2); x.fillText(String(8-i),b/2,m); x.fillText(String(8-i),n-b/2,m); }
  return c;
}

function demarrer(cv,urls,opt){
  opt=opt||{};
  var g=null,prog=null,U={},I=null,fini=false,pret=false,perdu=false,pertes=0,tPerte=0,gen=0;
  var mq=w.matchMedia('(prefers-reduced-motion: reduce)'), fin=w.matchMedia('(hover: hover) and (pointer: fine)');
  var ax=.5,ay=.75,az=.2,T=0,kr=0,ke=0,q=0,ec=0,vx=0,vy=0,px=0,py=0,M=new Float32Array(9);      // état de l'animation
  var niv=BAS,raf=0,avant=0,prochain=0,visible=true,cote=0;
  var actif=0,lents=0,calme=0,montee=-1e9,patience=6000,seuil=30,somme=0,nb=0,refus=0,tres=0,aise=false,cher=false;    // résolution adaptative
  var io=null,ro=null;

  function fige(){ try{ return w.localStorage.getItem('sbx_de')==='fige'; }catch(e){ return false; } }
  function vu(){ return !document.hidden&&visible; }

  function repli(raison){
    if(fini) return; fini=true; gen++; arrete(); clearTimeout(tPerte);
    document.removeEventListener('visibilitychange',relance); w.removeEventListener('pointermove',pointeur); w.removeEventListener('resize',mesureCote);
    cv.removeEventListener('webglcontextlost',perte); cv.removeEventListener('webglcontextrestored',retour);
    if(mq.removeEventListener) mq.removeEventListener('change',relance);
    if(io) io.disconnect(); if(ro) ro.disconnect();
    try{ var x=g&&!g.isContextLost()&&g.getExtension('WEBGL_lose_context'); if(x) x.loseContext(); }catch(e){ /* contexte déjà perdu : rien à libérer */ }
    if(opt.repli) opt.repli(String(raison&&raison.message||raison));
  }
  function arrete(){ if(raf){ cancelAnimationFrame(raf); raf=0; } }

  /* ── GPU ── compilation sans bloquer la page quand le navigateur le permet, puis textures. */
  function construit(suite){
    var G=++gen, par=g.getExtension('KHR_parallel_shader_compile'), t0=maintenant();
    function sh(t,x){ var h=g.createShader(t); g.shaderSource(h,x); g.compileShader(h); g.attachShader(prog,h); return h; }
    prog=g.createProgram(); var v=sh(g.VERTEX_SHADER,VS), f=sh(g.FRAGMENT_SHADER,FS); g.linkProgram(prog);
    (function attend(){
      if(fini||G!==gen) return;
      if(par&&!g.isContextLost()&&!g.getProgramParameter(prog,par.COMPLETION_STATUS_KHR)){
        if(maintenant()-t0>15000) return repli('compilation trop lente');
        return void setTimeout(attend,30);
      }
      try{
        if(g.isContextLost()) return;                              // l'évènement de perte décide
        if(!g.getProgramParameter(prog,g.LINK_STATUS)) throw new Error('shader '+(g.getShaderInfoLog(f)||g.getShaderInfoLog(v)||g.getProgramInfoLog(prog)||''));
        g.deleteShader(v); g.deleteShader(f); ressources();
        if(g.isContextLost()) return;
      }catch(e){ return repli(e); }
      suite();
    })();
  }
  function ressources(){
    g.useProgram(prog); g.bindVertexArray(g.createVertexArray()); g.disable(g.BLEND); g.disable(g.DITHER);
    ['R','T','M','C','S','P','F','E'].forEach(function(k){ U[k]=g.getUniformLocation(prog,k); });
    var A=g.TEXTURE_2D_ARRAY,D=g.TEXTURE_2D;
    g.activeTexture(g.TEXTURE0); g.bindTexture(A,g.createTexture()); g.texStorage3D(A,9,g.SRGB8_ALPHA8,IS,IS,6);
    I.forEach(function(im,i){
      if(im.naturalWidth!==IS||im.naturalHeight!==IS) throw new Error('image');
      g.texSubImage3D(A,0,0,0,i,IS,IS,1,g.RGBA,g.UNSIGNED_BYTE,im);
    });
    g.generateMipmap(A);
    g.texParameteri(A,g.TEXTURE_WRAP_S,g.CLAMP_TO_EDGE); g.texParameteri(A,g.TEXTURE_WRAP_T,g.CLAMP_TO_EDGE); g.texParameteri(A,g.TEXTURE_MIN_FILTER,g.LINEAR_MIPMAP_LINEAR);
    g.activeTexture(g.TEXTURE1); g.bindTexture(D,g.createTexture()); g.texImage2D(D,0,g.SRGB8_ALPHA8,g.RGBA,g.UNSIGNED_BYTE,plateau()); g.generateMipmap(D);
    g.texParameteri(D,g.TEXTURE_MIN_FILTER,g.LINEAR_MIPMAP_LINEAR);
    var an=g.getExtension('EXT_texture_filter_anisotropic'); if(an) g.texParameterf(D,an.TEXTURE_MAX_ANISOTROPY_EXT,4);
    g.uniform1i(U.F,0); g.uniform1i(U.E,1);
    var e=g.getError(); if(e&&e!==g.CONTEXT_LOST_WEBGL) throw new Error('gl '+e);
  }

  /* ── Une image ── */
  function mesureCote(){ var n=cv.clientWidth; if(n&&n!==cote){ cote=n; if(pret&&!raf) dessine(); } }
  function rotation(){
    var cx=Math.cos(ax),sx=Math.sin(ax),cy=Math.cos(ay),sy=Math.sin(ay),cz=Math.cos(az),sz=Math.sin(az);   // Rz·Ry·Rx, par colonnes
    M[0]=cz*cy; M[1]=sz*cy; M[2]=-sy; M[3]=cz*sy*sx-sz*cx; M[4]=sz*sy*sx+cz*cx; M[5]=cy*sx; M[6]=cz*sy*cx+sz*sx; M[7]=sz*sy*cx-cz*sx; M[8]=cy*cx;
  }
  /* Toutes les 9 s : chute, trois rebonds amortis, remontée. Écart au plateau dans ec, écrasement visé rendu. */
  function rebond(){
    var e=.62+.07*Math.sin(ke),k=kr-5.2,z; ec=.62;
    if(mq.matches) return 0;
    ec=e; if(k<0) return 0;
    if(k<.42){ z=k/.42; ec=e*(1-z*z); return z>.86?(z-.86)/.14*.5:0; } k-=.42;
    if(k<.5) return saut(k/.5,.55,1); k-=.5;
    if(k<.36) return saut(k/.36,.26,.55); k-=.36;
    if(k<.24) return saut(k/.24,.09,.25); k-=.24;
    z=Math.min(1,k/2.2); ec=e*z*z*(3-2*z); return 0;
  }
  function saut(y,h,f){ ec=h*4*y*(1-y); return f*Math.max(0,1-Math.min(y,1-y)*9); }
  function dessine(){
    if(perdu||fini||!cote) return;
    var n=Math.max(64,Math.round(Math.min(cote*Math.min(w.devicePixelRatio||1,1.5),1400)*NIVEAUX[niv]));
    if(cv.width!==n) cv.width=cv.height=n;
    rotation();
    var vis=rebond(),et=mq.matches||vis>0?0:.04*Math.max(0,1-ec/.3);
    q+=((vis>0?-.13*vis:et)-q)*(1-Math.exp(-pas/22));                                                      // élasticité adoucie, sans à-coup
    var sy=1+q,sx=q<0?1-q*.55:1,sup=(Math.abs(M[1])+Math.abs(M[4])+Math.abs(M[7]))*.63+.17;                // appui le plus bas du cube tourné
    g.viewport(0,0,n,n); g.uniform2f(U.R,n,n); g.uniform1f(U.T,T); g.uniformMatrix3fv(U.M,false,M);
    g.uniform3f(U.C,0,sup*sy+ec,0); g.uniform2f(U.S,sx,sy); g.uniform2f(U.P,vx,vy); g.drawArrays(g.TRIANGLES,0,3);
  }
  var pas=16;

  /* ── La boucle ── au plus ~60 images/s (30 au calme) ; le temps, lui, suit l'horloge. */
  function boucle(t){
    raf=requestAnimationFrame(boucle);
    var periode=mq.matches?33.3:16.67;
    if(t<prochain-3) return;
    prochain=Math.max(prochain+periode,t);
    var iv=avant?t-avant:0; avant=t; pas=iv?Math.min(iv,100):16;
    var v=(opt.vitesse||3)*(mq.matches?.25:1)*pas;
    ax=(ax+.00031*v)%TAU; ay=(ay+.00047*v)%TAU; az=(az+.00019*v)%TAU;
    if(mq.matches){ vx=vy=0; }
    else{
      T=(T+pas/1000)%100; kr=(kr+pas/1000)%9; ke=(ke+pas*.0013)%TAU;
      var k=1-Math.exp(-pas/270); vx+=(px-vx)*k; vy+=(py-vy)*k;
    }
    if(iv) adapte(iv,periode);
    if(!fini) dessine();
  }
  /* Résolution : un cran de moins après une série lente ; un cran de plus après une longue période fluide, la patience doublant à
     chaque remontée ratée (pas d'oscillation). Si baisser ne change rien, c'est l'écran qui est lent (30 Hz) : le cran revient. */
  function adapte(iv,periode){
    actif+=iv; somme+=Math.min(iv,300); nb++;
    tres=niv===BAS&&iv>TROP_LENT&&iv<900?tres+1:0;
    if(tres>=12) return repli('rendu trop lent');
    var lent=iv>Math.max(seuil,periode*1.8);
    lents=lent?lents+1:Math.max(0,lents-1);
    calme=lent?0:calme+iv;
    if(lents>25){
      var moy=somme/nb; lents=0; somme=0; nb=0; calme=0;
      if(refus&&moy>.92*refus&&moy<60){ seuil=moy*1.4; refus=0; niv=Math.max(0,niv-1); return; }
      if(!cher){ cher=true; if(opt.charge) opt.charge(); if(aise) return; }                  // d'abord alléger la page
      if(niv<BAS){ if(actif-montee<15000) patience=Math.min(patience*2,600000); refus=moy; niv++; }
    }else if(calme>patience&&niv>0){ niv--; montee=actif; calme=0; refus=0; somme=0; nb=0; patience=Math.max(patience,20000); }
    else if(nb>240){ somme=0; nb=0; }
  }
  function relance(){
    if(fini||!pret||perdu) return;
    if(fige()){ arrete(); ax=ay=az=0; T=0; kr=0; ke=0; vx=vy=0; q=0; dessine(); return; }
    if(vu()){ if(!raf){ avant=0; prochain=0; lents=0; calme=0; tres=0; raf=requestAnimationFrame(boucle); } } else arrete();
  }
  function pointeur(e){ if(fin.matches&&!mq.matches&&e.pointerType!=='touch'){ px=(e.clientX/w.innerWidth-.5)*2; py=(e.clientY/w.innerHeight-.5)*2; } }

  /* ── Mesure ── quelques images à la plus petite échelle, attendues par une barrière GPU : un rendu logiciel trop lent (kiosque)
     est reconnu avant d'animer, sans jamais bloquer la page. */
  function mesure(suite){
    var G=gen,n=0,best=1e9,t0,f;
    niv=BAS; un();
    function un(){
      if(fini||G!==gen||perdu) return;
      if(document.hidden) return void document.addEventListener('visibilitychange',un,{once:true});
      dessine(); t0=maintenant(); f=g.fenceSync(g.SYNC_GPU_COMMANDS_COMPLETE,0); g.flush();
      if(!f) return repli('contexte'); setTimeout(sonde,0);
    }
    function sonde(){
      if(fini||G!==gen||perdu) return;
      var d=maintenant()-t0;
      if(g.getSyncParameter(f,g.SYNC_STATUS)!==g.SIGNALED){
        if(document.hidden){ g.deleteSync(f); return un(); }        // mesure faussée : on recommence une fois visible
        if(d>(n?2500:8000)) return repli('rendu trop lent');
        return void setTimeout(sonde,1);
      }
      g.deleteSync(f); n++; if(n>1||d<40) best=Math.min(best,d);     // la première image porte la préparation du pilote
      if(n<3||(n<5&&best>TROP_LENT)) return void setTimeout(un,0);
      if(best>TROP_LENT) return repli('rendu trop lent');
      var cible=best<6?1:.45*Math.sqrt(14/Math.max(1,best-2)); niv=BAS;
      while(niv>0&&NIVEAUX[niv-1]<=cible+.02) niv--;
      aise=best<12&&!/swiftshader|llvmpipe|softpipe|software/i.test(nomGPU());
      suite();
    }
  }
  function nomGPU(){ var x=g.getExtension('WEBGL_debug_renderer_info'); return String(g.getParameter(x?x.UNMASKED_RENDERER_WEBGL:g.RENDERER)); }

  /* ── Contexte perdu ── on le laisse revenir (preventDefault) ; 4 s visibles sans retour, ou trop de pertes : repli. */
  function perte(e){
    e.preventDefault(); perdu=true; gen++; arrete();
    if(++pertes>3) return repli('contexte perdu');
    clearTimeout(tPerte); tPerte=setTimeout(function t(){ if(document.hidden) tPerte=setTimeout(t,4000); else repli('contexte perdu'); },4000);
  }
  function retour(){ clearTimeout(tPerte); perdu=false; cv.width=cv.height=64; construit(function(){ var dej=pret; if(dej){ dessine(); relance(); } else prepare(); }); }

  function prepare(){
    mesure(function(){
      pret=true; if(fige()){ ax=ay=az=0; } dessine();
      if(opt.pret) opt.pret(aise); relance();
    });
  }
  return Promise.all(urls.map(image)).then(function(im){
    I=im; mesureCote();
    g=cv.getContext('webgl2',{alpha:true,premultipliedAlpha:true,antialias:false,depth:false,stencil:false,powerPreference:'low-power'});
    if(!g) throw new Error('WebGL 2 absent');
    cv.addEventListener('webglcontextlost',perte); cv.addEventListener('webglcontextrestored',retour);
    document.addEventListener('visibilitychange',relance); w.addEventListener('pointermove',pointeur,{passive:true}); w.addEventListener('resize',mesureCote);
    if(mq.addEventListener) mq.addEventListener('change',relance);
    if(w.ResizeObserver){ ro=new ResizeObserver(mesureCote); ro.observe(cv); }
    if(w.IntersectionObserver){ io=new IntersectionObserver(function(e){ visible=e[e.length-1].isIntersecting; relance(); }); io.observe(cv); }
    construit(prepare);
    return {echelle:function(){ return NIVEAUX[niv]; },etat:function(){ return {angles:[ax,ay,az],T:T,rebond:kr,marche:!!raf,fini:fini}; },avance:avance,pose:pose};
  }).catch(function(e){ repli(e); return null; });

  /* Essais : des jours d'animation en un pas, par les mêmes replis de période ; une pose arrêtée, à pleine résolution. */
  function pose(a,b,c){ arrete(); pret=false; ax=a; ay=b; az=c; T=kr=ke=q=vx=vy=0; niv=0; dessine(); }
  function avance(ms){
    ax=(ax+.00031*ms*3)%TAU; ay=(ay+.00047*ms*3)%TAU; az=(az+.00019*ms*3)%TAU; T=(T+ms/1000)%100; kr=(kr+ms/1000)%9; ke=(ke+ms*.0013)%TAU;
  }
}
w.SbxDe3d={demarrer:demarrer};
})(window);
