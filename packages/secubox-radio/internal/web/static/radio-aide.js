// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Externalisé pour la CSP script-src 'self' (radio/micro, #1238-suite).
window.SBXAide&&SBXAide({
  root: document.querySelector('.wrap')||document.body,
  zones: function(){ return [
    {el:document.querySelector('.lecteur'),       label:'Lecteur — flux en direct, lecture/pause, volume'},
    {el:document.querySelector('.playlist'),      label:'File — les morceaux à venir (playlist du parc)'},
    {el:document.getElementById('chat'),          label:'Antenne — le chat du parc, en direct'},
    {el:document.querySelector('.proposer-micro'),label:'Proposer — ajouter un morceau à l’antenne'}
  ].filter(function(z){return z.el;}); }
});
