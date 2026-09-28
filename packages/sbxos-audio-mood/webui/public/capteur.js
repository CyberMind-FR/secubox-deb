// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Le capteur : un AudioWorklet qui transforme le micro en blocs Int16.
//
// POURQUOI UN WORKLET ET PAS UN ScriptProcessorNode. Le ScriptProcessor est
// déprécié et tourne sur le fil PRINCIPAL : le moindre rendu Svelte, le
// moindre redessin de canevas, et le son se met à hoqueter — on entend des
// trous dans l'analyse là où il n'y en a pas dans la voix. Le worklet tourne
// sur le fil audio, à côté du matériel.
//
// POURQUOI DE L'Int16 ET PAS DU Float32. Deux fois moins d'octets sur le
// réseau pour une plage dynamique qui dépasse largement ce qu'un micro de
// portable produit, et c'est le format que le serveur attend sans conversion.
class Capteur extends AudioWorkletProcessor {
  constructor() {
    super()
    // ~21 ms par envoi : assez gros pour ne pas noyer la WebSocket de
    // messages, assez petit pour que la latence reste sous le seuil annoncé.
    this.taille = 1024
    this.tampon = new Int16Array(this.taille)
    this.n = 0
  }

  process(entrees) {
    const canal = entrees[0] && entrees[0][0]
    if (!canal) return true // micro coupé : on reste vivant, sans rien envoyer
    for (let i = 0; i < canal.length; i++) {
      // Écrêtage explicite : un échantillon hors [-1,1] déborderait l'Int16 et
      // reviendrait par l'autre bout, transformant une saturation en craquement.
      let v = canal[i]
      if (v > 1) v = 1
      else if (v < -1) v = -1
      this.tampon[this.n++] = v < 0 ? v * 0x8000 : v * 0x7fff
      if (this.n === this.taille) {
        // On transfère le tampon plutôt que de le copier — puis on en refait
        // un : sans le transfert, chaque bloc serait recopié deux fois.
        this.port.postMessage(this.tampon.buffer, [this.tampon.buffer])
        this.tampon = new Int16Array(this.taille)
        this.n = 0
      }
    }
    return true
  }
}
registerProcessor('capteur', Capteur)
