// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox :: peertube-plugin-secubox-sso — entrer par la session SecuBox (#1562)
//
// SANS MOT DE PASSE POUR LA PERSONNE. nginx vérifie la session SecuBox
// (auth_request, le même contrôle que le BBS et le Cloud) et pose
// X-Sbx-Peertube-User sur la SEULE route d'authentification de ce greffon ;
// il la vide partout ailleurs. Le greffon ouvre alors ce compte par le
// mécanisme d'authentification externe de PeerTube. Trois gardes :
//   - l'en-tête n'est cru que venant de l'hôte (les autres conteneurs du
//     pont joignent PeerTube directement) ;
//   - seul un compte EXISTANT, rattaché à ce greffon et non bloqué, s'ouvre :
//     rien n'est jamais créé, un administrateur n'est jamais rattaché ;
//   - aucun `userUpdater` : le rôle, les quotas, le nom ne sont jamais touchés.
// Sans session, ou en « lecture LAN » (200 sans identité) : le formulaire.

const NPM = 'peertube-plugin-secubox-sso'
const VERSION = require('./package.json').version
const HOTE = new Set(['10.100.0.1', '::ffff:10.100.0.1'])
const NOM = /^[a-z0-9._]{1,50}$/

async function register ({ registerExternalAuth, getRouter, peertubeHelpers }) {
  const { database, logger } = peertubeHelpers

  const auth = registerExternalAuth({
    authName: 'secubox',
    authDisplayName: () => 'SecuBox',
    onAuthRequest: async (req, res) => {
      try {
        const nom = String(req.get('x-sbx-peertube-user') || '')
        if (!HOTE.has(req.socket.remoteAddress) || !NOM.test(nom)) return res.redirect('/login')
        const lignes = await database.query(
          'SELECT "username", "email" FROM "user" WHERE "username" = $1 AND "pluginAuth" = $2 AND "blocked" = false',
          { bind: [nom, NPM], type: 'SELECT' })
        if (lignes.length !== 1) return res.redirect('/login')
        auth.userAuthenticated({ req, res, username: lignes[0].username, email: lignes[0].email })
      } catch (err) {
        logger.error('secubox-sso : entrée refusée', { err })
        res.redirect('/login')
      }
    }
  })

  // /plugins/secubox-sso/router/entrer : l'adresse STABLE (sans version) que
  // nginx sert sous /sbx/entrer ; elle mène à la route versionnée, où nginx
  // pose l'en-tête après avoir vérifié la session.
  getRouter().get('/entrer', (req, res) =>
    res.redirect(`/plugins/secubox-sso/${VERSION}/auth/secubox`))
}

async function unregister () {}

module.exports = { register, unregister }
