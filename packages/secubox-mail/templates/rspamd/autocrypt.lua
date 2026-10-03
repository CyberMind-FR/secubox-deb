-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- SecuBox-Deb :: Autocrypt SORTANT (#1852, P2).
--
-- Ajoute l'en-tête `Autocrypt: addr=<adresse>; keydata=<clé publique>` aux courriels ENVOYÉS par une personne dont la
-- box connaît la clé publique : les clients compatibles (Delta Chat, K-9/FairEmail, Thunderbird…) peuvent alors chiffrer
-- leur réponse sans rien configurer.
--
-- Ce que la règle ne fait JAMAIS :
--   · lire une clé privée (la table ne contient que des clés PUBLIQUES, adresses VÉRIFIÉES par la box) ;
--   · agir sur du courrier entrant ou non authentifié (il faut une session d'envoi) ;
--   · parler au nom d'un autre : l'expéditeur affiché (From) doit être l'adresse de la session authentifiée ;
--   · remplacer un en-tête Autocrypt déjà posé par le client.
--
-- La table /etc/rspamd/autocrypt.json ({adresse: keydata}) est écrite par `mailctl autocrypt-sync` ; rspamd la
-- recharge tout seul quand le fichier change.

local lua_mime = require "lua_mime"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"

local N = 'autocrypt'
local table_cles = {}

local function charge(contenu)
  local parser = ucl.parser()
  local ok, err = parser:parse_string(contenu)
  if not ok then
    rspamd_logger.errx(rspamd_config, '%s: table illisible: %s', N, err)
    return
  end
  local t = parser:get_object()
  if type(t) ~= 'table' then return end
  local propre = {}
  for adresse, keydata in pairs(t) do
    -- seules des chaînes base64 d'une ligne : rien d'autre ne finit dans un en-tête
    if type(adresse) == 'string' and type(keydata) == 'string' and keydata:match('^[A-Za-z0-9+/=]+$')
        and adresse:match('^[^%s<>;"]+@[^%s<>;"]+$') then
      propre[adresse:lower()] = keydata
    end
  end
  table_cles = propre
end

rspamd_config:add_map({
  url = '/etc/rspamd/autocrypt.json',
  type = 'callback',
  description = 'SecuBox : clés publiques pour l\'en-tête Autocrypt (adresse -> keydata)',
  callback = charge,
})

-- Le login SMTP peut être « boîte@domaine » ou, via le SSO du webmail, « boîte@domaine*maître » : on ne garde que la boîte.
local function boite_authentifiee(task)
  local u = task:get_user()
  if not u then return nil end
  return (tostring(u):match('^([^*]+)') or ''):lower()
end

-- keydata replié (RFC 5322) : lignes de 72 caractères, continuation par une espace.
local function replie(keydata)
  local lignes = {}
  for i = 1, #keydata, 72 do
    lignes[#lignes + 1] = keydata:sub(i, i + 71)
  end
  return table.concat(lignes, '\r\n ')
end

rspamd_config:register_symbol({
  name = 'SBX_AUTOCRYPT',
  type = 'postfilter',
  priority = 10,
  callback = function(task)
    local boite = boite_authentifiee(task)
    if not boite or boite == '' then return false end
    if task:has_header('Autocrypt') then return false end
    local from = task:get_from('mime')
    if not from or not from[1] or not from[1].addr then return false end
    local adresse = from[1].addr:lower()
    if adresse ~= boite then return false end          -- jamais au nom d'un autre
    local keydata = table_cles[adresse]
    if not keydata then return false end
    lua_mime.modify_headers(task, {
      add = { ['Autocrypt'] = { value = 'addr=' .. adresse .. '; keydata=' .. replie(keydata), order = 1 } },
    })
    rspamd_logger.infox(task, '%s: en-tête ajouté pour %s', N, adresse)
    return true
  end,
})
