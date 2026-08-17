// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Évalue le PAC hors navigateur : on injecte le shim PAC `shExpMatch` (glob
// insensible à la casse sur le host, comme les navigateurs), on charge le
// fichier, puis on vérifie FindProxyForURL sur des cas réels.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function shExpMatch(str, pat) {
  // équivalent PAC : * = n'importe quelle suite ; ancré début→fin ; casse ignorée
  const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                                 .replace(/\*/g, '.*') + '$', 'i');
  return re.test(str);
}

const src = fs.readFileSync(path.join(__dirname, '..', 'www', 'tor', 'tor.pac'), 'utf8');
const sandbox = { shExpMatch };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const F = sandbox.FindProxyForURL;

const SOCKS = 'SOCKS5 192.168.1.200:9050';
const cases = [
  ['http://abcdefhij.onion/',      'abcdefhij.onion', SOCKS],   // onion simple
  ['http://a.b.deep.onion/x',      'a.b.deep.onion',  SOCKS],   // sous-domaines
  ['http://onion/',                'onion',           SOCKS],   // host « onion » nu
  ['https://example.com/',         'example.com',     'DIRECT'],
  ['https://onion.example.com/',   'onion.example.com','DIRECT'],// faux match !
  ['https://not-onion.org/',       'not-onion.org',   'DIRECT'],
];
let fail = 0;
for (const [url, host, want] of cases) {
  const got = F(url, host);
  if (got !== want) { console.error(`FAIL ${host}: got ${got} want ${want}`); fail = 1; }
  else console.log(`PASS ${host} -> ${got}`);
}
process.exit(fail);
