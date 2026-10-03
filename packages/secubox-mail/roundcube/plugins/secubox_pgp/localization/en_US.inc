<?php
/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 */
$labels = [];
$labels['chiffrer']        = 'Encrypt';
$labels['chiffrerinfo']    = 'Encrypt (and sign) this message with your Vault key — the key never leaves your browser';
$labels['signer']          = 'Sign';
$labels['signerinfo']      = 'Sign this message with your Vault key';
$labels['textebrut']       = 'Encryption and signing need plain text: switch the editor to text, then try again.';
$labels['manquants']       = 'No key for: $adresses. The message is not sent: it will never go out in clear by mistake.';
$labels['pasdecle']        = 'No OpenPGP key in "My vault": create it first.';
$labels['coffrescelle']    = 'The box Vault is sealed: an administrator must log in.';
$labels['nonconnecte']     = 'Session missing or expired: log in again.';
$labels['indisponible']    = 'The Vault OpenPGP page does not answer.';
$labels['dechiffre']       = 'Message decrypted in your browser';
$labels['signe']           = 'Signed message';
$labels['sigvalide']       = 'Valid signature';
$labels['siginvalide']     = 'INVALID SIGNATURE — the message was altered or the key does not match';
$labels['sigconnue']       = 'Signature present, but the sender\'s key is not known';
$labels['sigaucune']       = 'Not signed';
