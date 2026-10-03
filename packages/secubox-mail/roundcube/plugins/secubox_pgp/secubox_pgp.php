<?php
/**
 * SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * Source-Disclosed License — All rights reserved except as expressly granted.
 * See LICENCE-CMSD-1.0.md for terms.
 *
 * SecuBox-Deb :: secubox_pgp — OpenPGP dans le webmail, SANS clé côté serveur (#1852, P5)
 * CyberMind — https://cybermind.fr
 *
 * Ce greffon n'a AUCUNE cryptographie. Il insère, dans un cadre invisible, la page OpenPGP du Coffre
 * (https://pgp.<domaine>/pgp/), qui est d'une AUTRE origine : c'est elle qui tient la clé de la personne
 * (ouverte par sa connexion) et qui chiffre, signe, déchiffre, vérifie. Le JavaScript de ce webmail lui
 * envoie un texte et reçoit un résultat par postMessage ; il ne voit jamais la clé.
 *
 * Il n'agit que si `secubox_pgp_origine` est posé dans la configuration : sans cela, il ne charge rien.
 * `enigma` (clés côté serveur) reste exclu (#1738).
 */
class secubox_pgp extends rcube_plugin
{
    public $task = 'mail';

    public function init()
    {
        $rcmail  = rcmail::get_instance();
        $origine = (string) $rcmail->config->get('secubox_pgp_origine', '');
        if (!preg_match('~^https://[a-z0-9.-]+(:[0-9]{1,5})?$~', $origine)) {
            return;                                   // pas d'origine déclarée : le greffon ne fait rien
        }
        $this->add_texts('localization/', true);
        $rcmail->output->set_env('secubox_pgp_origine', $origine);
        $this->include_script('secubox_pgp.js');
        $this->include_stylesheet('secubox_pgp.css');

        if ($rcmail->action === 'compose') {
            foreach (['chiffrer' => 'chiffrer', 'signer' => 'signer'] as $cmd => $label) {
                $this->add_button([
                    'command'    => 'plugin.secubox_pgp.' . $cmd,
                    'type'       => 'link',
                    'class'      => 'button secubox-pgp ' . $cmd,
                    'classact'   => 'button secubox-pgp ' . $cmd . ' active',
                    'label'      => 'secubox_pgp.' . $label,
                    'title'      => 'secubox_pgp.' . $label . 'info',
                    'innerclass' => 'inner',
                ], 'toolbar');
            }
        }
        $this->add_hook('message_load', [$this, 'message_charge']);
    }

    /**
     * Ce que le navigateur doit savoir du message affiché : son expéditeur et son en-tête Autocrypt.
     * L'en-tête n'est transmis que s'il annonce l'adresse même de l'expéditeur (règle d'Autocrypt) ; le
     * contrôle de la clé reste fait par la page du Coffre.
     */
    public function message_charge($args)
    {
        $rcmail = rcmail::get_instance();
        $msg    = $args['object'];
        if (!$msg || empty($msg->headers)) {
            return $args;
        }
        $de = '';
        if (!empty($msg->sender['mailto'])) {
            $de = strtolower($msg->sender['mailto']);
        }
        $info = ['expediteur' => $de, 'autocrypt' => null];
        $brut = $rcmail->storage->get_raw_headers($msg->uid);
        if (is_string($brut) && $de !== '') {
            $brut = preg_replace("/\r?\n[ \t]+/", ' ', $brut);        // dépliage RFC 5322
            if (preg_match('/^Autocrypt:\s*(.+)$/mi', $brut, $m)) {
                $addr = '';
                $kd   = '';
                foreach (explode(';', $m[1]) as $attr) {
                    $kv = explode('=', trim($attr), 2);
                    if (count($kv) === 2 && strtolower($kv[0]) === 'addr') {
                        $addr = strtolower(trim($kv[1]));
                    } elseif (count($kv) === 2 && strtolower($kv[0]) === 'keydata') {
                        $kd = preg_replace('/\s+/', '', $kv[1]);
                    }
                }
                if ($addr === $de && preg_match('~^[A-Za-z0-9+/=]{40,16000}$~', $kd)) {
                    $info['autocrypt'] = ['courriel' => $addr, 'keydata' => $kd];
                }
            }
        }
        $rcmail->output->set_env('secubox_pgp_message', $info);
        return $args;
    }
}
