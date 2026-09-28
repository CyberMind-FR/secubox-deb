<?php
/*
 * SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * Source-Disclosed License — All rights reserved except as expressly granted.
 * See LICENCE-CMSD-1.0.md for terms.
 *
 * SecuBox :: secubox_sso — le webmail s'ouvre par la session SecuBox (#1562)
 *
 * SANS MOT DE PASSE POUR LA PERSONNE. Arrivée sans session Roundcube mais avec
 * sa session SecuBox (cookie secubox_session, domaine .<box>), la personne est
 * connectée à SA boîte :
 *   1. la session est VÉRIFIÉE par la box elle-même (/auth/verify, le même
 *      contrôle que le BBS) ; il faut un Remote-User non vide — en mode
 *      « lecture LAN » la route répond 200 sans identité, ce qui ne prouve
 *      rien — ET une boîte liée (Remote-Sbx-Mail) ;
 *   2. Roundcube ouvre IMAP/SMTP/ManageSieve AU NOM de cette boîte avec
 *      l'identifiant maître Dovecot (autorisation SASL : authcid = maître,
 *      authzid = la boîte). Le mot de passe de la personne n'est ni connu ni
 *      demandé ; le maître n'est accepté par Dovecot que depuis ce conteneur,
 *      et seulement pour une boîte qui existe (pass=yes).
 *   3. Le formulaire reste le formulaire : une saisie (_user posté) n'est
 *      jamais touchée, et le maître n'est posé que pour une session ouverte
 *      par ce greffon — jamais globalement.
 *
 * Déconnexion : un cookie de session empêche la reconnexion immédiate ; il
 * tombe avec le navigateur.
 */
class secubox_sso extends rcube_plugin
{
    public $task = '.*';

    function init()
    {
        $this->load_config();
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('storage_connect', [$this, 'relais']);
        $this->add_hook('managesieve_connect', [$this, 'relais']);
        $this->add_hook('smtp_connect', [$this, 'smtp']);
        $this->add_hook('logout_after', [$this, 'deconnecte']);
    }

    function startup($args)
    {
        if (empty($_SESSION['user_id']) && $args['task'] == 'login'
            && empty($_POST['_user']) && !empty($_COOKIE['secubox_session'])
            && empty($_COOKIE['secubox_sso_off'])) {
            $args['action'] = 'login';
        }
        return $args;
    }

    function authenticate($args)
    {
        if (!empty($_POST['_user'])) {
            return $args;                        // une saisie : le chemin ordinaire
        }
        $boite = $this->verifie();
        if ($boite) {
            $args['user'] = $boite;
            $args['pass'] = 'secubox-sso';       // jamais utilisé : le maître autorise
            $args['cookiecheck'] = false;
            $args['valid'] = true;
            $_SESSION['secubox_sso'] = 1;
        }
        return $args;
    }

    function relais($args)
    {
        if (!empty($_SESSION['secubox_sso'])) {
            $rc = rcmail::get_instance();
            $args['auth_cid'] = $rc->config->get('secubox_sso_maitre');
            $args['auth_pw'] = $rc->config->get('secubox_sso_secret');
            $args['auth_type'] = 'PLAIN';
        }
        return $args;
    }

    function smtp($args)
    {
        if (!empty($_SESSION['secubox_sso'])) {
            $rc = rcmail::get_instance();
            $args['smtp_user'] = $rc->get_user_name();
            $args['smtp_pass'] = '';
            $args['smtp_auth_cid'] = $rc->config->get('secubox_sso_maitre');
            $args['smtp_auth_pw'] = $rc->config->get('secubox_sso_secret');
            $args['smtp_auth_type'] = 'PLAIN';
        }
        return $args;
    }

    function deconnecte($args)
    {
        rcube_utils::setcookie('secubox_sso_off', '1', 0);
        return $args;
    }

    /** La boîte liée à la session SecuBox, ou null. */
    private function verifie()
    {
        $rc = rcmail::get_instance();
        $url = $rc->config->get('secubox_sso_verify');
        // Le Hall de CETTE box : webmail.gk2.secubox.in → hall.gk2.secubox.in,
        // sauf réglage explicite. Aucun nom de domaine écrit en dur.
        $hote = $rc->config->get('secubox_sso_hote')
            ?: 'hall.' . preg_replace('/^[^.]+\./', '', strtolower($_SERVER['HTTP_HOST'] ?? ''));
        if (!preg_match('/^[a-z0-9.\-]+$/', $hote)) {
            return null;
        }
        $jeton = preg_replace('/[^A-Za-z0-9._\-]/', '', $_COOKIE['secubox_session'] ?? '');
        if (!$url || !$jeton || !$rc->config->get('secubox_sso_maitre')) {
            return null;
        }
        $ctx = stream_context_create([
            'http' => ['method' => 'GET', 'timeout' => 4, 'ignore_errors' => true,
                       'header' => "Host: $hote\r\nCookie: secubox_session=$jeton\r\n"],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        if (@file_get_contents($url, false, $ctx) === false || empty($http_response_header)) {
            return null;
        }
        $code = 0; $qui = ''; $boite = '';
        foreach ($http_response_header as $l) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $l, $m)) $code = (int)$m[1];
            elseif (stripos($l, 'Remote-User:') === 0) $qui = trim(substr($l, 12));
            elseif (stripos($l, 'Remote-Sbx-Mail:') === 0) $boite = strtolower(trim(substr($l, 16)));
        }
        if ($code !== 200 || $qui === '' || !preg_match('/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/', $boite)) {
            return null;
        }
        return $boite;
    }
}
