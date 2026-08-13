<?php
/**
 * SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * Source-Disclosed License — All rights reserved except as expressly granted.
 * See LICENCE-CMSD-1.0.md for terms.
 *
 * SecuBox-Deb :: zipjointes — grouper les pièces jointes en une archive (#1029)
 * CyberMind — https://cybermind.fr
 *
 * Un bouton dans la composition : les pièces jointes du message deviennent une
 * archive unique, qui REMPLACE les originales.
 *
 * ON NE TOUCHE JAMAIS UN CHEMIN DE FICHIER. Roundcube a trois pilotes de
 * stockage pour les pièces en cours de composition — `filesystem_attachments`,
 * `database_attachments`, `redundant_attachments` — et seul le premier pose des
 * fichiers sur disque. Tout passe donc par les crochets `attachment_get`,
 * `attachment_upload` et `attachment_delete`, exactement comme le fait
 * Roundcube lui-même. Un greffon qui lirait `$att['path']` marcherait ici et
 * casserait chez qui stocke en base, sans que rien ne l'annonce.
 */
class zipjointes extends rcube_plugin
{
    public $task = 'mail';

    /** Au-delà, on refuse : l'archive est construite EN MEMOIRE. */
    private const TAILLE_MAX = 268435456; // 256 Mio

    /** Types que compresser ne réduit pas — voir estDejaCompresse(). */
    private const DEJA_COMPRESSE = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif',
        'audio/mpeg', 'audio/ogg', 'audio/flac', 'audio/mp4',
        'video/mp4', 'video/webm', 'video/x-matroska', 'video/quicktime',
        'application/zip', 'application/gzip', 'application/x-7z-compressed',
        'application/x-rar-compressed', 'application/x-xz',
        'application/pdf',
    ];

    public function init()
    {
        $this->add_texts('localization/', true);
        $this->register_action('plugin.zipjointes.grouper', [$this, 'grouper']);
        $this->add_hook('template_object_composeattachmentlist', [$this, 'bouton']);
        $this->include_script('zipjointes.js');
    }

    /**
     * Pose le bouton sous la liste des pièces jointes.
     *
     * SOUS LA LISTE, ET NON DANS LA BARRE D'OUTILS : le geste porte sur les
     * pièces jointes, il doit se trouver là où on les regarde. Dans la barre,
     * il serait noyé parmi des actions qui concernent le message entier.
     */
    public function bouton($p)
    {
        $rcmail = rcmail::get_instance();

        $lien = html::a([
            'href'    => '#',
            'class'   => 'button zipjointes',
            'id'      => 'zipjointes-grouper',
            'onclick' => "return rcmail.command('plugin.zipjointes.grouper','',this,event)",
            'title'   => $this->gettext('grouperinfo'),
        ], rcube::Q($this->gettext('grouper')));

        $rcmail->output->add_gui_object('zipjointesbouton', 'zipjointes-grouper');
        $p['content'] .= html::div(['class' => 'zipjointes-barre'], $lien);

        return $p;
    }

    /**
     * Groupe les pièces jointes de la composition en une archive.
     */
    public function grouper()
    {
        $rcmail = rcmail::get_instance();
        $id     = rcube_utils::get_input_value('_id', rcube_utils::INPUT_GPC);
        $cle    = 'compose_data_' . $id;

        $pieces = (array) ($_SESSION[$cle]['attachments'] ?? []);

        // MOINS DE DEUX PIECES : il n'y a rien à grouper. On le dit plutôt que
        // de produire une archive à un seul membre, qui serait plus lourde et
        // moins pratique que le fichier qu'elle enferme.
        if (count($pieces) < 2) {
            $rcmail->output->command('display_message', $this->gettext('rienagrouper'), 'warning');
            $rcmail->output->send();
            return;
        }

        $total = 0;
        foreach ($pieces as $a) {
            $total += (int) ($a['size'] ?? 0);
        }
        if ($total > self::TAILLE_MAX) {
            // L'ARCHIVE EST CONSTRUITE EN MEMOIRE. Refuser franchement vaut
            // mieux que faire tomber PHP sur une limite mémoire au milieu du
            // travail, en laissant les pièces d'origine dans un état incertain.
            $rcmail->output->command('display_message',
                $this->gettext('troplourd'), 'error');
            $rcmail->output->send();
            return;
        }

        $tmp = rcube_utils::temp_filename('zipjointes');
        $zip = new ZipArchive();
        if ($zip->open($tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            $rcmail->output->command('display_message', $this->gettext('echecarchive'), 'error');
            $rcmail->output->send();
            return;
        }

        $noms  = [];
        $brut  = 0;
        $dejaC = 0;

        foreach ($pieces as $a) {
            $contenu = $this->contenu($a);
            if ($contenu === null) {
                // UNE PIECE ILLISIBLE ARRETE TOUT. Produire une archive
                // incomplète ET supprimer les originales ferait perdre un
                // fichier — le seul résultat vraiment inacceptable ici.
                $zip->close();
                @unlink($tmp);
                $rcmail->output->command('display_message',
                    $this->gettext('pieceillisible'), 'error');
                $rcmail->output->send();
                return;
            }
            $nom = $this->nomUnique($a['name'] ?? 'piece.bin', $noms);
            $zip->addFromString($nom, $contenu);
            $brut += strlen($contenu);
            if ($this->estDejaCompresse($a['mimetype'] ?? '')) {
                $dejaC++;
            }
            unset($contenu);
        }

        $zip->close();
        $taille = @filesize($tmp);

        if (!$taille) {
            @unlink($tmp);
            $rcmail->output->command('display_message', $this->gettext('echecarchive'), 'error');
            $rcmail->output->send();
            return;
        }

        // L'ARCHIVE EST ENREGISTREE AVANT QUE LES ORIGINALES NE PARTENT.
        // L'ordre inverse laisserait, si l'enregistrement échoue, un message
        // sans aucune pièce jointe — le contenu perdu pour de bon.
        $nouvelle = $rcmail->plugins->exec_hook('attachment_upload', [
            'path'     => $tmp,
            'name'     => $this->nomArchive(),
            'size'     => $taille,
            'mimetype' => 'application/zip',
            'group'    => $id,
        ]);

        if (empty($nouvelle['status']) || !empty($nouvelle['abort'])) {
            @unlink($tmp);
            $rcmail->output->command('display_message', $this->gettext('echecarchive'), 'error');
            $rcmail->output->send();
            return;
        }

        unset($nouvelle['status'], $nouvelle['abort']);
        $rcmail->session->append($cle . '.attachments', $nouvelle['id'], $nouvelle);

        // Puis seulement les originales.
        foreach ($pieces as $ident => $a) {
            $rcmail->plugins->exec_hook('attachment_delete', $a);
            $rcmail->session->remove($cle . '.attachments.' . $ident);
            $rcmail->output->command('remove_from_attachment_list', 'rcmfile' . $ident);
        }
        @unlink($tmp);

        $rcmail->output->command('add2attachment_list', 'rcmfile' . $nouvelle['id'], [
            'html'      => rcube::Q($nouvelle['name']),
            'name'      => $nouvelle['name'],
            'mimetype'  => 'application/zip',
            'classname' => 'zip',
            'complete'  => true,
        ]);

        // ON DIT CE QU'ON A GAGNE, ET CE QU'ON N'A PAS GAGNE. Annoncer un
        // groupage réussi sur des fichiers déjà compressés laisserait croire à
        // une réduction qui n'a pas eu lieu.
        $msg = $this->gettext([
            'name' => 'groupees',
            'vars' => [
                'n'      => count($pieces),
                'avant'  => $this->lisible($brut),
                'apres'  => $this->lisible($taille),
            ],
        ]);
        if ($dejaC > 0 && $taille >= $brut * 0.95) {
            $msg .= ' ' . $this->gettext('dejacompresse');
        }
        $rcmail->output->command('display_message', $msg, 'confirmation');
        $rcmail->output->send();
    }

    /**
     * Rend le contenu d'une pièce jointe, quel que soit son pilote de stockage.
     *
     * `attachment_get` est LE point d'entrée : il rend `data` pour un stockage
     * en base, et un `path` pour un stockage sur disque. Lire `$a['path']`
     * directement marcherait avec `filesystem_attachments` et rendrait null
     * avec `database_attachments` — un greffon qui casse selon la configuration
     * du site, sans rien annoncer.
     */
    private function contenu(array $a): ?string
    {
        $rcmail = rcmail::get_instance();
        $att = $rcmail->plugins->exec_hook('attachment_get', $a);

        if (isset($att['data']) && $att['data'] !== '') {
            return $att['data'];
        }
        if (!empty($att['path']) && is_readable($att['path'])) {
            $d = file_get_contents($att['path']);
            return $d === false ? null : $d;
        }
        return null;
    }

    /**
     * Un nom unique dans l'archive.
     *
     * DEUX PIECES PEUVENT PORTER LE MEME NOM — on joint volontiers deux
     * `capture.png` venus de dossiers différents. Sans ce suffixe, la seconde
     * écraserait la première DANS l'archive : une perte silencieuse, découverte
     * seulement à l'ouverture, par le destinataire.
     */
    private function nomUnique(string $nom, array &$vus): string
    {
        $nom = preg_replace('~[/\\\\]+~', '_', $nom);
        $nom = trim($nom) !== '' ? $nom : 'piece.bin';
        if (!isset($vus[$nom])) {
            $vus[$nom] = 1;
            return $nom;
        }
        $n   = ++$vus[$nom];
        $ext = pathinfo($nom, PATHINFO_EXTENSION);
        $tige = $ext !== '' ? substr($nom, 0, -(strlen($ext) + 1)) : $nom;
        return $ext !== '' ? "{$tige}-{$n}.{$ext}" : "{$tige}-{$n}";
    }

    private function nomArchive(): string
    {
        return 'pieces-jointes-' . date('Ymd-His') . '.zip';
    }

    private function estDejaCompresse(string $mime): bool
    {
        return in_array(strtolower($mime), self::DEJA_COMPRESSE, true);
    }

    private function lisible(int $n): string
    {
        if ($n >= 1048576) {
            return round($n / 1048576, 1) . ' Mio';
        }
        if ($n >= 1024) {
            return round($n / 1024, 1) . ' Kio';
        }
        return $n . ' o';
    }
}
