// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// tailleMaxCle : une clé PEM Ed25519 fait ~120 octets ; au-delà, ce n'en est pas une.
const tailleMaxCle = 4096

// lireSansLien ouvre chemin sans suivre de lien (O_NOFOLLOW), exige un fichier régulier à un seul
// lien physique, appartenant à uid, et rend son contenu (≤ tailleMaxCle). interdit : bits de mode
// refusés (0o077 pour la clé privée, 0o022 pour la publique).
func lireSansLien(chemin string, uid uint32, interdit uint32) ([]byte, error) {
	fd, err := syscall.Open(chemin, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: chemin, Err: err}
	}
	f := os.NewFile(uintptr(fd), chemin)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: chemin, Err: err}
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return nil, fmt.Errorf("%s : pas un fichier régulier", chemin)
	case st.Uid != uid:
		return nil, fmt.Errorf("%s : propriétaire %d, attendu %d", chemin, st.Uid, uid)
	case st.Mode&interdit != 0:
		return nil, fmt.Errorf("%s : mode %04o trop ouvert", chemin, st.Mode&0o7777)
	case st.Nlink != 1:
		return nil, fmt.Errorf("%s : %d liens physiques", chemin, st.Nlink)
	}
	b, err := io.ReadAll(io.LimitReader(f, tailleMaxCle+1))
	if err != nil {
		return nil, err
	}
	if len(b) > tailleMaxCle {
		return nil, fmt.Errorf("%s : plus long que %d octets", chemin, tailleMaxCle)
	}
	return b, nil
}

// dossierPrive : dir est un vrai dossier (pas un lien) du compte courant, fermé au groupe et aux autres.
func dossierPrive(dir string, uid uint32, interdit uint32) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir() || !ok:
		return fmt.Errorf("%s : pas un dossier", dir)
	case sys.Uid != uid:
		return fmt.Errorf("%s : propriétaire %d, attendu %d", dir, sys.Uid, uid)
	case uint32(st.Mode().Perm())&interdit != 0:
		return fmt.Errorf("%s : mode %04o trop ouvert", dir, st.Mode().Perm())
	}
	return nil
}

// ChargerCle lit la clé PRIVÉE du relais : PEM PKCS#8 Ed25519, fichier du compte courant, 0600 au plus.
func ChargerCle(chemin string) (ed25519.PrivateKey, error) {
	b, err := lireSansLien(chemin, uint32(os.Geteuid()), 0o077)
	if err != nil {
		return nil, err
	}
	bloc, _ := pem.Decode(b)
	if bloc == nil || bloc.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s : PEM PKCS#8 attendu", chemin)
	}
	k, err := x509.ParsePKCS8PrivateKey(bloc.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s : %v", chemin, err)
	}
	cle, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s : pas une clé Ed25519", chemin)
	}
	return cle, nil
}

// CreerOuChargerCle : la clé existante, ou une clé neuve créée sans écraser ni suivre de lien
// (brouillon O_EXCL|O_NOFOLLOW 0600 dans le même dossier, puis link(2) : jamais une clé à moitié
// écrite sous le nom final). Le dossier doit être au compte courant et fermé aux autres (0700).
func CreerOuChargerCle(chemin string) (ed25519.PrivateKey, error) {
	uid := uint32(os.Geteuid())
	dir := filepath.Dir(chemin)
	if err := dossierPrive(dir, uid, 0o077); err != nil {
		return nil, err
	}
	cle, err := ChargerCle(chemin)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return cle, err
	}
	_, neuve, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(neuve)
	if err != nil {
		return nil, err
	}
	alea := make([]byte, 8)
	if _, err := rand.Read(alea); err != nil {
		return nil, err
	}
	brouillon := filepath.Join(dir, ".relais.key."+hex.EncodeToString(alea))
	fd, err := syscall.Open(brouillon, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: brouillon, Err: err}
	}
	f := os.NewFile(uintptr(fd), brouillon)
	err = f.Chmod(0o600)
	if err == nil {
		err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	if err == nil {
		err = f.Sync()
	}
	if errClose := f.Close(); err == nil {
		err = errClose
	}
	if err != nil {
		os.Remove(brouillon)
		return nil, err
	}
	errLien := os.Link(brouillon, chemin)
	// Le brouillon part AVANT la relecture : la clé ne doit avoir qu'un lien physique.
	if err := os.Remove(brouillon); err != nil {
		return nil, err
	}
	if errLien != nil && !errors.Is(errLien, fs.ErrExist) {
		return nil, errLien
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return ChargerCle(chemin)
}

// PEMPublique : la clé publique en PEM SubjectPublicKeyInfo, ce que lit `_cle_publique_relais`.
func PEMPublique(cle ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(cle.Public())
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// VerifierClePublique : au démarrage, la clé publique posée par le postinst (root, 0644, dossier
// root non inscriptible par d'autres) est bien celle de la clé privée. Sinon les modules refuseraient
// chaque jeton : on préfère ne pas démarrer et le dire.
func VerifierClePublique(chemin string, cle ed25519.PrivateKey, proprio uint32) error {
	if err := dossierPrive(filepath.Dir(chemin), proprio, 0o022); err != nil {
		return err
	}
	b, err := lireSansLien(chemin, proprio, 0o022)
	if err != nil {
		return err
	}
	bloc, _ := pem.Decode(b)
	if bloc == nil || bloc.Type != "PUBLIC KEY" {
		return fmt.Errorf("%s : PEM SubjectPublicKeyInfo attendu", chemin)
	}
	k, err := x509.ParsePKIXPublicKey(bloc.Bytes)
	if err != nil {
		return fmt.Errorf("%s : %v", chemin, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok || !pub.Equal(cle.Public()) {
		return fmt.Errorf("%s : ne correspond pas à la clé privée du relais", chemin)
	}
	return nil
}
