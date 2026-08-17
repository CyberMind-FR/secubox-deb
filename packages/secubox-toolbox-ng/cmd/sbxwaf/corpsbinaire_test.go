package main

import "testing"

func TestCorpsBinaireReconnaitLesEnvoisDeFichier(t *testing.T) {
	// L'envoi de l'application Mastodon, exactement tel qu'il arrive.
	for _, ct := range []string{
		"multipart/form-data; boundary=----WebKitFormBoundaryABC123",
		"MULTIPART/FORM-DATA; boundary=x",
		"image/jpeg", "image/png", "video/mp4", "audio/ogg",
		"application/octet-stream", "application/pdf", "application/zip",
	} {
		if !corpsBinaire(ct) {
			t.Errorf("corps binaire non reconnu, il sera juge par des regles textuelles : %q", ct)
		}
	}
}

// CE QUI DOIT RESTER INSPECTE. S'abstenir sur du texte reviendrait a ouvrir un
// trou : c'est dans ces corps-la que passent les injections reelles.
func TestLeTexteResteInspecte(t *testing.T) {
	for _, ct := range []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"application/xml",
		"text/plain",
		"text/html",
		"", // absent : on n'a aucune raison de supposer du binaire
	} {
		if corpsBinaire(ct) {
			t.Errorf("TROU : %q ne serait plus inspecte", ct)
		}
	}
}
