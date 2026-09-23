module github.com/CyberMind-FR/secubox-deb/gabriel-mood

// Go 1.22, comme tout le dépôt.
//
// LE BRIEF DEMANDAIT 1.25, ET `go mod tidy` L'A MIS TOUT SEUL : la dernière
// version de modernc.org/sqlite l'exige, et Go a téléchargé la chaîne 1.25
// dans le GOPATH du paquet pour y parvenir. Un paquet Debian ne doit pas
// dépendre d'un téléchargement de compilateur au moment de la construction —
// et `golang-go (>= 2:1.22~)` est ce que le dépôt déclare partout ailleurs.
// On épingle donc sqlite à la version que secubox-metanews vendorise déjà.
// Rien dans ce module ne demande une version plus récente du langage.
go 1.22

require (
	github.com/gorilla/websocket v1.5.3
	modernc.org/sqlite v1.29.10
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.19.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.49.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)
