module github.com/CyberMind-FR/secubox-deb/secubox-signal

go 1.22

// DEUX DEPENDANCES, et toutes deux DEJA vendorisees ailleurs dans le parc :
//   - modernc.org/sqlite   : SQLite pur Go, sans cgo. Standard du parc
//                            (socialrelay, metanews, bbs, radio).
//   - github.com/skip2/go-qrcode : QR d'appairage. Deja utilise par
//                            socialrelay, exactement pour cet usage.
//
// Ce qui n'est PAS pris, et pourquoi :
//   - pas de parseur TOML : la configuration du module est plate, un lecteur
//     de 80 lignes dans internal/config suffit (cf. son en-tete).
//   - pas de bibliotheque WebSocket : la poignee de main RFC 6455 et le
//     tramage texte tiennent dans internal/ws. Importer un framework pour
//     cela couterait plus a auditer qu'a ecrire.
require (
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
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
