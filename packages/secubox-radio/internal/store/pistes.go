package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

// Piste : ce que l'interface affiche.
type Piste struct {
	ID           int64
	Source       string
	Titre        string
	Auteur       string
	DureeMS      int64
	AjoutePar    int64
	AjouteLe     int64
	Fichier      string
	Mime         string
	Octets       int64
	Indisponible bool
	Raison       string
	Etat         string
	Motif        string
	Coeurs       int
	JoueeLe      int64 // 0 = jamais
}

// EnCache dit si la piste est prete a passer.
func (p Piste) EnCache() bool { return p.Fichier != "" && !p.Indisponible }

// Ajoute depose une piste, ou rend celle qui existe deja.
//
// LE DOUBLON N'EST PAS UNE ERREUR, c'est le geste banal de deux personnes qui
// aiment la meme chanson. On rend la piste existante et `neuf=false` : refuser
// obligerait l'appelant a distinguer une panne d'un cas normal.
//
// UNE PISTE INDISPONIBLE REDEVIENT CANDIDATE si on la repropose : c'est
// souvent ce que veut dire le geste — « reessaie celle-la ».
func (s *Store) Ajoute(source, titre string, par int64, maintenant time.Time) (Piste, bool, error) {
	cle := CleSource(source)
	if cle == "" {
		return Piste{}, false, errors.New("adresse vide")
	}
	if p, err := s.ParSource(cle); err == nil {
		if p.Indisponible {
			if _, err := s.db.Exec(
				`UPDATE pistes SET indisponible = 0, raison = '' WHERE id = ?`, p.ID); err != nil {
				return Piste{}, false, err
			}
			p.Indisponible, p.Raison = false, ""
		}
		return p, false, nil
	} else if !errors.Is(err, ErrPisteInconnue) {
		return Piste{}, false, err
	}
	var parN sql.NullInt64
	if par > 0 {
		parN = sql.NullInt64{Int64: par, Valid: true}
	}
	res, err := s.db.Exec(
		`INSERT INTO pistes (source, titre, ajoute_par, ajoute_le) VALUES (?,?,?,?)`,
		cle, titre, parN, maintenant.Unix())
	if err != nil {
		return Piste{}, false, err
	}
	id, _ := res.LastInsertId()
	p, err := s.ParID(id)
	return p, true, err
}

const selectPiste = `
SELECT p.id, p.source, p.titre, p.auteur, p.duree_ms,
       COALESCE(p.ajoute_par, 0), p.ajoute_le, p.fichier, p.mime, p.octets,
       p.indisponible, p.raison, p.etat, p.motif,
       (SELECT COUNT(*) FROM coeurs c WHERE c.piste_id = p.id) AS coeurs,
       COALESCE((SELECT MAX(l.debut_le) FROM lectures l WHERE l.piste_id = p.id), 0) AS jouee_le
  FROM pistes p `

func (s *Store) scan(r interface{ Scan(...any) error }) (Piste, error) {
	var p Piste
	var indispo int
	err := r.Scan(&p.ID, &p.Source, &p.Titre, &p.Auteur, &p.DureeMS,
		&p.AjoutePar, &p.AjouteLe, &p.Fichier, &p.Mime, &p.Octets,
		&indispo, &p.Raison, &p.Etat, &p.Motif, &p.Coeurs, &p.JoueeLe)
	p.Indisponible = indispo == 1
	return p, err
}

func (s *Store) ParID(id int64) (Piste, error) {
	p, err := s.scan(s.db.QueryRow(selectPiste+`WHERE p.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrPisteInconnue
	}
	return p, err
}

func (s *Store) ParSource(cle string) (Piste, error) {
	p, err := s.scan(s.db.QueryRow(selectPiste+`WHERE p.source = ?`, cle))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrPisteInconnue
	}
	return p, err
}

// Toutes rend LA PLAYLIST — c'est-a-dire ce qui est valide, et rien d'autre.
//
// Une proposition n'est pas a l'antenne. La rendre ici l'aurait fait passer
// dans le tirage par la porte de derriere, puisque `PourTirage` s'appuie sur
// cette liste.
func (s *Store) Toutes() ([]Piste, error) {
	rows, err := s.db.Query(selectPiste + `WHERE p.etat = 'validee' ORDER BY p.ajoute_le, p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Piste
	for rows.Next() {
		p, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PourTirage convertit la playlist en ce que le tirage attend.
//
// UNE PISTE PAS ENCORE EN CACHE EST ECARTEE comme indisponible : la tirer
// donnerait un silence. Elle reste dans la file, visible, avec son etat.
func (s *Store) PourTirage() ([]tirage.Piste, []Piste, error) {
	pistes, err := s.Toutes()
	if err != nil {
		return nil, nil, err
	}
	out := make([]tirage.Piste, 0, len(pistes))
	for _, p := range pistes {
		t := tirage.Piste{
			ID:           p.ID,
			AjouteLe:     time.Unix(p.AjouteLe, 0),
			Coeurs:       p.Coeurs,
			Indisponible: p.Indisponible || !p.EnCache(),
		}
		if p.JoueeLe > 0 {
			t.JoueeLe = time.Unix(p.JoueeLe, 0)
		}
		out = append(out, t)
	}
	return out, pistes, nil
}

// PoseCoeur : idempotent. Aimer deux fois n'est pas une erreur, c'est un
// double clic.
func (s *Store) PoseCoeur(pisteID, userID int64, maintenant time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO coeurs (piste_id, user_id, mis_le) VALUES (?,?,?)
		 ON CONFLICT (piste_id, user_id) DO NOTHING`,
		pisteID, userID, maintenant.Unix())
	return err
}

func (s *Store) RetireCoeur(pisteID, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM coeurs WHERE piste_id = ? AND user_id = ?`, pisteID, userID)
	return err
}

// ACoeur dit si CETTE personne a aime — pour que le bouton montre son etat.
func (s *Store) ACoeur(pisteID, userID int64) (bool, error) {
	var un int
	err := s.db.QueryRow(
		`SELECT 1 FROM coeurs WHERE piste_id = ? AND user_id = ?`, pisteID, userID).Scan(&un)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// NoteLecture inscrit qu'une piste commence, avec la graine du tirage.
//
// LA GRAINE EST RETENUE : c'est elle qui rend le choix explicable apres coup.
func (s *Store) NoteLecture(pisteID int64, debut time.Time, graine int64) error {
	_, err := s.db.Exec(
		`INSERT INTO lectures (piste_id, debut_le, graine) VALUES (?,?,?)`,
		pisteID, debut.Unix(), graine)
	return err
}

// PoseCache enregistre le fichier local d'une piste.
func (s *Store) PoseCache(id int64, fichier, mime string, octets, dureeMS int64, titre, auteur string) error {
	_, err := s.db.Exec(
		`UPDATE pistes SET fichier = ?, mime = ?, octets = ?, duree_ms = ?,
		        titre = CASE WHEN ? <> '' THEN ? ELSE titre END,
		        auteur = CASE WHEN ? <> '' THEN ? ELSE auteur END,
		        indisponible = 0, raison = ''
		  WHERE id = ?`,
		fichier, mime, octets, dureeMS, titre, titre, auteur, auteur, id)
	return err
}

// MarqueIndisponible ecarte une piste SANS la supprimer, avec sa raison.
func (s *Store) MarqueIndisponible(id int64, raison string) error {
	_, err := s.db.Exec(
		`UPDATE pistes SET indisponible = 1, raison = ? WHERE id = ?`, raison, id)
	return err
}

func (s *Store) Retire(id int64) error {
	_, err := s.db.Exec(`DELETE FROM pistes WHERE id = ?`, id)
	return err
}

// ── PROPOSITIONS ────────────────────────────────────────────────────────────

// Etats d'une piste.
const (
	EtatPropose = "proposee"
	EtatValide  = "validee"
	EtatRefuse  = "refusee"
)

// ErrDejaRefusee : la piste a ete ecartee par le sysop. La reproposer ne la
// ressuscite pas.
var ErrDejaRefusee = errors.New("piste deja refusee par le sysop")

// Propose depose une piste EN ATTENTE de validation.
//
// LA DIFFERENCE AVEC `Ajoute` N'EST PAS COSMETIQUE : `Ajoute` sert au sysop et
// met directement a l'antenne ; `Propose` sert aux membres et ne met rien.
// Une seule fonction avec un drapeau aurait fini par etre appelee avec le
// mauvais drapeau.
func (s *Store) Propose(source, titre string, par int64, maintenant time.Time) (Piste, bool, error) {
	return s.depose(source, titre, par, maintenant, EtatPropose)
}

func (s *Store) depose(source, titre string, par int64, maintenant time.Time, etat string) (Piste, bool, error) {
	cle := CleSource(source)
	if cle == "" {
		return Piste{}, false, errors.New("adresse vide")
	}
	if p, err := s.ParSource(cle); err == nil {
		// UN REFUS NE SE CONTOURNE PAS EN REPROPOSANT. Sans cette garde, un
		// membre ecarte par le sysop n'a qu'a recoller son lien pour revenir —
		// la validation ne vaudrait plus rien. C'est le seul chemin par lequel
		// la file de propositions pouvait etre videe de son sens.
		if p.Etat == EtatRefuse {
			return p, false, ErrDejaRefusee
		}
		// Une piste ecartee pour raison TECHNIQUE, elle, revient en jeu : c'est
		// en general ce que le geste veut dire, « reessaie celle-la ». Refus du
		// sysop et echec de telechargement sont deux choses differentes, et les
		// confondre creerait precisement le contournement ci-dessus.
		if p.Indisponible {
			if _, err := s.db.Exec(
				`UPDATE pistes SET indisponible = 0, raison = '' WHERE id = ?`, p.ID); err != nil {
				return Piste{}, false, err
			}
			p.Indisponible, p.Raison = false, ""
		}
		return p, false, nil
	} else if !errors.Is(err, ErrPisteInconnue) {
		return Piste{}, false, err
	}
	var parN sql.NullInt64
	if par > 0 {
		parN = sql.NullInt64{Int64: par, Valid: true}
	}
	res, err := s.db.Exec(
		`INSERT INTO pistes (source, titre, ajoute_par, ajoute_le, etat) VALUES (?,?,?,?,?)`,
		cle, titre, parN, maintenant.Unix(), etat)
	if err != nil {
		return Piste{}, false, err
	}
	id, _ := res.LastInsertId()
	p, err := s.ParID(id)
	return p, true, err
}

// Valide fait entrer une proposition a l'antenne.
//
// LES COEURS DEJA POSES SUIVENT : c'est une seule ligne qui change d'etat.
// L'enthousiasme qui a fait entrer le titre devient son poids de tirage.
func (s *Store) Valide(id, par int64, maintenant time.Time) error {
	return s.decide(id, par, maintenant, EtatValide, "")
}

// Refuse ecarte une proposition, avec un motif.
//
// LA PISTE N'EST PAS SUPPRIMEE : sans la ligne, la meme adresse pourrait etre
// reproposee indefiniment et le sysop trancherait chaque semaine la meme
// question.
func (s *Store) Refuse(id, par int64, maintenant time.Time, motif string) error {
	return s.decide(id, par, maintenant, EtatRefuse, motif)
}

func (s *Store) decide(id, par int64, maintenant time.Time, etat, motif string) error {
	var parN sql.NullInt64
	if par > 0 {
		parN = sql.NullInt64{Int64: par, Valid: true}
	}
	res, err := s.db.Exec(
		`UPDATE pistes SET etat = ?, decide_par = ?, decide_le = ?, motif = ? WHERE id = ?`,
		etat, parN, maintenant.Unix(), motif, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPisteInconnue
	}
	return nil
}

// Propositions rend la file d'attente du sysop, LES PLUS SOUTENUES D'ABORD.
//
// Trier par date ferait remonter ce qui vient d'arriver ; trier par coeurs fait
// remonter ce que la communaute demande. C'est la seule liste ou le coeur agit
// comme un vote — sur une piste deja a l'antenne, il ne pese que sur la
// probabilite.
func (s *Store) Propositions() ([]Piste, error) {
	// ON TRIE PAR NOM, JAMAIS PAR NUMERO DE COLONNE. Le premier jet ecrivait
	// `ORDER BY 13 DESC` : en ajoutant `etat` et `motif` au SELECT, la 13e
	// colonne est devenue `etat`, constante dans cette requete — le tri s'est
	// fait en silence sur rien du tout, et la file remontait l'ordre d'arrivee.
	return s.parEtat(EtatPropose, `ORDER BY coeurs DESC, p.ajoute_le`)
}

// Refusees : gardees visibles, pour que le refus soit consultable.
func (s *Store) Refusees() ([]Piste, error) {
	return s.parEtat(EtatRefuse, `ORDER BY p.decide_le DESC`)
}

func (s *Store) parEtat(etat, ordre string) ([]Piste, error) {
	rows, err := s.db.Query(selectPiste+`WHERE p.etat = ? `+ordre, etat)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Piste
	for rows.Next() {
		p, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── CACHE ───────────────────────────────────────────────────────────────────

// OctetsEnCache : ce que le parc occupe deja.
func (s *Store) OctetsEnCache() (int64, error) {
	var n int64
	err := s.db.QueryRow(
		`SELECT COALESCE(SUM(octets),0) FROM pistes WHERE fichier <> ''`).Scan(&n)
	return n, err
}

// APurger rend les pistes a evincer pour repasser sous la borne.
//
// LA MOINS RECEMMENT JOUEE D'ABORD, et non la plus ancienne : une piste de
// 2019 qui passe chaque semaine doit rester ; une nouveaute que personne
// n'ecoute peut partir. C'est ce que « moins recemment utilisee » veut dire, et
// trier par date d'ajout aurait fait exactement l'inverse.
//
// UNE PISTE N'EST PAS SUPPRIMEE, SEULEMENT SON FICHIER : elle reste dans la
// playlist, sera reprise si elle ressort au tirage. Evincer la ligne aurait
// fait disparaitre des titres du repertoire a chaque menage.
func (s *Store) APurger(borne int64, proteges map[int64]bool) ([]Piste, error) {
	total, err := s.OctetsEnCache()
	if err != nil {
		return nil, err
	}
	if total <= borne {
		return nil, nil
	}
	rows, err := s.db.Query(selectPiste + `WHERE p.fichier <> ''
		 ORDER BY jouee_le ASC, p.ajoute_le ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Piste
	for rows.Next() && total > borne {
		p, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		// ON NE RETIRE JAMAIS CE QUI PASSE OU VA PASSER : le programme est
		// fige sur quelques titres, les evincer couperait l'antenne.
		if proteges[p.ID] {
			continue
		}
		out = append(out, p)
		total -= p.Octets
	}
	return out, rows.Err()
}

// OublieCache retire le fichier d'une piste, sans toucher a la piste.
func (s *Store) OublieCache(id int64) error {
	_, err := s.db.Exec(
		`UPDATE pistes SET fichier = '', mime = '', octets = 0 WHERE id = ?`, id)
	return err
}
