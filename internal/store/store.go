package store

import (
	"database/sql"
	"fmt"
	"threatlens/internal/models"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %v", err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("Failed to migrate db: %v", err)
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
`)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS detections (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			title     TEXT,
			severity  INTEGER,
			evidence  TEXT,
			mitre_id  TEXT,
			timestamp TEXT
		);
	`)
	return err
}

func (s *Store) SaveDetections(detections []models.Detection) error {
	for _, d := range detections {
		_, err := s.db.Exec(`INSERT INTO detections (title, severity, evidence, mitre_id, timestamp) VALUES (?, ?, ?, ?, ?)`,
			d.Title, d.Severity, d.Evidence, d.MitreID, d.Timestamp)
		if err != nil {
			return fmt.Errorf("failed to save detection: %v", err)
		}

	}
	return nil
}

func (s *Store) QueryByTimeRange(from, to string) ([]models.Detection, error) {
	rows, err := s.db.Query(`SELECT title, severity, evidence, mitre_id, timestamp FROM detections WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC`,
		from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to query detections: %v", err)
	}
	defer rows.Close()

	var detections []models.Detection

	for rows.Next() {
		var d models.Detection
		if err := rows.Scan(&d.Title, &d.Severity, &d.Evidence, &d.MitreID, &d.Timestamp); err != nil {
			return nil, err
		}
		detections = append(detections, d)
	}
	return detections, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) GetSettings(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}
func (s *Store) SaveSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	return err
}

func (s *Store) GetRecentDetections(limit int) ([]models.Detection, error) {
	rows, err := s.db.Query(
		`SELECT title, severity, evidence, mitre_id, timestamp FROM detections ORDER BY timestamp DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var detections []models.Detection
	for rows.Next() {
		var d models.Detection
		if err := rows.Scan(&d.Title, &d.Severity, &d.Evidence, &d.MitreID, &d.Timestamp); err != nil {
			return nil, err
		}
		detections = append(detections, d)
	}
	return detections, nil
}
