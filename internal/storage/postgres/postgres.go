package postgres

import (
	"context"
	"errors"
	"fmt"
	"kaspersky_task/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotThreat = errors.New("no threat in bd")
	ErrUnique    = errors.New("unique error")
	ErrCheck     = errors.New("check error")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{
		db: pool,
	}
}

func (repo *Repository) Read(ctx context.Context, md5 string) (domain.Threat, error) {
	query := `SELECT md5, name, description, threat_type, severity, created_at, updated_at FROM threats WHERE md5 = $1`

	var threat domain.Threat
	err := repo.db.QueryRow(ctx, query, md5).Scan(&threat.MD5, &threat.Name, &threat.Description, &threat.ThreatType, &threat.Severity, &threat.CreatedAt, &threat.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, fmt.Errorf("read error: %w", ErrNotThreat)
	}

	if err != nil {
		return domain.Threat{}, fmt.Errorf("read error: %w", err)
	}

	return threat, nil
}

func (repo *Repository) Create(ctx context.Context, md5 string, name string, description string, threatType string, severity string) (domain.Threat, error) {
	query := `INSERT INTO threats (md5, name, description, threat_type, severity) VALUES ($1, $2, $3, $4, $5) RETURNING md5, name, description, threat_type, severity, created_at, updated_at`

	var threat domain.Threat
	err := repo.db.QueryRow(ctx, query, md5, name, description, threatType, severity).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.ThreatType,
		&threat.Severity,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return domain.Threat{}, fmt.Errorf("create error: %w", ErrUnique)
			}

			if pgErr.Code == "23514" {
				return domain.Threat{}, fmt.Errorf("create error: %w", ErrCheck)
			}
		}

		return domain.Threat{}, fmt.Errorf("create error: %w", err)
	}

	return threat, nil
}

func (repo *Repository) Update(ctx context.Context, md5 string, name string, description string, threatType string, severity string) (domain.Threat, error) {
	query := `UPDATE threats SET name = $1, description = $2, threat_type = $3, severity = $4, updated_at = NOW() WHERE md5 = $5 RETURNING md5, name, description, threat_type, severity, created_at, updated_at`

	var threat domain.Threat
	err := repo.db.QueryRow(ctx, query, name, description, threatType, severity, md5).Scan(&threat.MD5, &threat.Name, &threat.Description, &threat.ThreatType, &threat.Severity, &threat.CreatedAt, &threat.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, fmt.Errorf("update error: %w", ErrNotThreat)
	}

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" {
			return domain.Threat{}, fmt.Errorf("update error: %w", ErrCheck)
		}
		return domain.Threat{}, fmt.Errorf("update error: %w", err)
	}

	return threat, nil
}
