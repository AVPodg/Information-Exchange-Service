package service

import (
	"context"
	"errors"
	"fmt"
	"kaspersky_task/internal/domain"
	"kaspersky_task/internal/storage/postgres"
	"regexp"
	"strings"
)

var (
	ErrInvalidMD5     = errors.New("invalid md5")
	ErrNotFoundThreat = errors.New("not found threat")
	ErrInvalidRequest = errors.New("invalid options")

	ErrUniqueMD5     = errors.New("not unique md5")
	ErrCheckSeverity = errors.New("bad value severity")
)

type Storage interface {
	Read(context.Context, string) (domain.Threat, error)
	Create(context.Context, string, string, string, string, string) (domain.Threat, error)
	Update(context.Context, string, string, string, string, string) (domain.Threat, error)
}

type Service struct {
	repo Storage
}

func NewService(repo Storage) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) ReadThrear(ctx context.Context, md5 string) (domain.Threat, error) {
	md5 = strings.ToLower(md5)

	matched, err := regexp.MatchString("^[a-fA-F0-9]{32}$", md5)
	if err != nil {
		return domain.Threat{}, err
	}

	if !matched {
		return domain.Threat{}, fmt.Errorf("read threat error: %w", ErrInvalidMD5)
	}

	threat, err := s.repo.Read(ctx, md5)
	if errors.Is(err, postgres.ErrNotThreat) {
		return domain.Threat{}, fmt.Errorf("read threat error: %w", ErrNotFoundThreat)
	}

	if err != nil {
		return domain.Threat{}, fmt.Errorf("read threat error: %w", err)
	}

	return threat, nil
}

func (s *Service) CreateThreat(ctx context.Context, md5 string, name string, description string, threatType string, severity string) (domain.Threat, error) {
	md5 = strings.ToLower(md5)
	name = strings.TrimSpace(name)

	matched, err := regexp.MatchString("^[a-fA-F0-9]{32}$", md5)
	if err != nil {
		return domain.Threat{}, err
	}

	if !matched {
		return domain.Threat{}, fmt.Errorf("read threat error: %w", ErrInvalidRequest)
	}

	if name == "" {
		return domain.Threat{}, fmt.Errorf("create threat error: %w", ErrInvalidRequest)
	}

	switch severity {
	case "", "low", "medium", "high", "critical":
	default:
		return domain.Threat{}, fmt.Errorf("create threat error: %w", ErrInvalidRequest)
	}

	threat, err := s.repo.Create(ctx, md5, name, description, threatType, severity)
	if errors.Is(err, postgres.ErrUnique) {
		return domain.Threat{}, fmt.Errorf("create threat error: %w", ErrUniqueMD5)
	}

	if errors.Is(err, postgres.ErrCheck) {
		return domain.Threat{}, fmt.Errorf("create threat error: %w", ErrCheckSeverity)
	}

	if err != nil {
		return domain.Threat{}, err
	}

	return threat, nil
}

func (s *Service) UpdateThreat(ctx context.Context, md5 string, name string, description string, threatType string, severity string) (domain.Threat, error) {
	md5 = strings.ToLower(md5)
	name = strings.TrimSpace(name)

	matched, err := regexp.MatchString("^[a-fA-F0-9]{32}$", md5)
	if err != nil {
		return domain.Threat{}, err
	}

	if !matched {
		return domain.Threat{}, fmt.Errorf("update threat error: %w", ErrInvalidRequest)
	}

	if name == "" {
		return domain.Threat{}, fmt.Errorf("update threat error: %w", ErrInvalidRequest)
	}

	switch severity {
	case "", "low", "medium", "high", "critical":
	default:
		return domain.Threat{}, fmt.Errorf("update threat error: %w", ErrInvalidRequest)
	}

	threat, err := s.repo.Update(ctx, md5, name, description, threatType, severity)
	if errors.Is(err, postgres.ErrNotThreat) {
		return domain.Threat{}, fmt.Errorf("update threat error: %w", ErrNotFoundThreat)
	}

	if errors.Is(err, postgres.ErrCheck) {
		return domain.Threat{}, fmt.Errorf("update threat error: %w", ErrCheckSeverity)
	}

	if err != nil {
		return domain.Threat{}, fmt.Errorf("update threat error: %w", err)
	}

	return threat, nil
}
