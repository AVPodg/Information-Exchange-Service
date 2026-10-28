package service

import (
	"context"
	"errors"
	"kaspersky_task/internal/domain"
	"kaspersky_task/internal/storage/postgres"
	"testing"
)

type storageStub struct {
	threat domain.Threat
	err    error
	calls  int
}

func (s *storageStub) Read(_ context.Context, md5 string) (domain.Threat, error) {
	s.calls++
	s.threat.MD5 = md5
	return s.threat, s.err
}

func (s *storageStub) Create(_ context.Context, md5, name, description, kind, severity string) (domain.Threat, error) {
	s.calls++
	s.threat = domain.Threat{MD5: md5, Name: name, Description: description, ThreatType: kind, Severity: severity}
	return s.threat, s.err
}

func (s *storageStub) Update(ctx context.Context, md5, name, description, kind, severity string) (domain.Threat, error) {
	return s.Create(ctx, md5, name, description, kind, severity)
}

func TestValidation(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	for _, tc := range []struct {
		name string
		call func(*Service) error
		want error
	}{
		{"invalid read MD5", func(s *Service) error { _, err := s.ReadThrear(context.Background(), "bad"); return err }, ErrInvalidMD5},
		{"invalid create MD5", func(s *Service) error {
			_, err := s.CreateThreat(context.Background(), "bad", "Trojan", "", "", "")
			return err
		}, ErrInvalidRequest},
		{"blank name", func(s *Service) error {
			_, err := s.CreateThreat(context.Background(), md5, " \t", "", "", "")
			return err
		}, ErrInvalidRequest},
		{"invalid update severity", func(s *Service) error {
			_, err := s.UpdateThreat(context.Background(), md5, "Trojan", "", "", "extreme")
			return err
		}, ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &storageStub{}
			if err := tc.call(NewService(repo)); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if repo.calls != 0 {
				t.Fatal("invalid input reached storage")
			}
		})
	}
}

func TestNormalizationAndOptionalSeverity(t *testing.T) {
	repo := &storageStub{}
	s := NewService(repo)
	threat, err := s.CreateThreat(context.Background(), "D41D8CD98F00B204E9800998ECF8427E", "  Trojan  ", "description", "trojan", "")
	if err != nil {
		t.Fatal(err)
	}
	if threat.MD5 != "d41d8cd98f00b204e9800998ecf8427e" || threat.Name != "Trojan" || threat.Severity != "" || threat.Description != "description" || threat.ThreatType != "trojan" {
		t.Fatalf("unexpected threat: %+v", threat)
	}
}

func TestStorageErrors(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	for _, tc := range []struct {
		name string
		err  error
		call func(*Service) error
		want error
	}{
		{"read missing", postgres.ErrNotThreat, func(s *Service) error { _, err := s.ReadThrear(context.Background(), md5); return err }, ErrNotFoundThreat},
		{"update missing", postgres.ErrNotThreat, func(s *Service) error {
			_, err := s.UpdateThreat(context.Background(), md5, "Trojan", "", "", "")
			return err
		}, ErrNotFoundThreat},
		{"duplicate", postgres.ErrUnique, func(s *Service) error {
			_, err := s.CreateThreat(context.Background(), md5, "Trojan", "", "", "")
			return err
		}, ErrUniqueMD5},
		{"timeout", context.DeadlineExceeded, func(s *Service) error { _, err := s.ReadThrear(context.Background(), md5); return err }, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(NewService(&storageStub{err: tc.err})); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}
