package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"kaspersky_task/internal/domain"
	"kaspersky_task/internal/handler"
	"kaspersky_task/internal/service"
	"kaspersky_task/internal/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestThreatAPI(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	// Every run has its own schema; existing tables and data are never cleared.
	schema := pgx.Identifier{fmt.Sprintf("test_threats_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
	})
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrations, err := filepath.Glob("../migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) == 0 {
		t.Fatal("no up migrations found")
	}
	for _, path := range migrations {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", path, err)
		}
	}

	h := handler.NewHandler(service.NewService(postgres.NewRepository(pool)), 2*time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /info", h.PostThreatApi)
	mux.HandleFunc("GET /info/{md5}", h.GetInfoByMD5)
	mux.HandleFunc("PUT /info/{md5}", h.UpdateThreatApi)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(method, path, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: status = %d, want %d; body = %s", method, path, res.StatusCode, want, data)
		}
		if res.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected Content-Type: %s", res.Header.Get("Content-Type"))
		}
		if want >= http.StatusBadRequest {
			var response handler.ErrorResponse
			if err := json.Unmarshal(data, &response); err != nil || response.Message == "" {
				t.Fatalf("invalid error response: %s", data)
			}
		}
		return data
	}
	decode := func(data []byte) domain.Threat {
		t.Helper()
		var threat domain.Threat
		if err := json.Unmarshal(data, &threat); err != nil {
			t.Fatal(err)
		}
		return threat
	}
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	const path = "/info/" + md5
	full := `{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":" Trojan ","description":"details","threat_type":"trojan","severity":"high"}`
	created := decode(request(http.MethodPost, "/info", full, http.StatusCreated))
	if created.MD5 != md5 || created.Name != "Trojan" || created.Severity != "high" || created.CreatedAt.IsZero() {
		t.Fatalf("unexpected created threat: %+v", created)
	}
	request(http.MethodPost, "/info", strings.ToLower(full), http.StatusConflict)
	read := decode(request(http.MethodGet, "/info/"+strings.ToUpper(md5), "", http.StatusOK))
	if read != created {
		t.Fatalf("read = %+v, want %+v", read, created)
	}
	updated := decode(request(http.MethodPut, path, `{"name":"Updated"}`, http.StatusOK))
	if updated.Name != "Updated" || updated.Description != "" || updated.ThreatType != "" || updated.Severity != "" || !updated.CreatedAt.Equal(created.CreatedAt) || updated.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("unexpected update: %+v", updated)
	}
	read = decode(request(http.MethodGet, path, "", http.StatusOK))
	if read != updated {
		t.Fatalf("update was not persisted: %+v", read)
	}
	request(http.MethodPost, "/info", `{"md5":"11111111111111111111111111111111","name":"Minimal"}`, http.StatusCreated)
	request(http.MethodGet, "/info/00000000000000000000000000000000", "", http.StatusNotFound)
	request(http.MethodPut, "/info/00000000000000000000000000000000", `{"name":"Missing"}`, http.StatusNotFound)
}
