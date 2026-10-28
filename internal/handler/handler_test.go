package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRejectInvalidJSON(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, body := range []string{
			`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan","severity":null}`,
			`{"name":"Trojan","description":null}`,
			`{"name":"Trojan"} {}`,
		} {
			t.Run(method+"/"+body, func(t *testing.T) {
				// A nil service also ensures invalid input never reaches business logic.
				h := NewHandler(nil, time.Second)
				r := httptest.NewRequest(method, "/info", strings.NewReader(body))
				w := httptest.NewRecorder()
				if method == http.MethodPost {
					h.PostThreatApi(w, r)
				} else {
					h.UpdateThreatApi(w, r)
				}
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", w.Code)
				}
				var response ErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.Message == "" {
					t.Fatal("empty error message")
				}
			})
		}
	}
}
