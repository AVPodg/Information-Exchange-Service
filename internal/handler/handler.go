package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kaspersky_task/internal/domain"
	"kaspersky_task/internal/service"
	"log/slog"
	"net/http"
	"time"
)

const (
	statusClientCloseRequest = 499
)

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

type Service interface {
	ReadThrear(context.Context, string) (domain.Threat, error)
	CreateThreat(context.Context, string, string, string, string, string) (domain.Threat, error)
	UpdateThreat(context.Context, string, string, string, string, string) (domain.Threat, error)
}

type Handler struct {
	s       Service
	timeout time.Duration
}

func NewHandler(service Service, timeout time.Duration) *Handler {
	return &Handler{
		s:       service,
		timeout: timeout,
	}
}

type ThreatCreateRequest struct {
	MD5         requestString `json:"md5"`
	Name        requestString `json:"name"`
	Description requestString `json:"description"`
	ThreatType  requestString `json:"threat_type"`
	Severity    requestString `json:"severity"`
}

type ThreatUpdateRequest struct {
	Name        requestString `json:"name"`
	Description requestString `json:"description"`
	ThreatType  requestString `json:"threat_type"`
	Severity    requestString `json:"severity"`
}

func (h *Handler) GetInfoByMD5(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	threat, err := h.s.ReadThrear(ctx, md5)
	if errors.Is(err, context.DeadlineExceeded) {
		jsonError(w, http.StatusGatewayTimeout, ErrorResponse{
			Message: "request timeout",
			Details: "timeout 2s finished",
		})
		return
	}

	if errors.Is(err, context.Canceled) {
		jsonError(w, statusClientCloseRequest, ErrorResponse{
			Message: "client close request",
			Details: "cancel context",
		})
		return
	}

	if errors.Is(err, service.ErrInvalidMD5) {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "Invalid MD5",
			Details: "MD5 not matched '^[a-fA-F0-9]{32}$'",
		})
		return
	}

	if errors.Is(err, service.ErrNotFoundThreat) {
		jsonError(w, http.StatusNotFound, ErrorResponse{
			Message: "Threat not found",
			Details: fmt.Sprintf("No threat with MD5 %s found", md5),
		})
		return
	}

	if err != nil {
		slog.Error("get threat failed",
			"md5", md5,
			"error", err,
		)

		jsonError(w, http.StatusInternalServerError, ErrorResponse{
			Message: "server invalid error",
			Details: "Anouther error get request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(threat)
}

func (h *Handler) PostThreatApi(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var threatReq ThreatCreateRequest
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&threatReq); err != nil {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad json",
			Details: "Request body must contain a valid JSON object",
		})
		return
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad json",
			Details: "Request body must contain exactly one JSON object",
		})
		return
	}

	threat, err := h.s.CreateThreat(ctx, string(threatReq.MD5), string(threatReq.Name), string(threatReq.Description), string(threatReq.ThreatType), string(threatReq.Severity))
	if errors.Is(err, context.DeadlineExceeded) {
		jsonError(w, http.StatusGatewayTimeout, ErrorResponse{
			Message: "request timeout",
			Details: "timeout 2s finished",
		})
		return
	}

	if errors.Is(err, context.Canceled) {
		jsonError(w, statusClientCloseRequest, ErrorResponse{
			Message: "client close request",
			Details: "cancel context",
		})
		return
	}

	if errors.Is(err, service.ErrInvalidRequest) {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "invalid options",
			Details: "invalid options",
		})
		return
	}

	if errors.Is(err, service.ErrUniqueMD5) {
		jsonError(w, http.StatusConflict, ErrorResponse{
			Message: "md5 in db",
			Details: fmt.Sprintf("md5 %s not unique", threatReq.MD5),
		})
		return
	}

	if errors.Is(err, service.ErrCheckSeverity) {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad severity",
			Details: fmt.Sprintf("severity %s not in ('low', 'high', '')", threatReq.Severity),
		})
		return
	}

	if err != nil {
		slog.Error("post threat failed",
			"md5", threatReq.MD5,
			"error", err,
		)

		jsonError(w, http.StatusInternalServerError, ErrorResponse{
			Message: "server invalid error",
			Details: "Anouther error post request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(threat)
}

func (h *Handler) UpdateThreatApi(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var threatReq ThreatUpdateRequest
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&threatReq); err != nil {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad json",
			Details: "Request body must contain a valid JSON object",
		})
		return
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad json",
			Details: "Request body must contain exactly one JSON object",
		})
		return
	}

	threat, err := h.s.UpdateThreat(ctx, md5, string(threatReq.Name), string(threatReq.Description), string(threatReq.ThreatType), string(threatReq.Severity))
	if errors.Is(err, context.DeadlineExceeded) {
		jsonError(w, http.StatusGatewayTimeout, ErrorResponse{
			Message: "request timeout",
			Details: "timeout 2s finished",
		})
		return
	}

	if errors.Is(err, context.Canceled) {
		jsonError(w, statusClientCloseRequest, ErrorResponse{
			Message: "client close request",
			Details: "cancel context",
		})
		return
	}

	if errors.Is(err, service.ErrInvalidRequest) {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "invalid options",
			Details: "invalid options",
		})
		return
	}

	if errors.Is(err, service.ErrNotFoundThreat) {
		jsonError(w, http.StatusNotFound, ErrorResponse{
			Message: "Threat not found",
			Details: fmt.Sprintf("No threat with MD5 %s found", md5),
		})
		return
	}

	if errors.Is(err, service.ErrCheckSeverity) {
		jsonError(w, http.StatusBadRequest, ErrorResponse{
			Message: "bad severity",
			Details: fmt.Sprintf(
				"severity %q must be one of: low, medium, high, critical",
				threatReq.Severity,
			),
		})
		return
	}

	if err != nil {
		slog.Error("update threat failed",
			"md5", md5,
			"error", err,
		)

		jsonError(w, http.StatusInternalServerError, ErrorResponse{
			Message: "server invalid error",
			Details: "Anouther error post request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(threat)
}

func jsonError(w http.ResponseWriter, status int, err ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(err)
}
