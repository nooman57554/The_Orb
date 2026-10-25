package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	if strings.TrimSpace(req.Email) == "" || req.Password == "" {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Email and password are required.",
		)
		return
	}

	tokens, err := h.authService.Login(r.Context(), service.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Invalid Credentials",
				"Email or password is incorrect.",
			)
			return
		}

		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	if req.RefreshToken == "" {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"refresh_token is required.",
		)
		return
	}

	tokens, err := h.authService.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Invalid Refresh Token",
				"The refresh token is invalid, expired, or revoked.",
			)
			return
		}

		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	principal, hasPrincipal := identity.PrincipalFromContext(r.Context())

	var req logoutRequest
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		if err := decodeJSON(w, r, &req); err != nil {
			if !errors.Is(err, io.EOF) || !hasPrincipal {
				httpx.WriteProblem(
					w,
					http.StatusBadRequest,
					"Invalid Request",
					"Request body must contain valid JSON.",
				)
				return
			}
		}
	}

	// 1. Authenticated via Bearer token:
	if hasPrincipal && principal != nil && principal.SessionID != uuid.Nil {
		if req.SessionID != "" {
			targetUUID, err := uuid.Parse(req.SessionID)
			if err != nil {
				httpx.WriteProblem(
					w,
					http.StatusBadRequest,
					"Invalid Request",
					"Invalid session_id format.",
				)
				return
			}
			if targetUUID != principal.SessionID {
				httpx.WriteProblem(
					w,
					http.StatusForbidden,
					"Forbidden",
					"Cannot revoke another session.",
				)
				return
			}
		}

		if err := h.authService.LogoutSession(r.Context(), principal.SessionID); err != nil {
			if errors.Is(err, service.ErrInvalidRefreshToken) {
				httpx.WriteProblem(
					w,
					http.StatusUnauthorized,
					"Invalid Session",
					"The session was not found or has already expired.",
				)
				return
			}
			httpx.WriteProblem(
				w,
				http.StatusInternalServerError,
				"Internal Server Error",
				"An unexpected error occurred.",
			)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 2. Not authenticated via Bearer token:
	if req.RefreshToken == "" {
		if req.SessionID != "" {
			// Untrusted session ID supplied without authentication
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authentication required to revoke session.",
			)
			return
		}

		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"refresh_token is required.",
		)
		return
	}

	if req.SessionID != "" {
		targetUUID, err := uuid.Parse(req.SessionID)
		if err != nil {
			httpx.WriteProblem(
				w,
				http.StatusBadRequest,
				"Invalid Request",
				"Invalid session_id format.",
			)
			return
		}

		if err := h.authService.LogoutWithRefreshToken(r.Context(), req.RefreshToken, targetUUID); err != nil {
			if errors.Is(err, service.ErrForbiddenSession) {
				httpx.WriteProblem(
					w,
					http.StatusForbidden,
					"Forbidden",
					"Cannot revoke another session.",
				)
				return
			}
			if errors.Is(err, service.ErrInvalidRefreshToken) {
				httpx.WriteProblem(
					w,
					http.StatusUnauthorized,
					"Invalid Refresh Token",
					"The refresh token is invalid, expired, or revoked.",
				)
				return
			}
			httpx.WriteProblem(
				w,
				http.StatusInternalServerError,
				"Internal Server Error",
				"An unexpected error occurred.",
			)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Invalid Refresh Token",
				"The refresh token is invalid, expired, or revoked.",
			)
			return
		}
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	// Require exactly one JSON value in the request body.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON value")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}
