package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type UserHandler struct {
	userService  *service.UserService
	authzService *service.AuthorizationService
}

func NewUserHandler(
	userService *service.UserService,
	authzService *service.AuthorizationService,
) *UserHandler {
	return &UserHandler{
		userService:  userService,
		authzService: authzService,
	}
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func isValidEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	domain := parts[1]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	return true
}

func (h *UserHandler) CreateUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req createUserRequest

	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	email := strings.TrimSpace(req.Email)
	if !isValidEmail(email) {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"A valid email address is required.",
		)
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 128 {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Password must be between 8 and 128 characters.",
		)
		return
	}

	user, err := h.userService.CreateUser(
		r.Context(),
		service.CreateUserInput{
			Email:    email,
			Password: req.Password,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserAlreadyExists):
			httpx.WriteProblem(
				w,
				http.StatusConflict,
				"User Already Exists",
				"A user with this email already exists.",
			)

		default:
			httpx.WriteProblem(
				w,
				http.StatusInternalServerError,
				"Internal Server Error",
				"An unexpected error occurred.",
			)
		}

		return
	}

	response := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        user.ID.String(),
		Email:     user.Email,
		Status:    user.Status,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/v1/users/"+user.ID.String())
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) GetUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		httpx.WriteProblem(
			w,
			http.StatusUnauthorized,
			"Unauthorized",
			"Authentication is required.",
		)
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"User ID must be a valid UUID.",
		)
		return
	}

	// Authorize using the shared authorization engine:
	// Self-profile access is handled via resource ownership (ResourceID == principal.UserID).
	// Reading other profiles requires platform.user.read.
	authReq := authorization.AuthorizationRequest{
		Principal:    principal,
		Permission:   authorization.PermPlatformUserRead,
		ResourceType: "user",
		ResourceID:   userID.String(),
	}

	decision, err := h.authzService.Authorize(r.Context(), authReq)
	if err != nil {
		if errors.Is(err, authorization.ErrPolicyUnavailable) || errors.Is(err, authorization.ErrPolicyStale) {
			httpx.WriteProblem(
				w,
				http.StatusServiceUnavailable,
				"Service Unavailable",
				"Authorization policy is temporarily unavailable.",
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

	if !decision.Allowed {
		if decision.Reason == authorization.ReasonUnauthenticated {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authentication is required.",
			)
			return
		}

		httpx.WriteProblem(
			w,
			http.StatusForbidden,
			"Forbidden",
			"You are not authorized to access this resource.",
		)
		return
	}

	user, err := h.userService.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteProblem(
				w,
				http.StatusNotFound,
				"User Not Found",
				"The requested user was not found.",
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

	response := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        user.ID.String(),
		Email:     user.Email,
		Status:    user.Status,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "User ID must be a valid UUID.")
		return
	}

	if err := h.userService.SetUserStatus(r.Context(), userID, "deactivated"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "User Not Found", "The requested user was not found.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "User ID must be a valid UUID.")
		return
	}

	if err := h.userService.SetUserStatus(r.Context(), userID, "active"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "User Not Found", "The requested user was not found.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
