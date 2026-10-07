package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *UserHandler) CreateUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req createUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	if req.Email == "" {
		writeProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"email is required.",
		)
		return
	}

	if req.Password == "" {
		writeProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"password is required.",
		)
		return
	}

	user, err := h.userService.CreateUser(
		r.Context(),
		service.CreateUserInput{
			Email:    req.Email,
			Password: req.Password,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserAlreadyExists):
			writeProblem(
				w,
				http.StatusConflict,
				"User Already Exists",
				"A user with this email already exists.",
			)

		default:
			writeProblem(
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
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"User ID must be a valid UUID.",
		)
		return
	}

	user, err := h.userService.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeProblem(
				w,
				http.StatusNotFound,
				"User Not Found",
				"The requested user was not found.",
			)
			return
		}

		writeProblem(
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(response)
}
