package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type LoginInput struct {
	Email    string
	Password string
}

type AuthService struct {
	userRepo repository.UserRepository
}

func NewAuthService(
	userRepo repository.UserRepository,
) *AuthService {
	return &AuthService{
		userRepo: userRepo,
	}
}

func (s *AuthService) Login(
	ctx context.Context,
	input LoginInput,
) (*model.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if err := verifyPassword(input.Password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.Status != "active" {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
