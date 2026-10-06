package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var ErrUserAlreadyExists = errors.New("user already exists")

type UserService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{
		repo: repo,
	}
}

func (s *UserService) GetUserByID(
	ctx context.Context,
	id uuid.UUID,
) (*model.User, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *UserService) GetUserByEmail(
	ctx context.Context,
	email string,
) (*model.User, error) {
	return s.repo.GetByEmail(ctx, email)
}

func (s *UserService) CreateUser(
	ctx context.Context,
	user *model.User,
) error {
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))

	existing, err := s.repo.GetByEmail(ctx, user.Email)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("check existing user: %w", err)
		}
	} else if existing != nil {
		return ErrUserAlreadyExists
	}

	return s.repo.Create(ctx, user)
}
