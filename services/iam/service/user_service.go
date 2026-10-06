package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

const (
	argon2Memory      = 64 * 1024
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2KeyLength   = 32
	argon2SaltLength  = 16
)

var ErrUserAlreadyExists = errors.New("user already exists")

type CreateUserInput struct {
	Email    string
	Password string
}

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
	input CreateUserInput,
) (*model.User, error) {

	email := strings.ToLower(strings.TrimSpace(input.Email))

	existing, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("check existing user: %w", err)
		}
	} else if existing != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := hashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &model.User{
		ID:           uuid.Nil,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       "active",
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	return user, nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)

	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}
