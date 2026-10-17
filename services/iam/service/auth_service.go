package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

type LoginInput struct {
	Email    string
	Password string
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
}

type AuthService struct {
	userRepo        repository.UserRepository
	sessionRepo     repository.SessionRepository
	jwtManager      *auth.JWTManager
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	jwtManager *auth.JWTManager,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) (*AuthService, error) {
	if userRepo == nil || sessionRepo == nil || jwtManager == nil {
		return nil, fmt.Errorf("auth service dependencies are required")
	}
	if accessTokenTTL <= 0 || refreshTokenTTL <= 0 {
		return nil, fmt.Errorf("token lifetimes must be positive")
	}

	return &AuthService{
		userRepo:        userRepo,
		sessionRepo:     sessionRepo,
		jwtManager:      jwtManager,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	input LoginInput,
) (*TokenPair, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))

	user, err := s.userRepo.GetByEmail(ctx, email)
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

	sessionID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now()
	session := &model.Session{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: now.Add(s.refreshTokenTTL),
	}

	// Sign before persisting so a signing failure doesn't leave
	// an unusable session behind.
	accessToken, err := s.createAccessToken(user.ID, session.ID)
	if err != nil {
		return nil, err
	}

	if err := s.sessionRepo.Create(
		ctx,
		session,
		hashRefreshToken(refreshToken),
	); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	oldHash := hashRefreshToken(refreshToken)

	session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, oldHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("get session user: %w", err)
	}

	if user.Status != "active" {
		_ = s.sessionRepo.RevokeByRefreshTokenHash(ctx, oldHash)
		return nil, ErrInvalidRefreshToken
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// Sign before rotating: if signing fails, the old refresh token
	// remains usable.
	accessToken, err := s.createAccessToken(user.ID, session.ID)
	if err != nil {
		return nil, err
	}

	_, err = s.sessionRepo.RotateRefreshToken(
		ctx,
		oldHash,
		hashRefreshToken(newRefreshToken),
	)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Another request may have rotated it first.
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	refreshToken string,
) error {
	if refreshToken == "" {
		return ErrInvalidRefreshToken
	}

	err := s.sessionRepo.RevokeByRefreshTokenHash(
		ctx,
		hashRefreshToken(refreshToken),
	)
	if errors.Is(err, repository.ErrNotFound) {
		// Logout is idempotent: an already-revoked or unknown
		// credential doesn't need a second state change.
		return nil
	}
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (s *AuthService) createAccessToken(
	userID uuid.UUID,
	sessionID uuid.UUID,
) (string, error) {
	token, err := s.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    userID,
		SessionID: sessionID,
	})
	if err != nil {
		return "", fmt.Errorf("create access token: %w", err)
	}
	return token, nil
}

func generateRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
