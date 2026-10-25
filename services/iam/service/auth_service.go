package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
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
	ErrSessionNotFound     = errors.New("session not found")
)

const dummyArgon2idHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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

const defaultReuseGracePeriod = 15 * time.Second

type AuthService struct {
	userRepo         repository.UserRepository
	sessionRepo      repository.SessionRepository
	jwtManager       *auth.JWTManager
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	reuseGracePeriod time.Duration
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	jwtManager *auth.JWTManager,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	reuseGracePeriod time.Duration,
) (*AuthService, error) {
	if userRepo == nil || sessionRepo == nil || jwtManager == nil {
		return nil, fmt.Errorf("auth service dependencies are required")
	}
	if accessTokenTTL <= 0 || refreshTokenTTL <= 0 {
		return nil, fmt.Errorf("token lifetimes must be positive")
	}
	if reuseGracePeriod <= 0 {
		return nil, fmt.Errorf("reuse grace period must be positive")
	}

	return &AuthService{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		jwtManager:       jwtManager,
		accessTokenTTL:   accessTokenTTL,
		refreshTokenTTL:  refreshTokenTTL,
		reuseGracePeriod: reuseGracePeriod,
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
			_ = verifyPassword(input.Password, dummyArgon2idHash)
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
		if !errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("get session by refresh token hash: %w", err)
		}

		// Token hash not found as a current active token.
		// Check whether this token was previously rotated (reuse detection).
		reuseSession, reuseErr := s.sessionRepo.GetByPreviousTokenHash(ctx, oldHash)
		if reuseErr != nil {
			if errors.Is(reuseErr, repository.ErrNotFound) {
				return nil, ErrInvalidRefreshToken
			}
			return nil, fmt.Errorf("check token reuse: %w", reuseErr)
		}

		// Found as a previous token. Check if within grace period (concurrent race / network retry).
		if reuseSession.RotatedAt != nil && s.reuseGracePeriod > 0 && time.Since(*reuseSession.RotatedAt) <= s.reuseGracePeriod {
			return nil, ErrInvalidRefreshToken
		}

		// Replay attack / reuse outside grace window: revoke the compromised session.
		if revokeErr := s.sessionRepo.Revoke(ctx, reuseSession.ID); revokeErr != nil {
			return nil, fmt.Errorf("revoke session on token reuse: %w", revokeErr)
		}
		log.Printf("SECURITY: refresh token reuse detected for session %s; session revoked", reuseSession.ID)

		return nil, ErrInvalidRefreshToken
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
			// Another request rotated it first during this in-flight call.
			// Verify if it is in previous_token_hash and check grace period.
			reuseSession, reuseErr := s.sessionRepo.GetByPreviousTokenHash(ctx, oldHash)
			if reuseErr != nil {
				if errors.Is(reuseErr, repository.ErrNotFound) {
					return nil, ErrInvalidRefreshToken
				}
				return nil, fmt.Errorf("check token reuse after concurrent rotation: %w", reuseErr)
			}

			if reuseSession.RotatedAt != nil && s.reuseGracePeriod > 0 && time.Since(*reuseSession.RotatedAt) <= s.reuseGracePeriod {
				return nil, ErrInvalidRefreshToken
			}
			if revokeErr := s.sessionRepo.Revoke(ctx, reuseSession.ID); revokeErr != nil {
				return nil, fmt.Errorf("revoke session on token reuse: %w", revokeErr)
			}
			log.Printf("SECURITY: refresh token reuse detected for session %s; session revoked", reuseSession.ID)
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

func (s *AuthService) LogoutSession(
	ctx context.Context,
	sessionID uuid.UUID,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	err := s.sessionRepo.Revoke(ctx, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("revoke session by ID: %w", err)
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
