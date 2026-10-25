package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var (
	ErrUnauthorized = errors.New("unauthorized: missing or invalid principal")
	ErrForbidden    = errors.New("forbidden: insufficient permissions")
)

type AuthorizationService struct {
	authzRepo repository.AuthorizationRepository
}

func NewAuthorizationService(authzRepo repository.AuthorizationRepository) (*AuthorizationService, error) {
	if authzRepo == nil {
		return nil, fmt.Errorf("authorization repository is required")
	}
	return &AuthorizationService{authzRepo: authzRepo}, nil
}

// AuthorizePlatform evaluates whether the principal holds a platform-scoped permission
// granted through platform_role_assignments.
func (s *AuthorizationService) AuthorizePlatform(
	ctx context.Context,
	principal *identity.Principal,
	permission string,
) error {
	if principal == nil || !principal.IsValid() {
		return ErrUnauthorized
	}
	if permission == "" {
		return ErrForbidden
	}

	allowed, err := s.authzRepo.HasPlatformPermission(ctx, principal.UserID, permission)
	if err != nil {
		return fmt.Errorf("check platform permission: %w", err)
	}
	if !allowed {
		return ErrForbidden
	}

	return nil
}

// AuthorizeTenant evaluates whether the principal holds a tenant-scoped permission
// for the specific tenant resource identified by tenantID, granted through tenant_role_assignments.
// Platform roles do not bypass tenant assignment requirements.
func (s *AuthorizationService) AuthorizeTenant(
	ctx context.Context,
	principal *identity.Principal,
	tenantID uuid.UUID,
	permission string,
) error {
	if principal == nil || !principal.IsValid() {
		return ErrUnauthorized
	}
	if tenantID == uuid.Nil || permission == "" {
		return ErrForbidden
	}

	allowed, err := s.authzRepo.HasTenantPermission(ctx, principal.UserID, tenantID, permission)
	if err != nil {
		return fmt.Errorf("check tenant permission: %w", err)
	}
	if !allowed {
		return ErrForbidden
	}

	return nil
}

// AuthorizeUserRead authorizes access to a user profile.
// Active users are authorized to read their own profile (self-lookup).
// Reading another user's profile requires the platform-scoped user.read permission.
// A tenant-scoped user.read permission does not grant platform-wide user lookup.
func (s *AuthorizationService) AuthorizeUserRead(
	ctx context.Context,
	principal *identity.Principal,
	targetUserID uuid.UUID,
) error {
	if principal == nil || !principal.IsValid() {
		return ErrUnauthorized
	}
	if targetUserID == uuid.Nil {
		return ErrForbidden
	}

	if principal.UserID == targetUserID {
		return nil
	}

	return s.AuthorizePlatform(ctx, principal, "user.read")
}
