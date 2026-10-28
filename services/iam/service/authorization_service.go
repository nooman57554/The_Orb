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

type AuthorizationRequest struct {
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
}

type AuthorizationService struct {
	authzRepo repository.AuthorizationRepository
}

func NewAuthorizationService(authzRepo repository.AuthorizationRepository) (*AuthorizationService, error) {
	if authzRepo == nil {
		return nil, fmt.Errorf("authorization repository is required")
	}
	return &AuthorizationService{authzRepo: authzRepo}, nil
}

// AuthorizePlatform evaluates whether the principal holds a platform-scoped permission.
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

// AuthorizeTenant evaluates whether the principal holds a tenant-scoped permission.
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
// A user may always read their own profile if their status is active. Reading other users requires platform permission "user.read".
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
		active, err := s.authzRepo.IsUserActive(ctx, principal.UserID)
		if err != nil {
			return fmt.Errorf("check user active: %w", err)
		}
		if !active {
			return ErrForbidden
		}
		return nil
	}
	return s.AuthorizePlatform(ctx, principal, "user.read")
}

// Authorize evaluates a generic authorization request for the caller's verified principal.
func (s *AuthorizationService) Authorize(
	ctx context.Context,
	principal *identity.Principal,
	req AuthorizationRequest,
) error {
	if principal == nil || !principal.IsValid() {
		return ErrUnauthorized
	}
	if req.Action == "" {
		return ErrForbidden
	}

	// Tenant-scoped authorization
	if req.TenantID != uuid.Nil {
		if err := s.AuthorizeTenant(ctx, principal, req.TenantID, req.Action); err != nil {
			return err
		}

		// If a specific user resource within the tenant is targeted, ensure they belong to this tenant
		if (req.ResourceType == "user" || req.ResourceType == "member") && req.ResourceID != "" {
			targetUserID, err := uuid.Parse(req.ResourceID)
			if err == nil && targetUserID != uuid.Nil {
				belongs, err := s.authzRepo.UserBelongsToTenant(ctx, targetUserID, req.TenantID)
				if err != nil {
					return fmt.Errorf("verify user tenant membership: %w", err)
				}
				if !belongs {
					return ErrForbidden
				}
			}
		}

		return nil
	}

	// Platform-scoped authorization: self-lookup profile check
	if req.ResourceType == "user" && req.Action == "user.read" && req.ResourceID != "" {
		targetUserID, err := uuid.Parse(req.ResourceID)
		if err == nil {
			return s.AuthorizeUserRead(ctx, principal, targetUserID)
		}
	}

	return s.AuthorizePlatform(ctx, principal, req.Action)
}
