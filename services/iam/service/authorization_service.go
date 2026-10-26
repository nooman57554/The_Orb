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

// Authorize performs a single generic authorization evaluation for the verified principal.
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
		allowed, err := s.authzRepo.HasTenantPermission(ctx, principal.UserID, req.TenantID, req.Action)
		if err != nil {
			return fmt.Errorf("check tenant permission: %w", err)
		}
		if !allowed {
			return ErrForbidden
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

	// Platform-scoped authorization
	// Special-case: Self-lookup for user profile read
	if req.ResourceType == "user" && req.Action == "user.read" && req.ResourceID != "" {
		targetUserID, err := uuid.Parse(req.ResourceID)
		if err == nil && principal.UserID == targetUserID {
			return nil
		}
	}

	allowed, err := s.authzRepo.HasPlatformPermission(ctx, principal.UserID, req.Action)
	if err != nil {
		return fmt.Errorf("check platform permission: %w", err)
	}
	if !allowed {
		return ErrForbidden
	}

	return nil
}

// AuthorizePlatform evaluates whether the principal holds a platform-scoped permission.
func (s *AuthorizationService) AuthorizePlatform(
	ctx context.Context,
	principal *identity.Principal,
	permission string,
) error {
	return s.Authorize(ctx, principal, AuthorizationRequest{
		Action: permission,
	})
}

// AuthorizeTenant evaluates whether the principal holds a tenant-scoped permission.
func (s *AuthorizationService) AuthorizeTenant(
	ctx context.Context,
	principal *identity.Principal,
	tenantID uuid.UUID,
	permission string,
) error {
	return s.Authorize(ctx, principal, AuthorizationRequest{
		Action:   permission,
		TenantID: tenantID,
	})
}

// AuthorizeUserRead authorizes access to a user profile.
func (s *AuthorizationService) AuthorizeUserRead(
	ctx context.Context,
	principal *identity.Principal,
	targetUserID uuid.UUID,
) error {
	return s.Authorize(ctx, principal, AuthorizationRequest{
		Action:       "user.read",
		ResourceType: "user",
		ResourceID:   targetUserID.String(),
	})
}
