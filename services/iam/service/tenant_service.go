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

var (
	ErrInvalidTenantName = errors.New("invalid tenant name: cannot be empty")
	ErrInvalidTenantSlug = errors.New("invalid tenant slug: cannot be empty")
	ErrTenantNotFound    = errors.New("tenant not found")
)

type TenantService struct {
	tenantRepo repository.TenantRepository
}

func NewTenantService(tenantRepo repository.TenantRepository) (*TenantService, error) {
	if tenantRepo == nil {
		return nil, fmt.Errorf("tenant repository is required")
	}
	return &TenantService{tenantRepo: tenantRepo}, nil
}

func (s *TenantService) CreateTenant(
	ctx context.Context,
	name, slug string,
) (*model.Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidTenantName
	}
	slug = strings.TrimSpace(strings.ToLower(slug))
	if slug == "" {
		return nil, ErrInvalidTenantSlug
	}

	tenant := &model.Tenant{
		Name:   name,
		Slug:   slug,
		Status: "active",
	}

	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

func (s *TenantService) GetTenantByID(
	ctx context.Context,
	id uuid.UUID,
) (*model.Tenant, error) {
	if id == uuid.Nil {
		return nil, ErrTenantNotFound
	}

	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("get tenant: %w", err)
	}

	return tenant, nil
}

func (s *TenantService) ListTenants(
	ctx context.Context,
	offset, limit int,
) ([]model.Tenant, int, error) {
	return s.tenantRepo.List(ctx, offset, limit)
}

func (s *TenantService) UpdateTenant(
	ctx context.Context,
	id uuid.UUID,
	name string,
) (*model.Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidTenantName
	}

	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return nil, err
	}

	tenant.Name = name
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return nil, fmt.Errorf("update tenant: %w", err)
	}

	return tenant, nil
}

func (s *TenantService) DeactivateTenant(
	ctx context.Context,
	id uuid.UUID,
) error {
	if id == uuid.Nil {
		return ErrTenantNotFound
	}
	err := s.tenantRepo.SetStatus(ctx, id, "deactivated")
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	return nil
}

func (s *TenantService) ReactivateTenant(
	ctx context.Context,
	id uuid.UUID,
) error {
	if id == uuid.Nil {
		return ErrTenantNotFound
	}
	err := s.tenantRepo.SetStatus(ctx, id, "active")
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("reactivate tenant: %w", err)
	}
	return nil
}
