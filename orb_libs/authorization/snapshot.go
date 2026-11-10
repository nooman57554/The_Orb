package authorization

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrOlderSnapshotVersion = errors.New("cannot apply older or equal snapshot version")
)

// RoleScope defines the scope category of a role in the IAM model.
type RoleScope string

const (
	RoleScopePlatform     RoleScope = "platform"
	RoleScopeSystemTenant RoleScope = "system_tenant"
	RoleScopeCustomTenant RoleScope = "custom_tenant"
)

// UserPolicy contains authorization-relevant state for a user.
type UserPolicy struct {
	Active bool `json:"active"`
}

// RolePolicy contains the normalized representation of a role.
type RolePolicy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Scope       RoleScope `json:"scope"`
	TenantID    *string   `json:"tenant_id,omitempty"`
	Permissions []string  `json:"permissions"`
}

// PermissionDefinition defines the normalized catalog definition of a permission.
type PermissionDefinition struct {
	Name  string `json:"name"`
	Scope Scope  `json:"scope"`
}

// PolicySnapshot represents a consistent, immutable point-in-time snapshot of the entire authorization policy.
type PolicySnapshot struct {
	Version             int64                           `json:"version"`
	CreatedAt           time.Time                       `json:"created_at"`
	Users               map[string]UserPolicy           `json:"users"`
	PlatformAssignments map[string]string               `json:"platform_assignments"` // UserID -> RoleID
	TenantAssignments   map[string]map[string]string    `json:"tenant_assignments"`   // UserID -> TenantID -> RoleID
	Roles               map[string]RolePolicy           `json:"roles"`                // RoleID -> RolePolicy
	Permissions         map[string]PermissionDefinition `json:"permissions"`          // PermissionName -> PermissionDefinition
}

// Validate checks the structural and invariant integrity of a snapshot.
func (s *PolicySnapshot) Validate() error {
	if s == nil {
		return fmt.Errorf("%w: snapshot is nil", ErrInvalidSnapshot)
	}
	if s.Version <= 0 {
		return fmt.Errorf("%w: version must be greater than 0, got %d", ErrInvalidSnapshot, s.Version)
	}
	if s.CreatedAt.IsZero() {
		return fmt.Errorf("%w: creation timestamp cannot be zero", ErrInvalidSnapshot)
	}

	// Validate permissions catalog
	for name, perm := range s.Permissions {
		if perm.Scope != ScopePlatform && perm.Scope != ScopeTenant {
			return fmt.Errorf("%w: permission %q has invalid scope %q", ErrInvalidSnapshot, name, perm.Scope)
		}
	}

	// Validate role-permission invariant compatibility in snapshot
	for roleID, role := range s.Roles {
		switch role.Scope {
		case RoleScopePlatform:
			if role.TenantID != nil && *role.TenantID != "" {
				return fmt.Errorf("%w: platform role %q cannot have tenant ID", ErrInvalidSnapshot, roleID)
			}
			for _, permName := range role.Permissions {
				permDef, exists := s.Permissions[permName]
				if exists && permDef.Scope != ScopePlatform {
					return fmt.Errorf("%w: platform role %q assigned non-platform permission %q", ErrInvalidSnapshot, roleID, permName)
				}
			}
		case RoleScopeSystemTenant:
			if role.TenantID != nil && *role.TenantID != "" {
				return fmt.Errorf("%w: system tenant role %q cannot have specific tenant ID", ErrInvalidSnapshot, roleID)
			}
			for _, permName := range role.Permissions {
				permDef, exists := s.Permissions[permName]
				if exists && permDef.Scope != ScopeTenant {
					return fmt.Errorf("%w: system tenant role %q assigned non-tenant permission %q", ErrInvalidSnapshot, roleID, permName)
				}
			}
		case RoleScopeCustomTenant:
			if role.TenantID == nil || *role.TenantID == "" {
				return fmt.Errorf("%w: custom tenant role %q must have owning tenant ID", ErrInvalidSnapshot, roleID)
			}
			for _, permName := range role.Permissions {
				permDef, exists := s.Permissions[permName]
				if exists && permDef.Scope != ScopeTenant {
					return fmt.Errorf("%w: custom tenant role %q assigned non-tenant permission %q", ErrInvalidSnapshot, roleID, permName)
				}
			}
		default:
			return fmt.Errorf("%w: role %q has unknown scope %q", ErrInvalidSnapshot, roleID, role.Scope)
		}
	}

	return nil
}

// SnapshotHolder provides thread-safe access and atomic monotonic updates for a PolicySnapshot.
type SnapshotHolder struct {
	mu       sync.RWMutex
	snapshot *PolicySnapshot
}

// NewSnapshotHolder creates an empty SnapshotHolder.
func NewSnapshotHolder() *SnapshotHolder {
	return &SnapshotHolder{}
}

// Get returns the current snapshot or ErrPolicyUnavailable if none is loaded.
func (h *SnapshotHolder) Get() (*PolicySnapshot, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.snapshot == nil {
		return nil, ErrPolicyUnavailable
	}
	return h.snapshot, nil
}

// Set atomically replaces the snapshot, ensuring version monotonicity and invariant validation.
func (h *SnapshotHolder) Set(newSnapshot *PolicySnapshot) error {
	if err := newSnapshot.Validate(); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.snapshot != nil && newSnapshot.Version <= h.snapshot.Version {
		return fmt.Errorf("%w: current version %d >= incoming version %d",
			ErrOlderSnapshotVersion, h.snapshot.Version, newSnapshot.Version)
	}

	h.snapshot = newSnapshot
	return nil
}

// Version returns the current snapshot version, or 0 if uninitialized.
func (h *SnapshotHolder) Version() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.snapshot == nil {
		return 0
	}
	return h.snapshot.Version
}

// Age returns the time elapsed since the current snapshot was generated.
func (h *SnapshotHolder) Age() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.snapshot == nil {
		return 0
	}
	return time.Since(h.snapshot.CreatedAt)
}

// IsReady returns true if a valid snapshot is currently installed.
func (h *SnapshotHolder) IsReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.snapshot != nil
}
