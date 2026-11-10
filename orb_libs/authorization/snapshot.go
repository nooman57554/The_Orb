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

// TenantPolicy contains authorization-relevant state for a tenant.
type TenantPolicy struct {
	Active bool `json:"active"`
}

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
	Tenants             map[string]TenantPolicy         `json:"tenants"`              // TenantID -> TenantPolicy
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

// SnapshotStatus provides diagnostic and health observability for the authorization snapshot.
type SnapshotStatus struct {
	Version               int64         `json:"version"`
	CreatedAt             time.Time     `json:"created_at"`
	Age                   time.Duration `json:"age"`
	LastSuccessfulRefresh time.Time     `json:"last_successful_refresh"`
	LastRefreshError      string        `json:"last_refresh_error,omitempty"`
	IsReady               bool          `json:"is_ready"`
	IsStale               bool          `json:"is_stale"`
}

// SnapshotHolder provides thread-safe access and atomic monotonic updates for a PolicySnapshot.
type SnapshotHolder struct {
	mu                    sync.RWMutex
	snapshot              *PolicySnapshot
	lastSuccessfulRefresh time.Time
	lastRefreshError      error
	lastRefreshAttempt    time.Time
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
	h.lastSuccessfulRefresh = time.Now()
	h.lastRefreshError = nil
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

// RecordRefreshSuccess records that a refresh succeeded.
func (h *SnapshotHolder) RecordRefreshSuccess(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastSuccessfulRefresh = t
	h.lastRefreshAttempt = t
	h.lastRefreshError = nil
}

// RecordRefreshFailure records that a refresh failed.
func (h *SnapshotHolder) RecordRefreshFailure(err error, t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastRefreshError = err
	h.lastRefreshAttempt = t
}

// LastSuccessfulRefresh returns the timestamp of the last successful policy refresh.
func (h *SnapshotHolder) LastSuccessfulRefresh() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.lastSuccessfulRefresh
}

// LastRefreshError returns the last recorded policy refresh error, or nil if healthy.
func (h *SnapshotHolder) LastRefreshError() error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.lastRefreshError
}

// Status returns a health and freshness summary of the SnapshotHolder.
func (h *SnapshotHolder) Status(maxPolicyAge ...time.Duration) SnapshotStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := SnapshotStatus{
		LastSuccessfulRefresh: h.lastSuccessfulRefresh,
		IsReady:               h.snapshot != nil,
	}

	if h.lastRefreshError != nil {
		status.LastRefreshError = h.lastRefreshError.Error()
	}

	if h.snapshot != nil {
		status.Version = h.snapshot.Version
		status.CreatedAt = h.snapshot.CreatedAt
		status.Age = time.Since(h.snapshot.CreatedAt)
		if len(maxPolicyAge) > 0 && maxPolicyAge[0] > 0 {
			status.IsStale = status.Age > maxPolicyAge[0]
		}
	}

	return status
}
