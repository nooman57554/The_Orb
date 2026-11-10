package authorization

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EngineConfig configures the LocalEngine.
type EngineConfig struct {
	// MaxPolicyAge defines the maximum acceptable age of a policy snapshot.
	// If the snapshot is older than MaxPolicyAge, the engine fails closed with ErrPolicyStale.
	// Set to 0 to disable age expiration.
	MaxPolicyAge time.Duration
}

// LocalEngine evaluates authorization decisions locally in-memory using an immutable PolicySnapshot.
type LocalEngine struct {
	holder *SnapshotHolder
	cfg    EngineConfig
}

var _ Engine = (*LocalEngine)(nil)

// NewLocalEngine creates a new LocalEngine backed by a SnapshotHolder.
func NewLocalEngine(holder *SnapshotHolder, cfg ...EngineConfig) *LocalEngine {
	config := EngineConfig{}
	if len(cfg) > 0 {
		config = cfg[0]
	}
	return &LocalEngine{
		holder: holder,
		cfg:    config,
	}
}

// SnapshotVersion returns the version of the currently loaded snapshot.
func (e *LocalEngine) SnapshotVersion() int64 {
	return e.holder.Version()
}

// SnapshotAge returns the duration since the current snapshot was generated.
func (e *LocalEngine) SnapshotAge() time.Duration {
	return e.holder.Age()
}

// IsReady returns whether a usable snapshot is currently loaded and fresh.
func (e *LocalEngine) IsReady() bool {
	if !e.holder.IsReady() {
		return false
	}
	if e.cfg.MaxPolicyAge > 0 && e.holder.Age() > e.cfg.MaxPolicyAge {
		return false
	}
	return true
}

// Authorize evaluates an authorization request locally against the current policy snapshot.
func (e *LocalEngine) Authorize(ctx context.Context, req AuthorizationRequest) (Decision, error) {
	now := time.Now()

	// 1. Snapshot availability & freshness (Fail-closed)
	snapshot, err := e.holder.Get()
	if err != nil {
		return Decision{
			Allowed:     false,
			Reason:      ReasonPolicyUnavailable,
			EvaluatedAt: now,
		}, ErrPolicyUnavailable
	}

	if e.cfg.MaxPolicyAge > 0 && now.Sub(snapshot.CreatedAt) > e.cfg.MaxPolicyAge {
		return Decision{
			Allowed:       false,
			Reason:        ReasonPolicyStale,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, ErrPolicyStale
	}

	// 2. Principal check
	if req.Principal == nil || !req.Principal.IsValid() {
		return Decision{
			Allowed:       false,
			Reason:        ReasonUnauthenticated,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	userIDStr := req.Principal.UserID.String()

	// 3. User status check (if user status tracked in snapshot)
	if userPolicy, exists := snapshot.Users[userIDStr]; exists {
		if !userPolicy.Active {
			return Decision{
				Allowed:       false,
				Reason:        ReasonUserInactive,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	}

	// 4. Resource ownership rule: Self-profile access
	// A user reading their own profile resource is authorized by ownership invariant.
	if req.ResourceType == "user" && req.ResourceID != "" && req.ResourceID == userIDStr {
		if req.Permission == PermPlatformUserRead || req.Permission == PermTenantUserRead {
			return Decision{
				Allowed:       true,
				Reason:        ReasonAllowed,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	}

	// 5. Permission scope resolution from snapshot or canonical catalog
	permissionName := strings.TrimSpace(req.Permission)
	if permissionName == "" {
		return Decision{
			Allowed:       false,
			Reason:        ReasonUnknownPermission,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	var permScope Scope
	if permDef, exists := snapshot.Permissions[permissionName]; exists {
		permScope = permDef.Scope
	} else if catScope, exists := ScopeOf(permissionName); exists {
		permScope = catScope
	} else {
		return Decision{
			Allowed:       false,
			Reason:        ReasonUnknownPermission,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	// 6. Evaluate based on scope
	switch permScope {
	case ScopePlatform:
		return e.authorizePlatform(snapshot, userIDStr, permissionName, now)
	case ScopeTenant:
		return e.authorizeTenant(snapshot, userIDStr, req.TenantID, permissionName, now)
	default:
		return Decision{
			Allowed:       false,
			Reason:        ReasonRoleScopeMismatch,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}
}

func (e *LocalEngine) authorizePlatform(
	snapshot *PolicySnapshot,
	userIDStr string,
	permission string,
	now time.Time,
) (Decision, error) {
	// Platform role lookup
	roleID, hasRole := snapshot.PlatformAssignments[userIDStr]
	if !hasRole || roleID == "" {
		return Decision{
			Allowed:       false,
			Reason:        ReasonNoPlatformRole,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	role, exists := snapshot.Roles[roleID]
	if !exists {
		return Decision{
			Allowed:       false,
			Reason:        ReasonNoPlatformRole,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	if role.Scope != RoleScopePlatform {
		return Decision{
			Allowed:       false,
			Reason:        ReasonRoleScopeMismatch,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	for _, p := range role.Permissions {
		if p == permission {
			return Decision{
				Allowed:       true,
				Reason:        ReasonAllowed,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	}

	return Decision{
		Allowed:       false,
		Reason:        ReasonMissingPermission,
		PolicyVersion: snapshot.Version,
		EvaluatedAt:   now,
	}, nil
}

func (e *LocalEngine) authorizeTenant(
	snapshot *PolicySnapshot,
	userIDStr string,
	rawTenantID string,
	permission string,
	now time.Time,
) (Decision, error) {
	tenantUUID, err := uuid.Parse(strings.TrimSpace(rawTenantID))
	if err != nil || tenantUUID == uuid.Nil {
		return Decision{
			Allowed:       false,
			Reason:        ReasonMissingTenantScope,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}
	tenantIDStr := tenantUUID.String()

	// Tenant active status check (fail-closed if tenant inactive or missing from populated catalog)
	if tenantPolicy, exists := snapshot.Tenants[tenantIDStr]; exists {
		if !tenantPolicy.Active {
			return Decision{
				Allowed:       false,
				Reason:        ReasonTenantInactive,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	} else if len(snapshot.Tenants) > 0 {
		return Decision{
			Allowed:       false,
			Reason:        ReasonTenantInactive,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	// Tenant assignment lookup
	userTenantRoles, hasTenantMap := snapshot.TenantAssignments[userIDStr]
	if !hasTenantMap {
		return Decision{
			Allowed:       false,
			Reason:        ReasonNoTenantRole,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	roleID, hasRole := userTenantRoles[tenantIDStr]
	if !hasRole || roleID == "" {
		return Decision{
			Allowed:       false,
			Reason:        ReasonNoTenantRole,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	role, exists := snapshot.Roles[roleID]
	if !exists {
		return Decision{
			Allowed:       false,
			Reason:        ReasonNoTenantRole,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	if role.Scope == RoleScopePlatform {
		return Decision{
			Allowed:       false,
			Reason:        ReasonRoleScopeMismatch,
			PolicyVersion: snapshot.Version,
			EvaluatedAt:   now,
		}, nil
	}

	// Custom tenant role ownership invariant
	if role.Scope == RoleScopeCustomTenant {
		if role.TenantID == nil || *role.TenantID != tenantIDStr {
			return Decision{
				Allowed:       false,
				Reason:        ReasonCustomRoleWrongTenant,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	}

	for _, p := range role.Permissions {
		if p == permission {
			return Decision{
				Allowed:       true,
				Reason:        ReasonAllowed,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, nil
		}
	}

	return Decision{
		Allowed:       false,
		Reason:        ReasonMissingPermission,
		PolicyVersion: snapshot.Version,
		EvaluatedAt:   now,
	}, nil
}
