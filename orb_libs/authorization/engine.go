package authorization

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

var (
	ErrPolicyUnavailable = errors.New("authorization policy is unavailable")
	ErrPolicyStale       = errors.New("authorization policy is stale")
	ErrUnknownPermission = errors.New("unknown permission")
	ErrMissingScope      = errors.New("missing required authorization scope")
)

// Scope defines the operational boundary of a permission or role.
type Scope string

const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
)

// Canonical platform permission identifiers.
const (
	PermPlatformTenantList       = "platform.tenant.list"
	PermPlatformTenantRead       = "platform.tenant.read"
	PermPlatformTenantCreate     = "platform.tenant.create"
	PermPlatformTenantUpdate     = "platform.tenant.update"
	PermPlatformTenantDeactivate = "platform.tenant.deactivate"
	PermPlatformTenantReactivate = "platform.tenant.reactivate"
	PermPlatformUserRead         = "platform.user.read"
	PermPlatformUserDeactivate   = "platform.user.deactivate"
	PermPlatformUserReactivate   = "platform.user.reactivate"
	PermPlatformRoleRead         = "platform.role.read"
	PermPlatformRoleCreate       = "platform.role.create"
	PermPlatformRoleUpdate       = "platform.role.update"
	PermPlatformRoleDelete       = "platform.role.delete"
	PermPlatformRoleAssign       = "platform.role.assign"
	PermPlatformRoleAssignPerms  = "platform.role.assign_permissions"
)

// Canonical tenant permission identifiers.
const (
	PermTenantRead            = "tenant.read"
	PermTenantUpdate          = "tenant.update"
	PermTenantUserRead        = "tenant.user.read"
	PermTenantUserCreate      = "tenant.user.create"
	PermTenantUserUpdate      = "tenant.user.update"
	PermTenantUserAssignRole  = "tenant.user.assign_role"
	PermTenantUserRemove      = "tenant.user.remove"
	PermTenantRoleRead        = "tenant.role.read"
	PermTenantRoleCreate      = "tenant.role.create"
	PermTenantRoleUpdate      = "tenant.role.update"
	PermTenantRoleDelete      = "tenant.role.delete"
	PermTenantRoleAssignPerms = "tenant.role.assign_permissions"
	PermTenantPermissionRead  = "permission.read"

	// Agent & Workflow permissions (tenant-scoped)
	PermAgentRead       = "agent.read"
	PermAgentCreate     = "agent.create"
	PermAgentUpdate     = "agent.update"
	PermAgentDelete     = "agent.delete"
	PermWorkflowRead    = "workflow.read"
	PermWorkflowCreate  = "workflow.create"
	PermWorkflowUpdate  = "workflow.update"
	PermWorkflowDelete  = "workflow.delete"
	PermWorkflowExecute = "workflow.execute"
)

// CanonicalCatalog contains all canonical permissions mapped to their authoritative scope.
var CanonicalCatalog = map[string]Scope{
	PermPlatformTenantList:       ScopePlatform,
	PermPlatformTenantRead:       ScopePlatform,
	PermPlatformTenantCreate:     ScopePlatform,
	PermPlatformTenantUpdate:     ScopePlatform,
	PermPlatformTenantDeactivate: ScopePlatform,
	PermPlatformTenantReactivate: ScopePlatform,
	PermPlatformUserRead:         ScopePlatform,
	PermPlatformUserDeactivate:   ScopePlatform,
	PermPlatformUserReactivate:   ScopePlatform,
	PermPlatformRoleRead:         ScopePlatform,
	PermPlatformRoleCreate:       ScopePlatform,
	PermPlatformRoleUpdate:       ScopePlatform,
	PermPlatformRoleDelete:       ScopePlatform,
	PermPlatformRoleAssign:       ScopePlatform,
	PermPlatformRoleAssignPerms:  ScopePlatform,

	PermTenantRead:            ScopeTenant,
	PermTenantUpdate:          ScopeTenant,
	PermTenantUserRead:        ScopeTenant,
	PermTenantUserCreate:      ScopeTenant,
	PermTenantUserUpdate:      ScopeTenant,
	PermTenantUserAssignRole:  ScopeTenant,
	PermTenantUserRemove:      ScopeTenant,
	PermTenantRoleRead:        ScopeTenant,
	PermTenantRoleCreate:      ScopeTenant,
	PermTenantRoleUpdate:      ScopeTenant,
	PermTenantRoleDelete:      ScopeTenant,
	PermTenantRoleAssignPerms: ScopeTenant,
	PermTenantPermissionRead:  ScopeTenant,

	PermAgentRead:       ScopeTenant,
	PermAgentCreate:     ScopeTenant,
	PermAgentUpdate:     ScopeTenant,
	PermAgentDelete:     ScopeTenant,
	PermWorkflowRead:    ScopeTenant,
	PermWorkflowCreate:  ScopeTenant,
	PermWorkflowUpdate:  ScopeTenant,
	PermWorkflowDelete:  ScopeTenant,
	PermWorkflowExecute: ScopeTenant,
}

// ScopeOf returns the canonical scope of a permission name, or empty string if unknown.
func ScopeOf(permissionName string) (Scope, bool) {
	scope, ok := CanonicalCatalog[permissionName]
	return scope, ok
}

// Permission defines a specific action and its invariant scope.
type Permission struct {
	Name        string `json:"name"`
	Scope       Scope  `json:"scope"`
	Description string `json:"description,omitempty"`
}

// DecisionReason describes the rationale behind an authorization decision.
type DecisionReason string

const (
	ReasonAllowed                 DecisionReason = "allowed"
	ReasonUnauthenticated         DecisionReason = "unauthenticated"
	ReasonUserInactive            DecisionReason = "user_inactive"
	ReasonTenantInactive          DecisionReason = "tenant_inactive"
	ReasonUnknownPermission       DecisionReason = "unknown_permission"
	ReasonMissingTenantScope      DecisionReason = "missing_tenant_scope"
	ReasonNoPlatformRole          DecisionReason = "no_platform_role"
	ReasonNoTenantRole            DecisionReason = "no_tenant_role"
	ReasonRoleScopeMismatch       DecisionReason = "role_scope_mismatch"
	ReasonCustomRoleWrongTenant   DecisionReason = "custom_role_wrong_tenant"
	ReasonMissingPermission       DecisionReason = "missing_permission"
	ReasonPolicyUnavailable       DecisionReason = "policy_unavailable"
	ReasonPolicyStale             DecisionReason = "policy_stale"
	ReasonResourceOwnershipDenied DecisionReason = "resource_ownership_denied"
)

// AuthorizationRequest encapsulates all input parameters for an authorization decision.
type AuthorizationRequest struct {
	Principal    *identity.Principal `json:"principal"`
	Permission   string              `json:"permission"`
	TenantID     string              `json:"tenant_id,omitempty"`
	ResourceType string              `json:"resource_type,omitempty"`
	ResourceID   string              `json:"resource_id,omitempty"`
}

// Decision represents the outcome of an authorization evaluation.
type Decision struct {
	Allowed       bool           `json:"allowed"`
	Reason        DecisionReason `json:"reason"`
	PolicyVersion int64          `json:"policy_version"`
	EvaluatedAt   time.Time      `json:"evaluated_at"`
}

// Engine evaluates authorization requests against the local authorization snapshot.
type Engine interface {
	Authorize(ctx context.Context, req AuthorizationRequest) (Decision, error)
	SnapshotVersion() int64
	SnapshotAge() time.Duration
	IsReady() bool
}

// EngineConfig configures the LocalEngine.
type EngineConfig struct {
	// MaxPolicyAge defines the maximum acceptable staleness of a policy snapshot.
	// If the snapshot has not been confirmed or refreshed within MaxPolicyAge,
	// the engine fails closed with ErrPolicyStale.
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
	if e.cfg.MaxPolicyAge > 0 {
		lastConfirmed := e.holder.LastSuccessfulRefresh()
		if lastConfirmed.IsZero() {
			if e.holder.Age() > e.cfg.MaxPolicyAge {
				return false
			}
		} else if time.Since(lastConfirmed) > e.cfg.MaxPolicyAge {
			return false
		}
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

	if e.cfg.MaxPolicyAge > 0 {
		lastConfirmed := e.holder.LastSuccessfulRefresh()
		if lastConfirmed.IsZero() {
			lastConfirmed = snapshot.CreatedAt
		}
		if now.Sub(lastConfirmed) > e.cfg.MaxPolicyAge {
			return Decision{
				Allowed:       false,
				Reason:        ReasonPolicyStale,
				PolicyVersion: snapshot.Version,
				EvaluatedAt:   now,
			}, ErrPolicyStale
		}
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

// ParsedTenantUUID converts a string tenantID to uuid.UUID if valid.
func ParsedTenantUUID(tenantID string) (uuid.UUID, error) {
	return uuid.Parse(tenantID)
}
