package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

var (
	ErrPolicyUnavailable = errors.New("authorization policy is unavailable")
	ErrPolicyStale       = errors.New("authorization policy is stale")
	ErrInvalidSnapshot   = errors.New("invalid authorization snapshot")
	ErrUnknownPermission = errors.New("unknown permission")
	ErrMissingScope      = errors.New("missing required authorization scope")
)

// Scope defines the operational boundary of a permission or role.
type Scope string

const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
)

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

// ParsedTenantUUID converts a string tenantID to uuid.UUID if valid.
func ParsedTenantUUID(tenantID string) (uuid.UUID, error) {
	return uuid.Parse(tenantID)
}
