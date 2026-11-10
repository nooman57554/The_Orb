package authorization

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
