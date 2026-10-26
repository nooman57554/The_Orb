package model

import (
	"time"

	"github.com/google/uuid"
)

const (
	RoleScopePlatform     = "platform"
	RoleScopeSystemTenant = "system_tenant"
	RoleScopeCustomTenant = "custom_tenant"
)

type Role struct {
	ID          uuid.UUID
	Name        string
	Scope       string
	TenantID    *uuid.UUID
	Description string
	Permissions []Permission
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Scope       string    `json:"scope"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type RolePermission struct {
	RoleID       uuid.UUID
	PermissionID uuid.UUID
}

type RoleAssignment struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	RoleID    uuid.UUID  `json:"role_id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type PlatformRoleAssignment struct {
	UserID    uuid.UUID
	RoleID    uuid.UUID
	CreatedAt time.Time
}

type TenantRoleAssignment struct {
	UserID    uuid.UUID
	TenantID  uuid.UUID
	RoleID    uuid.UUID
	CreatedAt time.Time
}

type TenantMemberRecord struct {
	UserID    uuid.UUID
	Email     string
	Status    string
	RoleID    uuid.UUID
	RoleName  string
	RoleScope string
	JoinedAt  time.Time
}
