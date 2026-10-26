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
	ID          uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
}

type RolePermission struct {
	RoleID       uuid.UUID
	PermissionID uuid.UUID
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
