package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
)

// SnapshotLoader loads a complete, consistent PolicySnapshot from the IAM database.
type SnapshotLoader interface {
	LoadSnapshot(ctx context.Context) (*authorization.PolicySnapshot, error)
}

// PostgresSnapshotLoader implements SnapshotLoader using the PostgreSQL connection pool.
type PostgresSnapshotLoader struct {
	db *dbconnector.DBConnector
}

func NewPostgresSnapshotLoader(db *dbconnector.DBConnector) *PostgresSnapshotLoader {
	return &PostgresSnapshotLoader{db: db}
}

func (l *PostgresSnapshotLoader) LoadSnapshot(ctx context.Context) (*authorization.PolicySnapshot, error) {
	// 1. Determine current version from outbox or sequence
	var version int64
	err := l.db.Pool().QueryRow(ctx, "SELECT COALESCE(MAX(version), 1) FROM authz_outbox").Scan(&version)
	if err != nil || version <= 0 {
		version = 1
	}

	snapshot := &authorization.PolicySnapshot{
		Version:             version,
		CreatedAt:           time.Now().UTC(),
		Users:               make(map[string]authorization.UserPolicy),
		PlatformAssignments: make(map[string]string),
		TenantAssignments:   make(map[string]map[string]string),
		Roles:               make(map[string]authorization.RolePolicy),
		Permissions:         make(map[string]authorization.PermissionDefinition),
	}

	// 2. Load Permissions Catalog
	permRows, err := l.db.Pool().Query(ctx, "SELECT name, scope FROM permissions")
	if err != nil {
		return nil, fmt.Errorf("load permissions catalog: %w", err)
	}
	defer permRows.Close()

	for permRows.Next() {
		var name, scope string
		if err := permRows.Scan(&name, &scope); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		snapshot.Permissions[name] = authorization.PermissionDefinition{
			Name:  name,
			Scope: authorization.Scope(scope),
		}
	}
	if err := permRows.Err(); err != nil {
		return nil, fmt.Errorf("permissions rows error: %w", err)
	}

	// 3. Load Roles
	roleRows, err := l.db.Pool().Query(ctx, "SELECT id, name, scope, tenant_id FROM roles")
	if err != nil {
		return nil, fmt.Errorf("load roles: %w", err)
	}
	defer roleRows.Close()

	for roleRows.Next() {
		var (
			roleID   uuid.UUID
			name     string
			scope    string
			tenantID *uuid.UUID
		)
		if err := roleRows.Scan(&roleID, &name, &scope, &tenantID); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}

		var tidStr *string
		if tenantID != nil && *tenantID != uuid.Nil {
			s := tenantID.String()
			tidStr = &s
		}

		snapshot.Roles[roleID.String()] = authorization.RolePolicy{
			ID:          roleID.String(),
			Name:        name,
			Scope:       authorization.RoleScope(scope),
			TenantID:    tidStr,
			Permissions: make([]string, 0),
		}
	}
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("roles rows error: %w", err)
	}

	// 4. Load Role Permissions
	rpRows, err := l.db.Pool().Query(ctx, `
		SELECT rp.role_id, p.name
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
	`)
	if err != nil {
		return nil, fmt.Errorf("load role permissions: %w", err)
	}
	defer rpRows.Close()

	for rpRows.Next() {
		var (
			roleID   uuid.UUID
			permName string
		)
		if err := rpRows.Scan(&roleID, &permName); err != nil {
			return nil, fmt.Errorf("scan role permission: %w", err)
		}
		roleKey := roleID.String()
		if role, exists := snapshot.Roles[roleKey]; exists {
			role.Permissions = append(role.Permissions, permName)
			snapshot.Roles[roleKey] = role
		}
	}
	if err := rpRows.Err(); err != nil {
		return nil, fmt.Errorf("role permissions rows error: %w", err)
	}

	// 5. Load Users
	userRows, err := l.db.Pool().Query(ctx, "SELECT id, status FROM users")
	if err != nil {
		return nil, fmt.Errorf("load users: %w", err)
	}
	defer userRows.Close()

	for userRows.Next() {
		var (
			userID uuid.UUID
			status string
		)
		if err := userRows.Scan(&userID, &status); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		snapshot.Users[userID.String()] = authorization.UserPolicy{
			Active: status == "active",
		}
	}
	if err := userRows.Err(); err != nil {
		return nil, fmt.Errorf("users rows error: %w", err)
	}

	// 6. Load Platform Role Assignments
	pRows, err := l.db.Pool().Query(ctx, "SELECT user_id, role_id FROM role_assignments WHERE tenant_id IS NULL")
	if err != nil {
		return nil, fmt.Errorf("load platform role assignments: %w", err)
	}
	defer pRows.Close()

	for pRows.Next() {
		var (
			userID uuid.UUID
			roleID uuid.UUID
		)
		if err := pRows.Scan(&userID, &roleID); err != nil {
			return nil, fmt.Errorf("scan platform role assignment: %w", err)
		}
		snapshot.PlatformAssignments[userID.String()] = roleID.String()
	}
	if err := pRows.Err(); err != nil {
		return nil, fmt.Errorf("platform assignments rows error: %w", err)
	}

	// 7. Load Tenant Role Assignments
	tRows, err := l.db.Pool().Query(ctx, "SELECT user_id, tenant_id, role_id FROM role_assignments WHERE tenant_id IS NOT NULL")
	if err != nil {
		return nil, fmt.Errorf("load tenant role assignments: %w", err)
	}
	defer tRows.Close()

	for tRows.Next() {
		var (
			userID   uuid.UUID
			tenantID uuid.UUID
			roleID   uuid.UUID
		)
		if err := tRows.Scan(&userID, &tenantID, &roleID); err != nil {
			return nil, fmt.Errorf("scan tenant role assignment: %w", err)
		}
		uKey := userID.String()
		tKey := tenantID.String()
		if _, exists := snapshot.TenantAssignments[uKey]; !exists {
			snapshot.TenantAssignments[uKey] = make(map[string]string)
		}
		snapshot.TenantAssignments[uKey][tKey] = roleID.String()
	}
	if err := tRows.Err(); err != nil {
		return nil, fmt.Errorf("tenant assignments rows error: %w", err)
	}

	// 8. Validate structural and invariant integrity
	if err := snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("validate loaded snapshot: %w", err)
	}

	return snapshot, nil
}
