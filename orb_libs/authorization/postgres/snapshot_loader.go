package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
)

// DB defines the minimal PostgreSQL interface required to load authorization snapshots.
type DB interface {
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SnapshotLoader loads consistent PolicySnapshots from a PostgreSQL database.
// It implements authorization.SnapshotSource.
type SnapshotLoader struct {
	db DB
}

var _ authorization.SnapshotSource = (*SnapshotLoader)(nil)

// NewSnapshotLoader creates a new PostgreSQL SnapshotLoader.
func NewSnapshotLoader(db DB) *SnapshotLoader {
	return &SnapshotLoader{db: db}
}

// GetLatestVersion queries the current policy version from the outbox sequence table.
// If the query fails, it propagates the error and does not substitute a default version.
func (l *SnapshotLoader) GetLatestVersion(ctx context.Context) (int64, error) {
	var version int64
	err := l.db.QueryRow(ctx, "SELECT COALESCE(MAX(version), 1) FROM authz_outbox").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("query latest policy version: %w", err)
	}
	return version, nil
}

// LoadSnapshot loads a complete, transactionally consistent snapshot using a REPEATABLE READ read-only transaction.
// All policy tables and the policy version are read from a single MVCC snapshot.
func (l *SnapshotLoader) LoadSnapshot(ctx context.Context) (*authorization.PolicySnapshot, error) {
	tx, err := l.db.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin snapshot transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Determine current version within the same consistent read transaction
	var version int64
	err = tx.QueryRow(ctx, "SELECT COALESCE(MAX(version), 1) FROM authz_outbox").Scan(&version)
	if err != nil {
		return nil, fmt.Errorf("query policy version: %w", err)
	}

	snapshot := &authorization.PolicySnapshot{
		Version:             version,
		CreatedAt:           time.Now().UTC(),
		Users:               make(map[string]authorization.UserPolicy),
		Tenants:             make(map[string]authorization.TenantPolicy),
		PlatformAssignments: make(map[string]string),
		TenantAssignments:   make(map[string]map[string]string),
		Roles:               make(map[string]authorization.RolePolicy),
		Permissions:         make(map[string]authorization.PermissionDefinition),
	}

	// 2. Load Permissions Catalog
	permRows, err := tx.Query(ctx, "SELECT name, scope FROM permissions")
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
	roleRows, err := tx.Query(ctx, "SELECT id, name, scope, tenant_id FROM roles")
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
	rpRows, err := tx.Query(ctx, `
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
	userRows, err := tx.Query(ctx, "SELECT id, status FROM users")
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

	// 6. Load Tenants
	tenantRows, err := tx.Query(ctx, "SELECT id, status FROM tenants")
	if err != nil {
		return nil, fmt.Errorf("load tenants: %w", err)
	}
	defer tenantRows.Close()

	for tenantRows.Next() {
		var (
			tenantID uuid.UUID
			status   string
		)
		if err := tenantRows.Scan(&tenantID, &status); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		snapshot.Tenants[tenantID.String()] = authorization.TenantPolicy{
			Active: status == "active",
		}
	}
	if err := tenantRows.Err(); err != nil {
		return nil, fmt.Errorf("tenants rows error: %w", err)
	}

	// 7. Load Platform Role Assignments
	pRows, err := tx.Query(ctx, "SELECT user_id, role_id FROM role_assignments WHERE tenant_id IS NULL")
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

	// 8. Load Tenant Role Assignments
	tRows, err := tx.Query(ctx, "SELECT user_id, tenant_id, role_id FROM role_assignments WHERE tenant_id IS NOT NULL")
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

	// 9. Validate structural and invariant integrity
	if err := snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("validate loaded snapshot: %w", err)
	}

	return snapshot, nil
}
