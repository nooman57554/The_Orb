-- ============================================================
-- PLATFORM_ADMIN
-- Gets all platform-scoped permissions.
-- Platform and tenant scopes are strictly separate.
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id
)
SELECT
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'PLATFORM_ADMIN'
  AND r.scope = 'platform'
  AND p.scope = 'platform'
ON CONFLICT DO NOTHING;


-- ============================================================
-- TENANT_ADMIN_RW
-- Full tenant administration and application access.
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id
)
SELECT
    r.id,
    p.id
FROM roles r
JOIN permissions p
    ON p.name IN (
        -- Canonical tenant permissions
        'tenant.read',
        'tenant.update',
        'tenant.user.read',
        'tenant.user.create',
        'tenant.user.update',
        'tenant.user.assign_role',
        'tenant.user.remove',
        'tenant.role.read',
        'tenant.role.create',
        'tenant.role.update',
        'tenant.role.delete',
        'tenant.role.assign_permissions',
        'permission.read',

        -- Agent & workflow
        'agent.read',
        'agent.create',
        'agent.update',
        'agent.delete',
        'workflow.read',
        'workflow.create',
        'workflow.update',
        'workflow.delete',
        'workflow.execute'
    )
WHERE r.name = 'TENANT_ADMIN_RW'
  AND r.scope = 'system_tenant'
  AND p.scope = 'tenant'
ON CONFLICT DO NOTHING;


-- ============================================================
-- TENANT_ADMIN_READONLY
-- Read-only tenant administration.
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id
)
SELECT
    r.id,
    p.id
FROM roles r
JOIN permissions p
    ON p.name IN (
        'tenant.read',
        'tenant.user.read',
        'tenant.role.read',
        'permission.read',
        'agent.read',
        'workflow.read'
    )
WHERE r.name = 'TENANT_ADMIN_READONLY'
  AND r.scope = 'system_tenant'
  AND p.scope = 'tenant'
ON CONFLICT DO NOTHING;


-- ============================================================
-- TENANT_USER
-- Standard tenant user capabilities.
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id
)
SELECT
    r.id,
    p.id
FROM roles r
JOIN permissions p
    ON p.name IN (
        'tenant.read',
        'tenant.user.read',
        'agent.read',
        'workflow.read',
        'workflow.execute'
    )
WHERE r.name = 'TENANT_USER'
  AND r.scope = 'system_tenant'
  AND p.scope = 'tenant'
ON CONFLICT DO NOTHING;