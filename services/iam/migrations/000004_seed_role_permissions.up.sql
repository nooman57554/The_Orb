-- ============================================================
-- PLATFORM_ADMIN
-- Gets every currently defined permission.
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
        'tenant.read',
        'tenant.update',

        'user.read',
        'user.invite',
        'user.remove',

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
        'user.read',
        'agent.read',
        'workflow.read'
    )
WHERE r.name = 'TENANT_ADMIN_READONLY'
  AND r.scope = 'system_tenant'
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
        'user.read',
        'agent.read',
        'workflow.read',
        'workflow.execute'
    )
WHERE r.name = 'TENANT_USER'
  AND r.scope = 'system_tenant'
ON CONFLICT DO NOTHING;