INSERT INTO roles (
    id,
    name,
    scope,
    tenant_id,
    description
)
VALUES
(
    '01a0f2c7-fc19-7d9f-948c-864888e67b0a',
    'PLATFORM_ADMIN',
    'platform',
    NULL,
    'Full administrative access to the ORB platform'
),
(
    '01a0f2c7-fc19-7e4c-849f-a5a3fe3b598c',
    'TENANT_ADMIN_RW',
    'system_tenant',
    NULL,
    'Full read and write access within a tenant'
),
(
    '01a0f2c7-fc19-72a7-b663-852138d51053',
    'TENANT_ADMIN_READONLY',
    'system_tenant',
    NULL,
    'Read-only administrative access within a tenant'
),
(
    '01a0f2c7-fc19-7cde-8da7-8393655ed14c',
    'TENANT_USER',
    'system_tenant',
    NULL,
    'Standard tenant user access'
)
ON CONFLICT DO NOTHING;