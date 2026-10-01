DELETE FROM roles
WHERE scope IN (
    'platform',
    'system_tenant'
)
AND name IN (
    'PLATFORM_ADMIN',
    'TENANT_ADMIN_RW',
    'TENANT_ADMIN_READONLY',
    'TENANT_USER'
);