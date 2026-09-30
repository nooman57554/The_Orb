DELETE FROM role_permissions
WHERE role_id IN (
    SELECT id
    FROM roles
    WHERE name IN (
        'PLATFORM_ADMIN',
        'TENANT_ADMIN_RW',
        'TENANT_ADMIN_READONLY',
        'TENANT_USER'
    )
    AND scope IN (
        'platform',
        'system_tenant'
    )
);