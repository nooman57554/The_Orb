DELETE FROM permissions
WHERE name IN (
    -- Platform permissions
    'platform.tenant.list',
    'platform.tenant.read',
    'platform.tenant.create',
    'platform.tenant.update',
    'platform.tenant.deactivate',
    'platform.tenant.reactivate',
    'platform.user.read',
    'platform.user.deactivate',
    'platform.user.reactivate',
    'platform.role.read',
    'platform.role.create',
    'platform.role.update',
    'platform.role.delete',
    'platform.role.assign',
    'platform.role.assign_permissions',

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

    -- Agent & workflow permissions
    'agent.read',
    'agent.create',
    'agent.update',
    'agent.delete',
    'workflow.read',
    'workflow.create',
    'workflow.update',
    'workflow.delete',
    'workflow.execute'
);