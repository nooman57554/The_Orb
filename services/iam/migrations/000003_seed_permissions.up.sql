INSERT INTO permissions (
    id,
    name,
    scope,
    description
)
VALUES
-- ============================================================
-- PLATFORM PERMISSIONS (scope: platform)
-- ============================================================
(
    '01a0f2c7-fc19-7920-b482-79363f85a720',
    'platform.tenant.list',
    'platform',
    'List all tenants across platform'
),
(
    '01a0f2c7-fc19-7921-b482-79363f85a721',
    'platform.tenant.read',
    'platform',
    'Read any tenant details'
),
(
    '01a0f2c7-fc19-7922-b482-79363f85a722',
    'platform.tenant.create',
    'platform',
    'Create new tenants'
),
(
    '01a0f2c7-fc19-7923-b482-79363f85a723',
    'platform.tenant.update',
    'platform',
    'Update tenant settings across platform'
),
(
    '01a0f2c7-fc19-7924-b482-79363f85a724',
    'platform.tenant.deactivate',
    'platform',
    'Deactivate or suspend tenants'
),
(
    '01a0f2c7-fc19-7925-b482-79363f85a725',
    'platform.tenant.reactivate',
    'platform',
    'Reactivate tenants'
),
(
    '01a0f2c7-fc19-7926-b482-79363f85a726',
    'platform.user.read',
    'platform',
    'Read any user across platform'
),
(
    '01a0f2c7-fc19-7927-b482-79363f85a727',
    'platform.user.deactivate',
    'platform',
    'Deactivate user accounts'
),
(
    '01a0f2c7-fc19-7928-b482-79363f85a728',
    'platform.user.reactivate',
    'platform',
    'Reactivate user accounts'
),
(
    '01a0f2c7-fc19-7929-b482-79363f85a729',
    'platform.role.read',
    'platform',
    'Read platform roles'
),
(
    '01a0f2c7-fc19-7930-b482-79363f85a730',
    'platform.role.create',
    'platform',
    'Create platform roles'
),
(
    '01a0f2c7-fc19-7931-b482-79363f85a731',
    'platform.role.update',
    'platform',
    'Update platform roles'
),
(
    '01a0f2c7-fc19-7932-b482-79363f85a732',
    'platform.role.delete',
    'platform',
    'Delete platform roles'
),
(
    '01a0f2c7-fc19-7933-b482-79363f85a733',
    'platform.role.assign',
    'platform',
    'Assign platform roles or assign users across tenants'
),
(
    '01a0f2c7-fc19-7934-b482-79363f85a734',
    'platform.role.assign_permissions',
    'platform',
    'Assign permissions to platform roles'
),

-- ============================================================
-- CANONICAL TENANT PERMISSIONS (scope: tenant)
-- ============================================================
(
    '01a0f2c7-fc19-7940-b482-79363f85a740',
    'tenant.read',
    'tenant',
    'Read tenant details'
),
(
    '01a0f2c7-fc19-7941-b482-79363f85a741',
    'tenant.update',
    'tenant',
    'Update tenant details'
),
(
    '01a0f2c7-fc19-7942-b482-79363f85a742',
    'tenant.user.read',
    'tenant',
    'Read users within a tenant'
),
(
    '01a0f2c7-fc19-7943-b482-79363f85a743',
    'tenant.user.create',
    'tenant',
    'Provision new users in a tenant'
),
(
    '01a0f2c7-fc19-7944-b482-79363f85a744',
    'tenant.user.update',
    'tenant',
    'Update tenant users'
),
(
    '01a0f2c7-fc19-7945-b482-79363f85a745',
    'tenant.user.assign_role',
    'tenant',
    'Assign roles to users in a tenant'
),
(
    '01a0f2c7-fc19-7946-b482-79363f85a746',
    'tenant.user.remove',
    'tenant',
    'Remove users from a tenant'
),
(
    '01a0f2c7-fc19-7947-b482-79363f85a747',
    'tenant.role.read',
    'tenant',
    'Read tenant roles'
),
(
    '01a0f2c7-fc19-7948-b482-79363f85a748',
    'tenant.role.create',
    'tenant',
    'Create custom tenant roles'
),
(
    '01a0f2c7-fc19-7949-b482-79363f85a749',
    'tenant.role.update',
    'tenant',
    'Update custom tenant roles'
),
(
    '01a0f2c7-fc19-7950-b482-79363f85a750',
    'tenant.role.delete',
    'tenant',
    'Delete custom tenant roles'
),
(
    '01a0f2c7-fc19-7951-b482-79363f85a751',
    'tenant.role.assign_permissions',
    'tenant',
    'Assign permissions to custom tenant roles'
),
(
    '01a0f2c7-fc19-7952-b482-79363f85a752',
    'permission.read',
    'tenant',
    'Read permission catalog'
),

-- ============================================================
-- AGENT & WORKFLOW PERMISSIONS (scope: tenant)
-- ============================================================
(
    '01a0f2c7-fc19-7ad0-91f3-e542afb3927d',
    'agent.read',
    'tenant',
    'Read agents'
),
(
    '01a0f2c7-fc19-781d-9a45-5b937eddee42',
    'agent.create',
    'tenant',
    'Create agents'
),
(
    '01a0f2c7-fc19-7132-a19c-75994c5a87e0',
    'agent.update',
    'tenant',
    'Update agents'
),
(
    '01a0f2c7-fc19-7ff6-bb5d-00ebccf92453',
    'agent.delete',
    'tenant',
    'Delete agents'
),
(
    '01a0f2c7-fc19-74eb-b2f3-fcab82f5443d',
    'workflow.read',
    'tenant',
    'Read workflows'
),
(
    '01a0f2c7-fc19-7f3e-9843-f5f549c5dfbc',
    'workflow.create',
    'tenant',
    'Create workflows'
),
(
    '01a0f2c7-fc19-7f5c-a944-e39c6c586f38',
    'workflow.update',
    'tenant',
    'Update workflows'
),
(
    '01a0f2c7-fc19-7706-8b1a-d135e0fdb391',
    'workflow.delete',
    'tenant',
    'Delete workflows'
),
(
    '01a0f2c7-fc19-7d06-9461-283b635f4cdc',
    'workflow.execute',
    'tenant',
    'Execute workflows'
)
ON CONFLICT (name) DO UPDATE SET
    scope = EXCLUDED.scope,
    description = EXCLUDED.description;