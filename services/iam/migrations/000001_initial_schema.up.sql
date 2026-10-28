CREATE EXTENSION IF NOT EXISTS "citext";

-- ============================================================
-- FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- USERS
-- ============================================================

CREATE TABLE users (
    id UUID PRIMARY KEY,

    email CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_status_check
        CHECK (status IN ('active', 'suspended', 'deactivated'))
);

CREATE TRIGGER set_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();


-- ============================================================
-- TENANTS
-- ============================================================

CREATE TABLE tenants (
    id UUID PRIMARY KEY,

    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenants_status_check
        CHECK (status IN ('active', 'suspended', 'deactivated'))
);

CREATE TRIGGER set_timestamp_tenants
BEFORE UPDATE ON tenants
FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();


-- ============================================================
-- ROLES
-- ============================================================

CREATE TABLE roles (
    id UUID PRIMARY KEY,

    name TEXT NOT NULL,

    scope TEXT NOT NULL,

    tenant_id UUID
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT roles_scope_check
        CHECK (
            scope IN (
                'platform',
                'system_tenant',
                'custom_tenant'
            )
        ),

    CONSTRAINT roles_scope_tenant_check
        CHECK (
            (scope = 'platform' AND tenant_id IS NULL)
            OR
            (scope = 'system_tenant' AND tenant_id IS NULL)
            OR
            (scope = 'custom_tenant' AND tenant_id IS NOT NULL)
        )
);

CREATE TRIGGER set_timestamp_roles
BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

CREATE OR REPLACE FUNCTION check_role_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.scope != OLD.scope THEN
        RAISE EXCEPTION 'role scope is immutable';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'role tenant_id is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_role_immutability
BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION check_role_immutability();

CREATE UNIQUE INDEX uq_platform_role_name
    ON roles(name)
    WHERE scope = 'platform';

CREATE UNIQUE INDEX uq_system_tenant_role_name
    ON roles(name)
    WHERE scope = 'system_tenant';

CREATE UNIQUE INDEX uq_custom_tenant_role_name
    ON roles(tenant_id, name)
    WHERE scope = 'custom_tenant';

CREATE INDEX idx_roles_custom_tenant
    ON roles(tenant_id)
    WHERE scope = 'custom_tenant';


-- ============================================================
-- PERMISSIONS
-- ============================================================

CREATE TABLE permissions (
    id UUID PRIMARY KEY,

    name TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'tenant',
    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT permissions_scope_check
        CHECK (scope IN ('platform', 'tenant'))
);


-- ============================================================
-- ROLE → PERMISSION
-- ============================================================

CREATE TABLE role_permissions (
    role_id UUID NOT NULL
        REFERENCES roles(id)
        ON DELETE CASCADE,

    permission_id UUID NOT NULL
        REFERENCES permissions(id)
        ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

CREATE OR REPLACE FUNCTION check_role_permission_invariants()
RETURNS TRIGGER AS $$
DECLARE
    v_role_scope TEXT;
    v_perm_scope TEXT;
BEGIN
    SELECT scope INTO v_role_scope FROM roles WHERE id = NEW.role_id;
    SELECT scope INTO v_perm_scope FROM permissions WHERE id = NEW.permission_id;

    IF v_role_scope IN ('system_tenant', 'custom_tenant') AND v_perm_scope != 'tenant' THEN
        RAISE EXCEPTION 'Cannot assign platform permission % to tenant role %', NEW.permission_id, NEW.role_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_role_permission_invariants
BEFORE INSERT OR UPDATE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION check_role_permission_invariants();


-- ============================================================
-- ROLE ASSIGNMENTS
-- ============================================================

CREATE TABLE role_assignments (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    role_id UUID NOT NULL
        REFERENCES roles(id)
        ON DELETE RESTRICT,

    tenant_id UUID
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one platform-wide role per user (tenant_id IS NULL)
CREATE UNIQUE INDEX uq_role_assignments_platform_user
    ON role_assignments (user_id)
    WHERE tenant_id IS NULL;

-- At most one role per user per tenant (tenant_id IS NOT NULL)
CREATE UNIQUE INDEX uq_role_assignments_tenant_user
    ON role_assignments (user_id, tenant_id)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_role_assignments_user_id ON role_assignments(user_id);
CREATE INDEX idx_role_assignments_role_id ON role_assignments(role_id);
CREATE INDEX idx_role_assignments_tenant_id ON role_assignments(tenant_id)
    WHERE tenant_id IS NOT NULL;

-- Invariant Trigger: Enforce scope and custom tenant ownership at DB level
CREATE OR REPLACE FUNCTION check_role_assignment_invariants()
RETURNS TRIGGER AS $$
DECLARE
    v_role_scope TEXT;
    v_role_tenant_id UUID;
BEGIN
    SELECT scope, tenant_id INTO v_role_scope, v_role_tenant_id
    FROM roles
    WHERE id = NEW.role_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Referenced role % does not exist', NEW.role_id;
    END IF;

    IF v_role_scope = 'platform' THEN
        IF NEW.tenant_id IS NOT NULL THEN
            RAISE EXCEPTION 'Platform role assignment must have tenant_id NULL';
        END IF;
    ELSIF v_role_scope = 'system_tenant' THEN
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'System tenant role assignment must have non-null tenant_id';
        END IF;
    ELSIF v_role_scope = 'custom_tenant' THEN
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'Custom tenant role assignment must have non-null tenant_id';
        END IF;
        IF NEW.tenant_id != v_role_tenant_id THEN
            RAISE EXCEPTION 'Custom tenant role % belongs to tenant %, not assigned tenant %',
                NEW.role_id, v_role_tenant_id, NEW.tenant_id;
        END IF;
    ELSE
        RAISE EXCEPTION 'Unknown role scope %', v_role_scope;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_role_assignment_invariants
BEFORE INSERT OR UPDATE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION check_role_assignment_invariants();


-- ============================================================
-- SESSIONS
-- ============================================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    previous_token_hash TEXT,

    expires_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_at TIMESTAMPTZ,

    rotated_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_previous_token_hash
    ON sessions(previous_token_hash)
    WHERE previous_token_hash IS NOT NULL;


-- ============================================================
-- TENANT INVITATIONS
-- ============================================================

CREATE TABLE tenant_invitations (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    email CITEXT NOT NULL,

    role_id UUID NOT NULL
        REFERENCES roles(id),

    token_hash TEXT NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    accepted_at TIMESTAMPTZ,

    created_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_invitations_tenant_id ON tenant_invitations(tenant_id);
CREATE INDEX idx_tenant_invitations_email ON tenant_invitations(email);


-- ============================================================
-- SERVICE ACCOUNTS
-- ============================================================

CREATE TABLE service_accounts (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT service_accounts_status_check
        CHECK (status IN ('active', 'suspended', 'deactivated')),

    UNIQUE (tenant_id, name)
);

CREATE TRIGGER set_timestamp_service_accounts
BEFORE UPDATE ON service_accounts
FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();


-- ============================================================
-- API CREDENTIALS
-- ============================================================

CREATE TABLE api_credentials (
    id UUID PRIMARY KEY,

    service_account_id UUID NOT NULL
        REFERENCES service_accounts(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,

    secret_hash TEXT NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ,

    last_used_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (service_account_id, name)
);


-- ============================================================
-- TENANT RESOURCES
-- ============================================================

CREATE TABLE tenant_resources (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    resource_type TEXT NOT NULL,

    endpoint TEXT,

    database_name TEXT,

    credential_ref TEXT,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenant_resources_status_check
        CHECK (
            status IN (
                'active',
                'provisioning',
                'suspended',
                'deactivated'
            )
        ),

    UNIQUE (tenant_id, resource_type)
);

CREATE TRIGGER set_timestamp_tenant_resources
BEFORE UPDATE ON tenant_resources
FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();