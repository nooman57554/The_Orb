DELETE FROM permissions
WHERE name IN (
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
);