INSERT INTO permissions (
    id,
    name,
    description
)
VALUES
(
    '01a0f2c7-fc19-7839-b482-79363f85a781',
    'tenant.read',
    'Read tenant information'
),
(
    '01a0f2c7-fc19-74d3-b5eb-416d05f0b200',
    'tenant.update',
    'Update tenant information'
),
(
    '01a0f2c7-fc19-711f-adff-78e9a83a0791',
    'user.read',
    'Read users within a tenant'
),
(
    '01a0f2c7-fc19-7ea2-a294-1bf965a603f5',
    'user.invite',
    'Invite users to a tenant'
),
(
    '01a0f2c7-fc19-7db4-8293-e76cee3eecd3',
    'user.remove',
    'Remove users from a tenant'
),
(
    '01a0f2c7-fc19-7ad0-91f3-e542afb3927d',
    'agent.read',
    'Read agents'
),
(
    '01a0f2c7-fc19-781d-9a45-5b937eddee42',
    'agent.create',
    'Create agents'
),
(
    '01a0f2c7-fc19-7132-a19c-75994c5a87e0',
    'agent.update',
    'Update agents'
),
(
    '01a0f2c7-fc19-7ff6-bb5d-00ebccf92453',
    'agent.delete',
    'Delete agents'
),
(
    '01a0f2c7-fc19-74eb-b2f3-fcab82f5443d',
    'workflow.read',
    'Read workflows'
),
(
    '01a0f2c7-fc19-7f3e-9843-f5f549c5dfbc',
    'workflow.create',
    'Create workflows'
),
(
    '01a0f2c7-fc19-7f5c-a944-e39c6c586f38',
    'workflow.update',
    'Update workflows'
),
(
    '01a0f2c7-fc19-7706-8b1a-d135e0fdb391',
    'workflow.delete',
    'Delete workflows'
),
(
    '01a0f2c7-fc19-7d06-9461-283b635f4cdc',
    'workflow.execute',
    'Execute workflows'
)
ON CONFLICT (name) DO NOTHING;