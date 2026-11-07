INSERT INTO atlas_roles (role_name, description, permissions) VALUES
    ('reader', 'Read records', ARRAY['records:read']::text[]),
    ('writer', 'Read and create records', ARRAY['records:read', 'records:write']::text[]),
    ('admin', 'Manage records, API keys, and access roles', ARRAY['records:read', 'records:write', 'keys:manage']::text[]);
