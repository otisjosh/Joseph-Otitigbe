CREATE TABLE atlas_roles (
    role_name text PRIMARY KEY CHECK (role_name IN ('reader', 'writer', 'admin')),
    description text NOT NULL,
    permissions text[] NOT NULL DEFAULT '{}'
);
