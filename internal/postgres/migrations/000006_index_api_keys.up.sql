CREATE INDEX atlas_api_keys_active_role_idx
    ON atlas_api_keys (role_name)
    WHERE revoked_at IS NULL;
