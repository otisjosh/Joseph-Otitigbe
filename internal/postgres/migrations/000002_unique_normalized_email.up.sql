CREATE UNIQUE INDEX atlas_records_email_normalized_uidx
    ON atlas_records (lower(btrim(email)));
