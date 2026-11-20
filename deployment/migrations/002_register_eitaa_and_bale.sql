INSERT INTO applications (title, package_name, category, is_active)
VALUES
    ('Eitaa', 'ir.eitaa.messenger', 'Messaging', TRUE),
    ('Bale', 'ir.nasim', 'Messaging', TRUE)
ON CONFLICT (package_name) DO UPDATE
SET title = EXCLUDED.title,
    category = EXCLUDED.category,
    is_active = EXCLUDED.is_active,
    updated_at = CURRENT_TIMESTAMP
WHERE (applications.title, applications.category, applications.is_active)
      IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.category, EXCLUDED.is_active);
