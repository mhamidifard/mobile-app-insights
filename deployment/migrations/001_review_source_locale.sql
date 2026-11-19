ALTER TABLE reviews
    ADD COLUMN IF NOT EXISTS source_language TEXT,
    ADD COLUMN IF NOT EXISTS source_country TEXT;
