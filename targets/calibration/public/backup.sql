-- PLANTED BUG (P-PUBLIC-DIR-SENSITIVE): a database dump committed under public/, which Next.js
-- serves verbatim at /backup.sql to anyone. Sensitive files must never live in public/. Caught by
-- checkPublicDirSensitive (filesystem walk of public/) → high. Fake, inert data below.
INSERT INTO users (id, email, password_hash) VALUES (1, 'sample@example.com', '$2b$10$FAKEfakeFAKEfakeFAKEfa');
