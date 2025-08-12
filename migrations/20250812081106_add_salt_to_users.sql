-- Add migration script here
ALTER TABLE users ADD Column salt Text NOT NULL;