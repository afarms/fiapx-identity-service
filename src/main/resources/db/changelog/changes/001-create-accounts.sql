--liquibase formatted sql
--changeset fiapx:001-create-accounts
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('USER', 'ADMIN')),
    active BOOLEAN NOT NULL,
    credential_version BIGINT NOT NULL DEFAULT 0 CHECK (credential_version >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_account_email CHECK (email = lower(trim(email))),
    CONSTRAINT ck_account_name CHECK (length(trim(name)) > 0)
);
CREATE INDEX ix_accounts_created ON accounts(created_at, id);
-- Roll-forward after real data exists.
--rollback DROP TABLE accounts;
