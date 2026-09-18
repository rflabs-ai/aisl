/**
 * M12 Phase 2 — Row-level security on `security_events` (ADR-018).
 *
 * Migration id 2. Depends on migration id 1 (the `security_events` table) and
 * on the idempotent `app_rw` / `app_reader` role bootstrap in the migration
 * runner (src/event-store-pg.ts) — the roles are cluster-level and are NOT
 * created here. Static DDL only: no passwords, no secrets, no user input ever
 * reaches this SQL. Applied by the shared migration runner (forward-only,
 * sha256-recorded); tests apply `RLS_MIGRATION.sql` directly against a
 * disposable scratch database.
 */

import { type StoreMigration } from './event-store-pg.ts';

export const RLS_MIGRATION: StoreMigration = {
  id: 2,
  sql: `
    -- Deny-by-default tenant isolation, enforced by the database (ADR-018).
    -- FORCE applies RLS to the table owner too; superusers still bypass RLS,
    -- which the append-only triggers below cover.
    ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE security_events FORCE ROW LEVEL SECURITY;

    -- Runtime role: reads the whole global hash chain (seq is world-order,
    -- one signer: resume/verify/bundle read across all tenants) and appends
    -- every event. No UPDATE/DELETE grant exists and no policy grants it:
    -- default deny on top of revoked privileges.
    DROP POLICY IF EXISTS security_events_app_rw_select ON security_events;
    CREATE POLICY security_events_app_rw_select ON security_events
      FOR SELECT TO app_rw
      USING (true);

    DROP POLICY IF EXISTS security_events_app_rw_insert ON security_events;
    CREATE POLICY security_events_app_rw_insert ON security_events
      FOR INSERT TO app_rw
      WITH CHECK (true);

    -- Audit-reader role: tenant-scoped only. The context is set per
    -- transaction; unset context -> NULL -> false -> ZERO rows (fail closed),
    -- wrong context -> only that tenant's rows, never another's.
    DROP POLICY IF EXISTS security_events_app_reader_select ON security_events;
    CREATE POLICY security_events_app_reader_select ON security_events
      FOR SELECT TO app_reader
      USING (tenant_id = current_setting('app.tenant_id', true));

    -- Every other role: no policy exists -> default deny.

    -- Append-only belt and braces: no mutation privileges on any role, and
    -- triggers that raise on UPDATE/DELETE even for a role that regains the
    -- privilege (mirrors the SQLite triggers in src/events.ts).
    REVOKE UPDATE, DELETE ON security_events FROM PUBLIC;
    REVOKE UPDATE, DELETE ON security_events FROM app_rw;
    GRANT USAGE ON SCHEMA public TO app_rw;
    GRANT SELECT, INSERT ON security_events TO app_rw;
    GRANT USAGE ON SCHEMA public TO app_reader;
    GRANT SELECT ON security_events TO app_reader;

    CREATE OR REPLACE FUNCTION security_events_append_only_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'security_events is append-only';
    END;
    $$;

    DROP TRIGGER IF EXISTS security_events_no_update ON security_events;
    CREATE TRIGGER security_events_no_update
      BEFORE UPDATE ON security_events
      FOR EACH ROW EXECUTE FUNCTION security_events_append_only_guard();

    DROP TRIGGER IF EXISTS security_events_no_delete ON security_events;
    CREATE TRIGGER security_events_no_delete
      BEFORE DELETE ON security_events
      FOR EACH ROW EXECUTE FUNCTION security_events_append_only_guard();
  `,
};
