-- Wipe the demo estate. Identity, settings and intel feeds stay.
--
-- Every table in `public` that is not in `keep` is truncated in one statement
-- with CASCADE, so foreign keys are not an ordering problem. One transaction:
-- either the estate is empty or nothing changed.
BEGIN;

DO $$
DECLARE
  keep text[] := ARRAY[
    'alembic_version', 'organizations', 'users', 'organization_members',
    'api_keys', 'user_sessions', 'platform_settings', 'platform_secrets',
    'ai_providers', 'ai_prompts', 'ai_settings', 'kev_entries',
    'kev_feed_state', 'epss_scores', 'trivy_db_updates', 'mfa_challenges',
    'mfa_recovery_codes', 'oidc_states', 'device_authorizations'
  ];
  stmt text;
BEGIN
  SELECT 'TRUNCATE TABLE ' || string_agg(format('%I', tablename), ', ') || ' CASCADE'
    INTO stmt
    FROM pg_tables
   WHERE schemaname = 'public'
     AND tablename <> ALL (keep);
  IF stmt IS NULL THEN
    RAISE NOTICE 'nothing to truncate';
  ELSE
    RAISE NOTICE 'truncating % tables', (SELECT count(*) FROM pg_tables
                                          WHERE schemaname = 'public'
                                            AND tablename <> ALL (keep));
    EXECUTE stmt;
  END IF;
END
$$;

COMMIT;
