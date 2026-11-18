\pset pager off
\set ON_ERROR_STOP on
DO $$
DECLARE
  keep text[] := ARRAY['alembic_version','organizations','users','organization_members',
                       'api_keys','user_sessions','platform_settings','platform_secrets',
                       'ai_providers','ai_prompts','ai_settings','kev_entries',
                       'kev_feed_state','epss_scores','trivy_db_updates','mfa_challenges',
                       'mfa_recovery_codes','oidc_states','device_authorizations'];
  stmt text;
BEGIN
  SELECT 'TRUNCATE TABLE ' || string_agg(format('%I', tablename), ', ') || ' CASCADE'
    INTO stmt
    FROM pg_tables
   WHERE schemaname = 'public'
     AND tablename <> ALL (keep);
  RAISE NOTICE 'tables: %', (SELECT count(*) FROM pg_tables
                              WHERE schemaname='public' AND tablename <> ALL (keep));
  RAISE NOTICE 'statement length: %', length(stmt);
  RAISE NOTICE 'first 300: %', left(stmt, 300);
END
$$;
