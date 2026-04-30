-- 0015_apps_invite_url_template.sql
--
-- Per-app invite URL template (Section 8, issue #22).
--
-- Tarn ships no hosted landing page for invite tokens — apps own the URL
-- surface. This column records each app's URL template; the SDK substitutes
-- `{token_id}` and appends `#<base64url(payload_key)>` to build the shareable
-- link. Set at app onboarding (manually in v1; no developer-portal flow).

ALTER TABLE apps ADD COLUMN invite_url_template TEXT;
