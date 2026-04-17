-- Migration: enforce tenant attribution at the database level.
--
-- Wave 1 added proof_drills.user_id as a nullable column and the /api/history
-- and /api/proof handlers carried an `OR user_id IS NULL` bridge so scans
-- produced before Wave 1 rolled out would keep appearing. Wave 3b removes
-- that bridge and requires every row to be attributable to a user. The
-- matching database-level guarantee is this NOT NULL constraint so the
-- handlers can rely on user_id being present without a defensive fallback.
--
-- Safety: we verified that proof_drills contains no NULL-user_id rows
-- before shipping this migration (the table was truncated during Wave 3a
-- testing, and the staging / prod deployments do not carry legacy data).
-- If you are running this against a DB that still has Wave-1-era rows,
-- either delete them or run `UPDATE proof_drills SET user_id = '<admin>'
-- WHERE user_id IS NULL` first, otherwise this ALTER will fail.

ALTER TABLE proof_drills ALTER COLUMN user_id SET NOT NULL;
