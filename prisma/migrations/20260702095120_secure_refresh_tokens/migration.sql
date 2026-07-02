-- Step 1: add new columns (familyId nullable so existing rows are unaffected)
ALTER TABLE "refresh_tokens"
  ADD COLUMN "familyId"           TEXT,
  ADD COLUMN "requestedIp"        TEXT,
  ADD COLUMN "requestedUserAgent" TEXT,
  ADD COLUMN "usedAt"             TIMESTAMP(3);

-- Step 2: backfill every existing row with its own unique family ID
UPDATE "refresh_tokens" SET "familyId" = gen_random_uuid()::text WHERE "familyId" IS NULL;

-- Step 3: now safe to enforce NOT NULL
ALTER TABLE "refresh_tokens" ALTER COLUMN "familyId" SET NOT NULL;

-- CreateIndex
CREATE INDEX "refresh_tokens_familyId_idx" ON "refresh_tokens"("familyId");
