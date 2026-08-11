/*
  Warnings:

  - Added the required column `purpose` to the `otp_codes` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "OtpPurpose" AS ENUM ('REGISTRATION', 'PASSWORD_RESET');

-- DropIndex
DROP INDEX "otp_codes_target_type_idx";

-- AlterTable
ALTER TABLE "otp_codes" ADD COLUMN     "purpose" "OtpPurpose" NOT NULL,
ADD COLUMN     "requestedIp" TEXT,
ADD COLUMN     "requestedUserAgent" TEXT;

-- CreateIndex
CREATE INDEX "otp_codes_target_type_purpose_idx" ON "otp_codes"("target", "type", "purpose");
