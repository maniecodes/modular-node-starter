-- AlterTable
ALTER TABLE "role_permissions" ADD COLUMN     "userInviteId" TEXT;

-- AlterTable
ALTER TABLE "user_roles" ADD COLUMN     "userInviteId" TEXT;

-- CreateTable
CREATE TABLE "UserInvite" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserInvite_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_invite_roles" (
    "inviteId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,

    CONSTRAINT "user_invite_roles_pkey" PRIMARY KEY ("inviteId","roleId")
);

-- CreateIndex
CREATE UNIQUE INDEX "UserInvite_tokenHash_key" ON "UserInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "UserInvite_email_idx" ON "UserInvite"("email");

-- AddForeignKey
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_userInviteId_fkey" FOREIGN KEY ("userInviteId") REFERENCES "UserInvite"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_userInviteId_fkey" FOREIGN KEY ("userInviteId") REFERENCES "UserInvite"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_invite_roles" ADD CONSTRAINT "user_invite_roles_inviteId_fkey" FOREIGN KEY ("inviteId") REFERENCES "UserInvite"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_invite_roles" ADD CONSTRAINT "user_invite_roles_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;
