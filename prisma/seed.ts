/**
 * Seeds default roles and permissions.
 * Run once after first migration: npm run db:seed
 *
 * Roles created:
 *   user - standard authenticated user (read/update/delete own data)
 *   super_admin - full access to all resources
 */
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import bcrypt from 'bcryptjs';
import * as dotenv from 'dotenv';

dotenv.config();

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

const PERMISSIONS = [
  { action: 'create', resource: 'users' },
  { action: 'read', resource: 'users' },
  { action: 'update', resource: 'users' },
  { action: 'delete', resource: 'users' },
  { action: 'create', resource: 'roles' },
  { action: 'read', resource: 'roles' },
  { action: 'update', resource: 'roles' },
  { action: 'delete', resource: 'roles' },
  { action: 'assign', resource: 'roles' },
  { action: 'create', resource: 'permissions' },
  { action: 'read', resource: 'permissions' },
  { action: 'delete', resource: 'permissions' },
];

const ROLE_PERMISSIONS: Record<string, string[]> = {
  user: ['users.read', 'users.update', 'users.delete'],
  super_admin: PERMISSIONS.map((p) => `${p.resource}.${p.action}`),
};

async function main() {
  console.log('Seeding roles and permissions...\n');

  const created = await Promise.all(
    PERMISSIONS.map((p) =>
      prisma.permission.upsert({
        where: { action_resource: { action: p.action, resource: p.resource } },
        update: {},
        create: p,
      }),
    ),
  );

  const permMap = new Map(created.map((p) => [`${p.resource}.${p.action}`, p.id]));
  console.log(`  ${created.length} permissions upserted`);

  const roleMap = new Map<string, string>();
  for (const [roleName, permKeys] of Object.entries(ROLE_PERMISSIONS)) {
    const role = await prisma.role.upsert({
      where: { name: roleName },
      update: {},
      create: { name: roleName },
    });
    roleMap.set(roleName, role.id);

    await Promise.all(
      permKeys
        .filter((key) => permMap.has(key))
        .map((key) => {
          const permId = permMap.get(key)!;
          return prisma.rolePermission.upsert({
            where: { roleId_permissionId: { roleId: role.id, permissionId: permId } },
            update: {},
            create: { roleId: role.id, permissionId: permId },
          });
        }),
    );

    console.log(`  '${roleName}' role - ${permKeys.length} permissions assigned`);
  }

  const superAdminEmail = process.env.SUPER_ADMIN_EMAIL?.toLowerCase();
  const superAdminPassword = process.env.SUPER_ADMIN_PASSWORD;
  const superAdminFirstName = process.env.SUPER_ADMIN_FIRST_NAME;
  const superAdminLastName = process.env.SUPER_ADMIN_LAST_NAME;
  const superAdminPhone = process.env.SUPER_ADMIN_PHONE || undefined;

  if (!superAdminEmail || !superAdminPassword || !superAdminFirstName || !superAdminLastName) {
    throw new Error(
      'SUPER_ADMIN_EMAIL, SUPER_ADMIN_PASSWORD, SUPER_ADMIN_FIRST_NAME, and SUPER_ADMIN_LAST_NAME are required in environment to seed super admin',
    );
  }

  const hashedPassword = await bcrypt.hash(superAdminPassword, 12);
  const superAdmin = await prisma.user.upsert({
    where: { email: superAdminEmail },
    update: {
      firstName: superAdminFirstName,
      lastName: superAdminLastName,
      phone: superAdminPhone,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: false,
    },
    create: {
      firstName: superAdminFirstName,
      lastName: superAdminLastName,
      email: superAdminEmail,
      phone: superAdminPhone,
      password: hashedPassword,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: false,
    },
  });

  const superAdminRoleId = roleMap.get('super_admin');
  if (!superAdminRoleId) {
    throw new Error('super_admin role not found after seeding roles');
  }

  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: superAdmin.id,
        roleId: superAdminRoleId,
      },
    },
    update: {},
    create: {
      userId: superAdmin.id,
      roleId: superAdminRoleId,
      assignedBy: superAdmin.id,
    },
  });

  console.log(`  super_admin user seeded (${superAdminEmail}) and role assigned`);
  console.log('\nSeeding complete.');
}

void (async () => {
  try {
    await main();
  } catch (err) {
    console.error(err);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
})();
