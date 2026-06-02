/**
 * Seeds default roles and permissions.
 * Run once after first migration: npm run db:seed
 *
 * Roles created:
 *   user  — standard authenticated user (read/update/delete own data)
 *   admin — full access to all resources
 */
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
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

  // Upsert all permissions
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
  console.log(`  ✓ ${created.length} permissions upserted`);

  // Upsert roles and wire up their permissions
  for (const [roleName, permKeys] of Object.entries(ROLE_PERMISSIONS)) {
    const role = await prisma.role.upsert({
      where: { name: roleName },
      update: {},
      create: { name: roleName },
    });

    await Promise.all(
      permKeys.map((key) => {
        const permId = permMap.get(key);
        if (!permId) return Promise.resolve();
        return prisma.rolePermission.upsert({
          where: { roleId_permissionId: { roleId: role.id, permissionId: permId } },
          update: {},
          create: { roleId: role.id, permissionId: permId },
        });
      }),
    );

    console.log(`  ✓ '${roleName}' role — ${permKeys.length} permissions assigned`);
  }

  console.log('\nSeeding complete.');
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
