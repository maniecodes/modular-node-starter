import { prisma } from '@/core/database/prisma';
import { CreatePermissionInput, CreateRoleInput } from '../roles.types';

// ─── Roles ────────────────────────────────────────────────────────────────────

export async function createRole(data: CreateRoleInput) {
  return prisma.role.create({
    data: { name: data.name.toLowerCase(), description: data.description },
    select: { id: true, name: true, description: true, createdAt: true },
  });
}

export async function findAllRoles() {
  return prisma.role.findMany({
    select: { id: true, name: true, description: true, createdAt: true },
    orderBy: { name: 'asc' },
  });
}

export async function findRoleById(id: string) {
  return prisma.role.findUnique({
    where: { id },
    select: {
      id: true,
      name: true,
      description: true,
      createdAt: true,
      permissions: {
        select: {
          permission: {
            select: {
              id: true,
              action: true,
              resource: true,
              description: true,
              createdAt: true,
            },
          },
        },
      },
    },
  });
}

export async function findRoleByName(name: string) {
  return prisma.role.findUnique({
    where: { name },
    select: { id: true, name: true },
  });
}

// ─── Permissions ──────────────────────────────────────────────────────────────

export async function createPermission(data: CreatePermissionInput) {
  return prisma.permission.create({
    data: {
      action: data.action.toLowerCase(),
      resource: data.resource.toLowerCase(),
      description: data.description,
    },
    select: { id: true, action: true, resource: true, description: true, createdAt: true },
  });
}

export async function findAllPermissions() {
  return prisma.permission.findMany({
    select: { id: true, action: true, resource: true, description: true, createdAt: true },
    orderBy: [{ resource: 'asc' }, { action: 'asc' }],
  });
}

export async function findPermissionById(id: string) {
  return prisma.permission.findUnique({
    where: { id },
    select: { id: true, action: true, resource: true },
  });
}

export async function findPermissionByKey(action: string, resource: string) {
  return prisma.permission.findUnique({
    where: { action_resource: { action, resource } },
    select: { id: true },
  });
}

// ─── Role ↔ Permission assignments ───────────────────────────────────────────

export async function assignPermissionToRole(roleId: string, permissionId: string) {
  return prisma.rolePermission.create({ data: { roleId, permissionId } });
}

export async function revokePermissionFromRole(roleId: string, permissionId: string) {
  return prisma.rolePermission.delete({
    where: { roleId_permissionId: { roleId, permissionId } },
  });
}

// ─── User ↔ Role assignments ──────────────────────────────────────────────────

export async function assignRoleToUser(userId: string, roleId: string, assignedBy?: string) {
  return prisma.userRole.create({ data: { userId, roleId, assignedBy } });
}

export async function revokeRoleFromUser(userId: string, roleId: string) {
  return prisma.userRole.delete({
    where: { userId_roleId: { userId, roleId } },
  });
}

export async function findUserRoles(userId: string) {
  return prisma.userRole.findMany({
    where: { userId },
    select: {
      assignedAt: true,
      role: { select: { id: true, name: true, description: true, createdAt: true } },
    },
  });
}

export async function findUserPermissions(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: {
          permissions: {
            select: {
              permission: { select: { action: true, resource: true } },
            },
          },
        },
      },
    },
  });
  return [
    ...new Set(
      userRoles.flatMap((ur) =>
        ur.role.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];
}

export async function findUserIdsByRoleId(roleId: string): Promise<string[]> {
  const records = await prisma.userRole.findMany({
    where: { roleId },
    select: { userId: true },
  });
  return records.map((r) => r.userId);
}


export async function deleteRoleById(id: string) {
  return prisma.role.delete({ where: { id } });
}

export async function deletePermissionById(id: string) {
  return prisma.permission.delete({ where: { id } });
}
