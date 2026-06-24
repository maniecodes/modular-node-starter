import { AppError } from '@/core/errors/AppError';
import { securityEvent } from '@/core/audit/security-events';
import { writeAuditLog } from '@/core/audit/audit-log.repository';
import { invalidateCachedContext } from '@/core/cache/user-context-cache';
import * as repo from '@/modules/roles/repositories/roles.repository';
import { CreatePermissionInput, CreateRoleInput } from '@/modules/roles/roles.types';
import { ParsedPagination } from '@/common/helpers/pagination';

// ─── Roles ────────────────────────────────────────────────────────────────────

export async function createRole(input: CreateRoleInput) {
  const existing = await repo.findRoleByName(input.name.toLowerCase());
  if (existing) throw new AppError(`Role '${input.name}' already exists`, 409);
  return repo.createRole(input);
}

export async function listRoles(pagination: ParsedPagination) {
  return repo.findAllRoles({ skip: pagination.skip, take: pagination.take });
}

export async function getRoleById(id: string) {
  const role = await repo.findRoleById(id);
  if (!role) throw new AppError('Role not found', 404);
  return {
    id: role.id,
    name: role.name,
    description: role.description,
    createdAt: role.createdAt,
    permissions: role.permissions.map((rp) => rp.permission),
  };
}

// ─── Permissions ──────────────────────────────────────────────────────────────

export async function createPermission(input: CreatePermissionInput) {
  const action = input.action.toLowerCase();
  const resource = input.resource.toLowerCase();
  const existing = await repo.findPermissionByKey(action, resource);
  if (existing) throw new AppError(`Permission '${resource}.${action}' already exists`, 409);
  return repo.createPermission({ ...input, action, resource });
}

export async function listPermissions() {
  return repo.findAllPermissions();
}

// ─── Role ↔ Permission assignments ───────────────────────────────────────────

export async function assignPermissionToRole(roleId: string, permissionId: string) {
  const [role, permission] = await Promise.all([
    repo.findRoleById(roleId),
    repo.findPermissionById(permissionId),
  ]);
  if (!role) throw new AppError('Role not found', 404);
  if (!permission) throw new AppError('Permission not found', 404);

  try {
    await repo.assignPermissionToRole(roleId, permissionId);
  } catch (err: unknown) {
    if ((err as { code?: string }).code === 'P2002') {
      throw new AppError('Permission already assigned to this role', 409);
    }
    throw err;
  }

  // Invalidate cache for all users who have this role so they see updated permissions immediately
  const userIds = await repo.findUserIdsByRoleId(roleId);
  userIds.forEach((uid) => invalidateCachedContext(uid));

  securityEvent('permission_assigned', { roleId, permissionId, roleName: role.name });
  writeAuditLog({
    event: 'permission_assigned',
    targetId: roleId,
    metadata: { roleId, permissionId, roleName: role.name },
  }).catch((err) => console.error('Audit log write failed:', err));
}

export async function revokePermissionFromRole(roleId: string, permissionId: string) {
  try {
    await repo.revokePermissionFromRole(roleId, permissionId);
  } catch (err: unknown) {
    if ((err as { code?: string }).code === 'P2025') {
      throw new AppError('Permission is not assigned to this role', 404);
    }
    throw err;
  }

  // Invalidate cache for all users who have this role
  const userIds = await repo.findUserIdsByRoleId(roleId);
  userIds.forEach((uid) => invalidateCachedContext(uid));

  securityEvent('permission_revoked', { roleId, permissionId });
  writeAuditLog({
    event: 'permission_revoked',
    targetId: roleId,
    metadata: { roleId, permissionId },
  }).catch((err) => console.error('Audit log write failed:', err));
}

// ─── User ↔ Role assignments ──────────────────────────────────────────────────

export async function assignRoleToUser(roleId: string, userId: string, assignedBy?: string) {
  const role = await repo.findRoleById(roleId);
  if (!role) throw new AppError('Role not found', 404);

  try {
    await repo.assignRoleToUser(userId, roleId, assignedBy);
  } catch (err: unknown) {
    if ((err as { code?: string }).code === 'P2002') {
      throw new AppError('Role already assigned to this user', 409);
    }
    throw err;
  }

  invalidateCachedContext(userId);

  securityEvent('role_assigned', { userId, roleId, roleName: role.name, assignedBy });
  writeAuditLog({
    event: 'role_assigned',
    actorId: assignedBy,
    targetId: userId,
    metadata: { roleId, roleName: role.name },
  }).catch((err) => console.error('Audit log write failed:', err));
}

export async function revokeRoleFromUser(roleId: string, userId: string) {
  try {
    await repo.revokeRoleFromUser(userId, roleId);
  } catch (err: unknown) {
    if ((err as { code?: string }).code === 'P2025') {
      throw new AppError('Role is not assigned to this user', 404);
    }
    throw err;
  }

  invalidateCachedContext(userId);

  securityEvent('role_revoked', { userId, roleId });
  writeAuditLog({
    event: 'role_revoked',
    targetId: userId,
    metadata: { roleId },
  }).catch((err) => console.error('Audit log write failed:', err));
}

export async function getUserRoles(userId: string) {
  const userRoles = await repo.findUserRoles(userId);
  return userRoles.map((ur) => ({ ...ur.role, assignedAt: ur.assignedAt }));
}

export async function getUserWithPermissions(userId: string) {
  const [userRoles, permissions] = await Promise.all([
    repo.findUserRoles(userId),
    repo.findUserPermissions(userId),
  ]);
  return {
    userId,
    roles: userRoles.map((ur) => ({ ...ur.role, assignedAt: ur.assignedAt })),
    permissions,
  };
}

export async function checkUserHasRole(userId: string, roleName: string) {
  const userRoles = await repo.findUserRoles(userId);
  return { hasRole: userRoles.some((ur) => ur.role.name === roleName) };
}

export async function checkUserHasPermission(userId: string, permission: string) {
  const permissions = await repo.findUserPermissions(userId);
  return { hasPermission: permissions.includes(permission) };
}

export async function getRolePermissions(roleId: string) {
  const role = await repo.findRoleById(roleId);
  if (!role) throw new AppError('Role not found', 404);
  return role.permissions.map((rp) => rp.permission);
}

export async function deleteRole(id: string) {
  const role = await repo.findRoleById(id);
  if (!role) throw new AppError('Role not found', 404);
  await repo.deleteRoleById(id);
}

export async function deletePermission(id: string) {
  const permission = await repo.findPermissionById(id);
  if (!permission) throw new AppError('Permission not found', 404);
  await repo.deletePermissionById(id);
}
