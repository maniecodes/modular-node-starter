import { Response } from 'express';
import { AuthenticatedRequest } from '@/common/types';
import { sendSuccess, sendCreated, sendNoContent, sendPaginatedSuccess } from '@/common/helpers/response';
import { parsePaginationQuery, buildPaginatedResponse } from '@/common/helpers/pagination';
import * as service from '../services/roles.service';
import { withPagination } from '@/common/helpers/paginated-handler';
import { AppError } from '@/core/errors/AppError';

// Roles

export async function createRoleHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const role = await service.createRole(req.body);
  sendCreated(res, role, 'Role created');
}

export const listRolesHandler = withPagination(
  (pagination) => service.listRoles(pagination),
  'Retrieved all roles',
);

export async function getRoleHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const role = await service.getRoleById(req.params.id as string);
  sendSuccess(res, role);
}

// Permissions

export async function createPermissionHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  const permission = await service.createPermission(req.body);
  sendCreated(res, permission, 'Permission created');
}

export const listPermissionsHandler = withPagination(
  (pagination) => service.listPermissions(pagination),
  'Retrieved all permissions',
);

// Role <-> Permission assignments

export async function assignPermissionHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  await service.assignPermissionToRole(req.params.id as string, req.body.permissionId);
  sendSuccess(res, null, 'Permission assigned to role');
}

export async function revokePermissionHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  await service.revokePermissionFromRole(
    req.params.id as string,
    req.params.permissionId as string,
  );
  sendNoContent(res);
}

// User <-> Role assignments

export async function assignRoleToUserHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  await service.assignRoleToUser(req.params.id as string, req.body.userId, req.user?.id);
  sendSuccess(res, null, 'Role assigned to user');
}

export async function revokeRoleFromUserHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  await service.revokeRoleFromUser(req.params.id as string, req.params.userId as string);
  sendNoContent(res);
}

export async function getUserRolesHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const roles = await service.getUserRoles(req.params.userId as string);
  sendSuccess(res, roles);
}

export async function getUserWithPermissionsHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  const result = await service.getUserWithPermissions(req.params.userId as string);
  sendSuccess(res, result);
}

export async function checkUserRoleHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  const result = await service.checkUserHasRole(
    req.params.userId as string,
    req.params.roleName as string,
  );
  sendSuccess(res, result);
}

export async function checkUserPermissionHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  const permission = req.query.key as string;
  if (!permission) {
    sendSuccess(res, { hasPermission: false });
    return;
  }
  const result = await service.checkUserHasPermission(req.params.userId as string, permission);
  sendSuccess(res, result);
}

export const getRolePermissionsHandler = withPagination(
  (pagination, req) => service.getRolePermissions(req.params.id as string, pagination),
  'Retrieved all permissions for the role',
);

export async function deleteRoleHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  await service.deleteRole(req.params.id as string);
  sendNoContent(res);
}

export async function deletePermissionHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  await service.deletePermission(req.params.id as string);
  sendNoContent(res);
}
