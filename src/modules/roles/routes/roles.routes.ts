import { Router, Response, NextFunction } from 'express';
import { requireAuth } from '@/core/middleware/auth.middleware';
import { authorize } from '@/modules/access-control/middleware';
import { validate } from '@/core/middleware/validate.middleware';
import {
  createRoleSchema,
  createPermissionSchema,
  assignPermissionSchema,
  assignRoleSchema,
} from '../validators/roles.validator';
import {
  createRoleHandler,
  listRolesHandler,
  getRoleHandler,
  getRolePermissionsHandler,
  deleteRoleHandler,
  createPermissionHandler,
  listPermissionsHandler,
  deletePermissionHandler,
  assignPermissionHandler,
  revokePermissionHandler,
  assignRoleToUserHandler,
  revokeRoleFromUserHandler,
  getUserRolesHandler,
  getUserWithPermissionsHandler,
  checkUserRoleHandler,
  checkUserPermissionHandler,
} from '../controllers/roles.controller';
import { AuthenticatedRequest } from '@/common/types';

type AuthHandler = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => Promise<void>;

const wrap =
  (fn: AuthHandler) =>
    (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
      fn(req, res, next).catch(next);
    };

// Roles router
// Mounted at /api/v1/roles
//
// NOTE: /users/* routes are registered BEFORE /:id routes to prevent Express
// from matching the literal string \users\ as the :id param.

export const rolesRouter = Router();

rolesRouter.use(requireAuth);

// Collection
rolesRouter.get('/', authorize('roles.read'), wrap(listRolesHandler));
rolesRouter.post('/', authorize('roles.create'), validate(createRoleSchema), wrap(createRoleHandler));

// User-scoped — must be BEFORE /:id
rolesRouter.get('/users/:userId', authorize('roles.read'), wrap(getUserWithPermissionsHandler));
rolesRouter.get('/users/:userId/roles', authorize('roles.read'), wrap(getUserRolesHandler));
rolesRouter.get('/users/:userId/has-role/:roleName', authorize('roles.read'), wrap(checkUserRoleHandler));
rolesRouter.get('/users/:userId/has-permission', authorize('roles.read'), wrap(checkUserPermissionHandler));

// Single role
rolesRouter.get('/:id', authorize('roles.read'), wrap(getRoleHandler));
rolesRouter.delete('/:id', authorize('roles.delete'), wrap(deleteRoleHandler));
rolesRouter.get('/:id/permissions', authorize('roles.read'), wrap(getRolePermissionsHandler));

// Role <-> Permission
rolesRouter.post('/:id/permissions', authorize('roles.update'), validate(assignPermissionSchema), wrap(assignPermissionHandler));
rolesRouter.delete('/:id/permissions/:permissionId', authorize('roles.update'), wrap(revokePermissionHandler));

// Role <-> User
rolesRouter.post('/:id/users', authorize('roles.assign'), validate(assignRoleSchema), wrap(assignRoleToUserHandler));
rolesRouter.delete('/:id/users/:userId', authorize('roles.assign'), wrap(revokeRoleFromUserHandler));

// Permissions router
// Mounted at /api/v1/permissions

export const permissionsRouter = Router();

permissionsRouter.use(requireAuth);

permissionsRouter.get('/', authorize('permissions.read'), wrap(listPermissionsHandler));
permissionsRouter.post('/', authorize('permissions.create'), validate(createPermissionSchema), wrap(createPermissionHandler));
permissionsRouter.delete('/:id', authorize('permissions.delete'), wrap(deletePermissionHandler));
