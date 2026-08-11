import { Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { AuthenticatedRequest } from '@/common/types';

export function requireRole(...roles: string[]) {
  return (req: AuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw new AppError('Unauthenticated', 401);
    }
    if (roles.length > 0) {
      const userRoles = req.user.roles ?? [];
      const hasRole = roles.some((r) => userRoles.includes(r));
      if (!hasRole) throw new AppError('Forbidden', 403);
    }
    next();
  };
}

export function authorize(permission: string) {
  return (req: AuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) throw new AppError('Unauthenticated', 401);
    if (!req.user.permissions?.includes(permission)) {
      throw new AppError(`Forbidden — missing permission: ${permission}`, 403);
    }
    next();
  };
}
