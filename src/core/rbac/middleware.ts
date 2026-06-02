import { Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { AuthenticatedRequest } from '@/common/types';

export function requireRole(...roles: string[]) {
  return (req: AuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw new AppError('Unauthenticated', 401);
    }
    if (roles.length > 0 && !roles.includes(req.user.role ?? '')) {
      throw new AppError('Forbidden', 403);
    }
    next();
  };
}
