import { Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { verifyAccessToken } from './jwt';
import { AuthenticatedRequest } from '@/common/types';

export function requireAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    throw new AppError('Missing or invalid Authorization header', 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = verifyAccessToken(token);
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch {
    throw new AppError('Invalid or expired token', 401);
  }
}
