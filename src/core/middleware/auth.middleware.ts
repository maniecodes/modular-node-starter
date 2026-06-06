import { Request, Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { verifyAccessToken } from '../auth/jwt';
import { AuthenticatedRequest } from '@/common/types';
import { loadUserContext } from '../auth/user-context';

export async function requireAuth(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    throw new AppError('Missing or invalid Authorization header', 401);
  }

  const token = authHeader.slice(7);

  let payload: { sub: string; email?: string; phone?: string };
  try {
    payload = verifyAccessToken(token);
  } catch {
    throw new AppError('Invalid or expired token', 401);
  }

  const context = await loadUserContext(payload.sub);
  if (!context) throw new AppError('User not found', 401);
  if (!context.isActive) throw new AppError('Account is deactivated', 403);

  (req as AuthenticatedRequest).user = {
    id: context.id,
    email: context.email ?? undefined,
    phone: context.phone ?? undefined,
    roles: context.roles,
    permissions: context.permissions,
  };
  next();
}
