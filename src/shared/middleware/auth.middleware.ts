// src/shared/middleware/auth.middleware.ts
import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '@/config/env';
import { AppError } from '@/shared/middleware/error.middleware';
import { AuthenticatedRequest } from '@/shared/types';

interface JwtPayload {
  sub: string;
  email: string;
  iat?: number;
  exp?: number;
}

export function requireAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    throw new AppError('Missing or invalid Authorization header', 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, env.JWT_SECRET) as JwtPayload;
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch {
    throw new AppError('Invalid or expired token', 401);
  }
}


