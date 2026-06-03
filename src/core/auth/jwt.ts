import jwt from 'jsonwebtoken';
import { env } from '@/core/config/env';

export interface AccessTokenPayload {
  sub: string;
  email: string;
}

export function signAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign({ email: payload.email }, env.JWT_SECRET, {
    subject: payload.sub,
    expiresIn: env.JWT_EXPIRES_IN,
  } as jwt.SignOptions);
}

export function signRefreshToken(userId: string): string {
  return jwt.sign({}, env.JWT_REFRESH_SECRET, {
    subject: userId,
    expiresIn: env.JWT_REFRESH_EXPIRES_IN,
  } as jwt.SignOptions);
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  const payload = jwt.verify(token, env.JWT_SECRET) as jwt.JwtPayload;
  return { sub: payload.sub!, email: payload.email as string };
}

export function verifyRefreshToken(token: string): { sub: string; exp: number } {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;
  return { sub: payload.sub!, exp: payload.exp! };
}
