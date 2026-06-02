// src/modules/auth/auth.service.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '@/config/database';
import { env } from '@/config/env';
import { AppError } from '@/shared/middleware/error.middleware';
import { AuthUser, LoginInput, RegisterInput, TokenPair } from './auth.types';

function generateTokenPair(user: AuthUser): TokenPair {
  const payload = { email: user.email};

  const accessToken = jwt.sign(payload, env.JWT_SECRET, {
    subject: user.id,
    expiresIn: env.JWT_EXPIRES_IN,
  } as jwt.SignOptions);

  const refreshToken = jwt.sign({}, env.JWT_REFRESH_SECRET, {
    subject: user.id,
    expiresIn: env.JWT_REFRESH_EXPIRES_IN,
  } as jwt.SignOptions);

  return { accessToken, refreshToken };
}

export async function register(
  input: RegisterInput,
): Promise<{ user: AuthUser; tokens: TokenPair }> {
  const existing = await prisma.user.findUnique({ where: { email: input.email } });
  if (existing) {
    throw new AppError('Email is already in use', 409);
  }

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);

  const user = await prisma.user.create({
    data: { name: input.name, email: input.email, password: hashedPassword },
    select: { id: true, name: true, email: true },
  });

  const tokens = generateTokenPair(user);
  return { user, tokens };
}

export async function login(input: LoginInput): Promise<{ user: AuthUser; tokens: TokenPair }> {
  const user = await prisma.user.findUnique({
    where: { email: input.email },
    select: { id: true, name: true, email: true, password: true },
  });

  if (!user) {
    throw new AppError('Invalid credentials', 401);
  }

  const isPasswordValid = await bcrypt.compare(input.password, user.password);
  if (!isPasswordValid) {
    throw new AppError('Invalid credentials', 401);
  }

  const { password: _password, ...safeUser } = user;
  const tokens = generateTokenPair(safeUser);
  return { user: safeUser, tokens };
}

export async function refreshTokens(token: string): Promise<TokenPair> {
  let payload: jwt.JwtPayload;

  try {
    payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    select: { id: true, name: true, email: true },
  });

  if (!user) {
    throw new AppError('User not found', 401);
  }

  return generateTokenPair(user);
}
