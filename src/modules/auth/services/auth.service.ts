import bcrypt from 'bcryptjs';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import * as authRepository from '../repositories/auth.repository';
import { AuthUser, LoginInput, RegisterInput, TokenPair } from '../auth.types';

function buildTokenPair(user: AuthUser): TokenPair {
  return {
    accessToken: signAccessToken({ sub: user.id, email: user.email }),
    refreshToken: signRefreshToken(user.id),
  };
}

export async function register(
  input: RegisterInput,
): Promise<{ user: AuthUser; tokens: TokenPair }> {
  const existing = await authRepository.findUserByEmail(input.email);
  if (existing) throw new AppError('Email is already in use', 409);

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);
  const user = await authRepository.createUser({
    name: input.name,
    email: input.email,
    password: hashedPassword,
  });

  return { user, tokens: buildTokenPair(user) };
}

export async function login(input: LoginInput): Promise<{ user: AuthUser; tokens: TokenPair }> {
  const user = await authRepository.findUserByEmail(input.email);
  if (!user) throw new AppError('Invalid credentials', 401);

  const isValid = await bcrypt.compare(input.password, user.password);
  if (!isValid) throw new AppError('Invalid credentials', 401);

  const { password: _password, ...safeUser } = user;
  return { user: safeUser, tokens: buildTokenPair(safeUser) };
}

export async function refreshTokens(token: string): Promise<TokenPair> {
  let payload: { sub: string };

  try {
    payload = verifyRefreshToken(token);
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  const user = await authRepository.findUserById(payload.sub);
  if (!user) throw new AppError('User not found', 401);

  return buildTokenPair(user);
}
