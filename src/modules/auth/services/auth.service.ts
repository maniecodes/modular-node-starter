import bcrypt from 'bcryptjs';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import * as authRepository from '../repositories/auth.repository';
import { AuthResult, AuthUser, LoginInput, RegisterInput, TokenPair } from '../auth.types';

/**
 * Signs a refresh token, stores its hash in DB, and returns the token string.
 * expiresIn is the JWT `exp` unix timestamp returned by verifyRefreshToken.
 */
async function issueRefreshToken(userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = signRefreshToken(userId);
  // Decode our own token to get the canonical expiry — avoids duplicating the
  // env.JWT_REFRESH_EXPIRES_IN parsing logic here.
  const { exp } = verifyRefreshToken(token);
  const expiresAt = new Date(exp * 1000);
  await authRepository.storeRefreshToken(userId, token, expiresAt);
  return { token, expiresAt };
}

function buildSafeUser(user: { id: string; name: string; email: string }): AuthUser {
  return { id: user.id, name: user.name, email: user.email };
}

export async function register(input: RegisterInput): Promise<AuthResult> {
  const existing = await authRepository.findUserByEmail(input.email);
  if (existing) throw new AppError('Email is already in use', 409);

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);

  const user = await authRepository.createUser({
    name: input.name,
    email: input.email,
    password: hashedPassword,
  });

  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email });

  return { user: buildSafeUser(user), tokens: { accessToken, refreshToken } };
}

export async function login(input: LoginInput): Promise<AuthResult> {
  const user = await authRepository.findUserByEmail(input.email);

  // Intentionally vague — don't reveal whether the email exists
  if (!user) throw new AppError('Invalid credentials', 401);

  if (!user.isActive) throw new AppError('Account is deactivated', 403);

  const isValid = await bcrypt.compare(input.password, user.password);
  if (!isValid) throw new AppError('Invalid credentials', 401);

  const safeUser = buildSafeUser(user);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

export async function refreshTokens(rawToken: string): Promise<TokenPair> {
  // 1. Verify JWT signature first — cheap, no DB hit
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawToken);
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  // 2. Consume the token from DB — atomic delete prevents replay
  const record = await authRepository.consumeRefreshToken(rawToken);
  if (!record) throw new AppError('Refresh token has already been used or revoked', 401);

  // 3. Verify the user is still valid
  const user = await authRepository.findUserById(payload.sub);
  if (!user) throw new AppError('User not found', 401);
  if (!user.isActive) throw new AppError('Account is deactivated', 403);

  // 4. Issue a new pair (rotation: old token is already deleted)
  const { token: newRefreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email });

  return { accessToken, refreshToken: newRefreshToken };
}

/** Revokes a single refresh token. Safe to call even if the token is already gone. */
export async function logout(rawToken: string): Promise<void> {
  // Validate the token structure first, but ignore expiry — a user should be
  // able to log out even with an expired token sitting in their client.
  try {
    verifyRefreshToken(rawToken);
  } catch (err: unknown) {
    // Allow logout even for expired tokens — just not for malformed ones
    const message = err instanceof Error ? err.message : '';
    if (!message.includes('expired')) {
      throw new AppError('Invalid refresh token', 400);
    }
  }
  await authRepository.revokeRefreshToken(rawToken);
}
