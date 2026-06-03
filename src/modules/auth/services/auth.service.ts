import bcrypt from 'bcryptjs';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import { securityEvent } from '@/core/audit/security-events';
import { isLocked, recordFailedAttempt, clearAttempts } from '@/core/auth/login-protection';
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

  securityEvent('register_success', { userId: user.id, email: user.email });

  return { user: buildSafeUser(user), tokens: { accessToken, refreshToken } };
}

export async function login(input: LoginInput): Promise<AuthResult> {
  // Check lockout before touching the DB — avoids unnecessary load under brute-force
  if (isLocked(input.email)) {
    securityEvent('login_locked', { email: input.email });
    throw new AppError('Too many failed login attempts. Please try again later.', 429);
  }

  const user = await authRepository.findUserByEmail(input.email);

  if (!user) {
    recordFailedAttempt(input.email);
    securityEvent('login_failure', { email: input.email, reason: 'user_not_found' });
    throw new AppError('Invalid credentials', 401);
  }

  if (!user.isActive) {
    securityEvent('login_failure', {
      email: input.email,
      userId: user.id,
      reason: 'account_deactivated',
    });
    throw new AppError('Account is deactivated', 403);
  }

  const isValid = await bcrypt.compare(input.password, user.password);
  if (!isValid) {
    recordFailedAttempt(input.email);
    securityEvent('login_failure', {
      email: input.email,
      userId: user.id,
      reason: 'wrong_password',
    });
    throw new AppError('Invalid credentials', 401);
  }

  clearAttempts(input.email);

  const safeUser = buildSafeUser(user);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email });

  securityEvent('login_success', { userId: user.id, email: user.email });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

export async function refreshTokens(rawToken: string): Promise<TokenPair> {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawToken);
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  const record = await authRepository.consumeRefreshToken(rawToken);
  if (!record) {
    securityEvent('refresh_replay_denied', { userId: payload.sub });
    throw new AppError('Refresh token has already been used or revoked', 401);
  }

  const user = await authRepository.findUserById(payload.sub);
  if (!user) throw new AppError('User not found', 401);
  if (!user.isActive) throw new AppError('Account is deactivated', 403);

  const { token: newRefreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email });

  securityEvent('refresh_success', { userId: user.id });

  return { accessToken, refreshToken: newRefreshToken };
}

export async function logout(rawToken: string): Promise<void> {
  try {
    verifyRefreshToken(rawToken);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : '';
    if (!message.includes('expired')) {
      throw new AppError('Invalid refresh token', 400);
    }
  }
  await authRepository.revokeRefreshToken(rawToken);
  securityEvent('logout_success', {});
}
