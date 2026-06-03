import bcrypt from 'bcryptjs';
import { AppError } from '@/core/errors/AppError';
import * as authService from '../services/auth.service';
import * as authRepository from '../repositories/auth.repository';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';

// Mock at the repository boundary — service tests must not know Prisma internals
jest.mock('../repositories/auth.repository');
// Mock JWT utility functions directly — avoids reimplementing crypto in tests
jest.mock('@/core/auth/jwt');
jest.mock('bcryptjs');

const mockRepo = authRepository as jest.Mocked<typeof authRepository>;
const mockSignAccess = signAccessToken as jest.MockedFunction<typeof signAccessToken>;
const mockSignRefresh = signRefreshToken as jest.MockedFunction<typeof signRefreshToken>;
const mockVerifyRefresh = verifyRefreshToken as jest.MockedFunction<typeof verifyRefreshToken>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

const sampleUser = { id: 'user-1', name: 'Alice', email: 'alice@example.com' };
const dbUserWithPassword = { ...sampleUser, password: 'hashed', isActive: true };
const futureExp = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;

const tokenRecord = {
  id: 'rt-1',
  userId: 'user-1',
  tokenHash: 'abc123',
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  createdAt: new Date(),
};

/** Sets up the mocks needed for issueRefreshToken (called inside register/login/refreshTokens). */
function mockIssueRefreshToken(refreshTokenValue = 'refresh-token') {
  mockSignRefresh.mockReturnValueOnce(refreshTokenValue);
  mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
  mockRepo.storeRefreshToken.mockResolvedValueOnce(undefined as never);
}

beforeEach(() => jest.clearAllMocks());

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
describe('authService.register', () => {
  it('throws 409 when email already exists', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);

    await expect(
      authService.register({ name: 'Alice', email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Email is already in use', 409));
  });

  it('hashes the password before storing', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockRepo.createUser.mockResolvedValueOnce(sampleUser as never);
    mockIssueRefreshToken();
    mockSignAccess.mockReturnValueOnce('access');

    await authService.register({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Password1',
    });

    expect(mockBcrypt.hash).toHaveBeenCalledWith('Password1', expect.any(Number));
  });

  it('returns user and token pair on success', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockRepo.createUser.mockResolvedValueOnce(sampleUser as never);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.register({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Password1',
    });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.user).not.toHaveProperty('password');
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });
});

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
describe('authService.login', () => {
  it('throws 401 when user not found', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('throws 403 when account is deactivated', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isActive: false,
    } as never);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Account is deactivated', 403));
  });

  it('throws 401 for wrong password', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'wrong' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('returns user (without password) and tokens on valid credentials', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.user).not.toHaveProperty('password');
    expect(result.user).not.toHaveProperty('isActive');
    expect(result.tokens.accessToken).toBe('access');
  });

  it('stores a new refresh token in the DB on successful login', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(mockRepo.storeRefreshToken).toHaveBeenCalledWith('user-1', 'refresh', expect.any(Date));
  });
});

// ---------------------------------------------------------------------------
// refreshTokens
// ---------------------------------------------------------------------------
describe('authService.refreshTokens', () => {
  it('throws 401 for an invalid refresh token (bad signature)', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('invalid signature');
    });

    await expect(authService.refreshTokens('bad-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 for an expired refresh token', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('jwt expired');
    });

    await expect(authService.refreshTokens('expired-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when the token has already been consumed (replay prevention)', async () => {
    // JWT is cryptographically valid but was already used — consumeRefreshToken returns null
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('already-used-token')).rejects.toMatchObject({
      statusCode: 401,
      message: expect.stringContaining('already been used'),
    });
  });

  it('rejects a second attempt with the same token (race condition / token reuse)', async () => {
    // First request: succeeds and rotates the token
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    await authService.refreshTokens('old-token');

    // Second request with the same old token — DB record is gone
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('old-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when user no longer exists', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('User not found', 401),
    );
  });

  it('throws 403 when account is deactivated', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: false } as never);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('Account is deactivated', 403),
    );
  });

  it('issues a rotated token pair on success', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    const tokens = await authService.refreshTokens('old-token');

    expect(tokens.accessToken).toBe('new-access');
    expect(tokens.refreshToken).toBe('new-refresh');
    // Old token was consumed; a new one was stored
    expect(mockRepo.storeRefreshToken).toHaveBeenCalledWith(
      'user-1',
      'new-refresh',
      expect.any(Date),
    );
  });
});

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------
describe('authService.logout', () => {
  it('revokes the given refresh token', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('valid-refresh');

    expect(mockRepo.revokeRefreshToken).toHaveBeenCalledWith('valid-refresh');
  });

  it('still revokes an expired token so the client is cleaned up', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('jwt expired');
    });
    mockRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('expired-refresh');

    expect(mockRepo.revokeRefreshToken).toHaveBeenCalledWith('expired-refresh');
  });

  it('throws 400 for a completely malformed token', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('invalid signature');
    });

    await expect(authService.logout('not-a-jwt')).rejects.toMatchObject({ statusCode: 400 });
  });
});
