import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '@/core/database/prisma';
import { AppError } from '@/core/errors/AppError';
import * as authService from '../services/auth.service';

jest.mock('@/core/database/prisma', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
  },
}));

jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

const mockPrismaUser = prisma.user as jest.Mocked<typeof prisma.user>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;
const mockJwt = jwt as jest.Mocked<typeof jwt>;

const sampleUser = {
  id: 'user-1',
  name: 'Alice',
  email: 'alice@example.com',
};

const dbUser = {
  ...sampleUser,
  password: 'hashed',
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

beforeEach(() => jest.clearAllMocks());

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
describe('authService.register', () => {
  it('throws 409 when email already exists', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(dbUser as never);

    await expect(
      authService.register({ name: 'Alice', email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Email is already in use', 409));
  });

  it('hashes the password before storing', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockPrismaUser.create.mockResolvedValueOnce(sampleUser as never);
    (mockJwt.sign as jest.Mock).mockReturnValue('token');

    await authService.register({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Password1',
    });

    expect(mockBcrypt.hash).toHaveBeenCalledWith('Password1', expect.any(Number));
  });

  it('returns user and token pair on success', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockPrismaUser.create.mockResolvedValueOnce(sampleUser as never);
    (mockJwt.sign as jest.Mock).mockReturnValueOnce('access').mockReturnValueOnce('refresh');

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
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('throws 403 when account is deactivated', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce({ ...dbUser, isActive: false } as never);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Account is deactivated', 403));
  });

  it('throws 401 for wrong password', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(dbUser as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'wrong' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('returns user (without password) and tokens on valid credentials', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(dbUser as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    (mockJwt.sign as jest.Mock).mockReturnValueOnce('access').mockReturnValueOnce('refresh');

    const result = await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.user).not.toHaveProperty('password');
    expect(result.user).not.toHaveProperty('isActive');
    expect(result.tokens.accessToken).toBe('access');
  });
});

// ---------------------------------------------------------------------------
// refreshTokens
// ---------------------------------------------------------------------------
describe('authService.refreshTokens', () => {
  it('throws 401 for an invalid refresh token', async () => {
    (mockJwt.verify as jest.Mock).mockImplementationOnce(() => {
      throw new Error('invalid');
    });

    await expect(authService.refreshTokens('bad-token')).rejects.toThrow(
      new AppError('Invalid or expired refresh token', 401),
    );
  });

  it('throws 401 when user no longer exists', async () => {
    (mockJwt.verify as jest.Mock).mockReturnValueOnce({ sub: 'user-1' });
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('User not found', 401),
    );
  });

  it('throws 403 when account is deactivated', async () => {
    (mockJwt.verify as jest.Mock).mockReturnValueOnce({ sub: 'user-1' });
    mockPrismaUser.findUnique.mockResolvedValueOnce({
      ...sampleUser,
      isActive: false,
    } as never);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('Account is deactivated', 403),
    );
  });

  it('returns a new token pair for a valid token', async () => {
    (mockJwt.verify as jest.Mock).mockReturnValueOnce({ sub: 'user-1' });
    mockPrismaUser.findUnique.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    (mockJwt.sign as jest.Mock)
      .mockReturnValueOnce('new-access')
      .mockReturnValueOnce('new-refresh');

    const tokens = await authService.refreshTokens('valid-token');

    expect(tokens.accessToken).toBe('new-access');
    expect(tokens.refreshToken).toBe('new-refresh');
  });
});
