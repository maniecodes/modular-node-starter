// src/modules/users/__tests__/users.service.test.ts
import { prisma } from '@/core/database/prisma';
import { AppError } from '@/core/errors/AppError';
import * as usersService from '../services/users.service';

jest.mock('@/core/database/prisma', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
  },
}));

const mockPrismaUser = prisma.user as jest.Mocked<typeof prisma.user>;

const sampleUser = {
  id: 'user-1',
  name: 'Alice',
  email: 'alice@example.com',
  createdAt: new Date(),
};

beforeEach(() => jest.clearAllMocks());

describe('usersService.getProfile', () => {
  it('returns the user profile', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(sampleUser as never);

    const profile = await usersService.getProfile('user-1');

    expect(profile.id).toBe('user-1');
    expect(profile.email).toBe('alice@example.com');
  });

  it('throws 404 when user does not exist', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);

    await expect(usersService.getProfile('unknown')).rejects.toThrow(
      new AppError('User not found', 404),
    );
  });
});

describe('usersService.updateProfile', () => {
  it('updates and returns the user', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(sampleUser as never);
    mockPrismaUser.update.mockResolvedValueOnce({ ...sampleUser, name: 'Bob' } as never);

    const result = await usersService.updateProfile('user-1', { name: 'Bob' });

    expect(result.name).toBe('Bob');
  });

  it('throws 404 when user does not exist', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);

    await expect(usersService.updateProfile('unknown', { name: 'Bob' })).rejects.toThrow(
      new AppError('User not found', 404),
    );
  });
});
