import { AppError } from '@/core/errors/AppError';
import * as authService from '@/modules/auth/services/auth.service';
import * as adminService from '@/modules/admin/services/admin.service';
import * as adminRepository from '@/modules/admin/repositories/admin.repository';
import * as authRepository from '@/modules/auth/repositories/auth.repository';
import * as userRepository from '@/modules/users/repositories/users.repository';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import * as loginProtection from '@/core/auth/login-protection';
import * as mailService from '@/core/mail/mail.service';
import { logger } from '@/common/utils/logger';
import { env } from '@/core/config/env';

jest.mock('@/modules/auth/repositories/auth.repository');
jest.mock('@/modules/users/repositories/users.repository');
jest.mock('@/modules/admin/repositories/admin.repository');
jest.mock('@/core/auth/jwt');
jest.mock('@/core/auth/login-protection');
jest.mock('@/core/mail/mail.service');
jest.mock('@/core/auth/social-auth-provider.service');
jest.mock('@/common/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn(),
    },
}));

const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockAdminRepo = adminRepository as jest.Mocked<typeof adminRepository>;
const mockMailService = mailService as jest.Mocked<typeof mailService>;
const mockLogger = logger as jest.Mocked<typeof logger>;

const sampleUser = {
    id: 'user-1',
    firstName: 'Sam',
    lastName: 'John',
    email: 'sam@gmail.com',
    phone: null,
    isVerified: true,
    isEmailVerified: true,
    isPhoneVerified: false,
};
const dbUserWithPassword = { ...sampleUser, password: 'hashed', isActive: true };
const sampleRole = {
    id: 'role-1',
    name: 'user',
    permissions: [
        {
            permission: { resource: 'users', action: 'read' },
        },
    ],
};
const futureExp = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;

const tokenRecord = {
    id: 'rt-1',
    userId: 'user-1',
    tokenHash: 'abc123',
    revokedAt: null,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
};


// ---------------------------------------------------------------------------
// inviteUser
// ---------------------------------------------------------------------------
describe('authService.inviteUser', () => {
    it('creates invite and returns the accept URL for email channel', async () => {
        mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
        mockUserRepo.findRolesByNames.mockResolvedValueOnce([
            { id: 'role-1', name: 'staff' },
        ] as never);
        mockUserRepo.findUserById.mockResolvedValueOnce(sampleUser as never);
        mockAdminRepo.createUserInvite.mockResolvedValueOnce({
            inviteId: 'invite-1',
            rawToken: 'raw-token',
            expiresAt: new Date(Date.now() + 60_000),
        } as never);
        mockMailService.sendEmail.mockResolvedValueOnce(undefined as never);

        const result = await adminService.inviteUser(
            {
                email: 'new.staff@example.com',
                roles: ['staff'],
                channel: 'email',
            },
            'user-1',
        );

        expect(mockAdminRepo.createUserInvite).toHaveBeenCalledWith({
            email: 'new.staff@example.com',
            createdBy: 'user-1',
            roleIds: ['role-1'],
        });
        expect(mockMailService.sendEmail).not.toHaveBeenCalled();
        expect(result.acceptUrl).toContain('accept-invite?token=');
        expect(result.inviteId).toBe('invite-1');
        expect(result.channel).toBe('email');
    });

    it('returns invite metadata for whatsapp channel', async () => {
        mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
        mockUserRepo.findRolesByNames.mockResolvedValueOnce([
            { id: 'role-1', name: 'staff' },
        ] as never);
        mockUserRepo.findUserById.mockResolvedValueOnce(sampleUser as never);
        mockAdminRepo.createUserInvite.mockResolvedValueOnce({
            inviteId: 'invite-2',
            rawToken: 'raw-token-2',
            expiresAt: new Date(Date.now() + 60_000),
        } as never);

        const result = await adminService.inviteUser(
            {
                email: 'new.staff@example.com',
                phone: '+2348012345678',
                roles: ['staff'],
                channel: 'whatsapp',
            },
            'user-1',
        );

        expect(mockLogger.info).not.toHaveBeenCalled();
        expect(result.acceptUrl).toContain('accept-invite?token=');
        expect(result.channel).toBe('whatsapp');
    });
});
