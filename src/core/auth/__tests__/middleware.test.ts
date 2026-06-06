import { Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { requireAuth } from '../../middleware/auth.middleware';
import { AuthenticatedRequest } from '@/common/types';

jest.mock('@/core/auth/jwt', () => ({
  verifyAccessToken: jest.fn(),
}));

jest.mock('@/core/auth/user-context', () => ({
  loadUserContext: jest.fn(),
}));

import { verifyAccessToken } from '@/core/auth/jwt';
import { loadUserContext } from '@/core/auth/user-context';

const mockVerify = verifyAccessToken as jest.MockedFunction<typeof verifyAccessToken>;
const mockLoadContext = loadUserContext as jest.MockedFunction<typeof loadUserContext>;

const validPayload = { sub: 'user-1', email: 'alice@example.com' };

const fullContext = {
  id: 'user-1',
  email: 'alice@example.com',
  phone: null,
  isActive: true,
  roles: ['admin'],
  permissions: ['users.read', 'roles.create'],
};

const makeReq = (authHeader?: string): AuthenticatedRequest =>
  ({ headers: { authorization: authHeader ?? 'Bearer valid.token' } }) as AuthenticatedRequest;

const res = {} as Response;
const next = jest.fn() as NextFunction;

beforeEach(() => jest.clearAllMocks());

// ---------------------------------------------------------------------------
// requireAuth
// ---------------------------------------------------------------------------
describe('requireAuth', () => {
  it('throws 401 when Authorization header is absent', async () => {
    const req = { headers: {} } as AuthenticatedRequest;
    await expect(requireAuth(req, res, next)).rejects.toMatchObject({ statusCode: 401 });
    expect(next).not.toHaveBeenCalled();
  });

  it('throws 401 when scheme is not Bearer', async () => {
    await expect(requireAuth(makeReq('Basic abc123'), res, next)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when token verification fails', async () => {
    mockVerify.mockImplementation(() => {
      throw new Error('jwt expired');
    });
    await expect(requireAuth(makeReq(), res, next)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 401 when user is not found in DB', async () => {
    mockVerify.mockReturnValue(validPayload);
    mockLoadContext.mockResolvedValue(null);
    await expect(requireAuth(makeReq(), res, next)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 403 when user account is deactivated', async () => {
    mockVerify.mockReturnValue(validPayload);
    mockLoadContext.mockResolvedValue({ ...fullContext, isActive: false });
    await expect(requireAuth(makeReq(), res, next)).rejects.toMatchObject({ statusCode: 403 });
  });

  it('populates req.user with id, email, roles and permissions on success', async () => {
    mockVerify.mockReturnValue(validPayload);
    mockLoadContext.mockResolvedValue(fullContext);

    const req = makeReq();
    await requireAuth(req, res, next);

    expect(req.user).toEqual({
      id: 'user-1',
      email: 'alice@example.com',
      phone: undefined,
      roles: ['admin'],
      permissions: ['users.read', 'roles.create'],
    });
    expect(next).toHaveBeenCalledWith();
  });

  it('passes the user ID from the JWT sub claim to loadUserContext', async () => {
    mockVerify.mockReturnValue({ sub: 'user-42', email: 'bob@example.com' });
    mockLoadContext.mockResolvedValue({ ...fullContext, id: 'user-42', email: 'bob@example.com' });

    await requireAuth(makeReq(), res, next);

    expect(mockLoadContext).toHaveBeenCalledWith('user-42');
  });

  it('throws 401 when the Bearer token is an empty string', async () => {
    // Authorization: "Bearer " with nothing after it
    mockVerify.mockImplementation(() => {
      throw new Error('jwt malformed');
    });
    await expect(requireAuth(makeReq('Bearer '), res, next)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('propagates unexpected errors thrown by loadUserContext', async () => {
    mockVerify.mockReturnValue(validPayload);
    mockLoadContext.mockRejectedValueOnce(new Error('DB connection lost'));

    await expect(requireAuth(makeReq(), res, next)).rejects.toThrow('DB connection lost');
  });
});
