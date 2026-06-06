import { Response, NextFunction } from 'express';
import { AppError } from '@/core/errors/AppError';
import { authorize, requireRole } from '../middleware';
import { AuthenticatedRequest } from '@/common/types';

const res = {} as Response;
const next = jest.fn() as NextFunction;

const makeReq = (user?: AuthenticatedRequest['user']): AuthenticatedRequest =>
  ({ user }) as AuthenticatedRequest;

beforeEach(() => jest.clearAllMocks());

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------
describe('authorize', () => {
  it('throws 401 when req.user is not set', () => {
    expect(() => authorize('users.read')(makeReq(undefined), res, next)).toThrow(AppError);
    expect(() => authorize('users.read')(makeReq(undefined), res, next)).toThrow(
      expect.objectContaining({ statusCode: 401 }),
    );
  });

  it('throws 403 when user has no permissions at all', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', permissions: [] });
    expect(() => authorize('users.read')(req, res, next)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
  });

  it('throws 403 when user has other permissions but not the required one', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', permissions: ['roles.read', 'roles.create'] });
    expect(() => authorize('users.read')(req, res, next)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
  });

  it('calls next when user has the exact permission', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', permissions: ['users.read'] });
    authorize('users.read')(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('calls next when user has the permission among many', () => {
    const req = makeReq({
      id: '1',
      email: 'a@b.com',
      permissions: ['users.read', 'users.delete', 'roles.create'],
    });
    authorize('users.delete')(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('error message includes the missing permission name', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', permissions: [] });
    expect(() => authorize('roles.assign')(req, res, next)).toThrow(
      expect.objectContaining({ message: expect.stringContaining('roles.assign') }),
    );
  });
});

// ---------------------------------------------------------------------------
// requireRole
// ---------------------------------------------------------------------------
describe('requireRole', () => {
  it('throws 401 when req.user is not set', () => {
    expect(() => requireRole('admin')(makeReq(undefined), res, next)).toThrow(
      expect.objectContaining({ statusCode: 401 }),
    );
  });

  it('throws 403 when user has no matching role', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', roles: ['user'] });
    expect(() => requireRole('admin')(req, res, next)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
  });

  it('calls next when user has one of the required roles', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', roles: ['user', 'moderator'] });
    requireRole('admin', 'moderator')(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('calls next with no roles restriction (empty roles list)', () => {
    const req = makeReq({ id: '1', email: 'a@b.com', roles: [] });
    requireRole()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
});
