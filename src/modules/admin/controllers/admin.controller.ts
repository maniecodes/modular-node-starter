import { Request, Response } from 'express';
import * as adminService from '@/modules/admin/services/admin.service';
import { AuthenticatedRequest } from '@/common/types';
import { AppError } from '@/core/errors/AppError';
import { sendCreated, sendSuccess } from '@/common/helpers/response';
import { parsePaginationQuery, buildPaginatedResponse } from '@/common/helpers/pagination';
import { InviteUserInput } from '@/modules/admin/admin.types';
import { withPagination } from '@/common/helpers/paginated-handler';
import { withFilterSearch } from '@/common/helpers/filter-search.hof';
import { FilterSearchConfig } from '@/common/helpers/filter-search.types';


/**
 *  Handler for inviting a new user to the platform. 
 *  It creates an invitation and sends an email to the invitee with instructions on how to accept the invitation and create their account.
 *  endpoint: POST /api/v1/auth/invite
 * 
 * @param req 
 * @param res 
 */
export async function inviteUserHandler(
    req: AuthenticatedRequest,
    res: Response,
): Promise<void> {
    if (!req.user) throw new AppError('Unauthenticated', 401);

    const result = await adminService.inviteUser(
        req.body as InviteUserInput,
        req.user.id,
    );

    sendCreated(res, result, 'User invitation created');
}

/**
 * Handler for retrieving a paginated list of users in the system.
 * Supports filtering by isActive, role, and createdAt; full-text searching across name, email, and phone.
 * Query examples:
 *   GET /api/v1/admin/users?search=john&page=1&limit=10
 *   GET /api/v1/admin/users?search=john&searchFields=firstName,lastName&page=1&limit=10
 *   GET /api/v1/admin/users?filter=isActive:true&filter=role:admin
 *   GET /api/v1/admin/users?filter=createdAt:2024-01-01,2024-12-31&page=1
 *   endpoint: GET /api/v1/admin/users
 * 
 * @param req 
 * @param res
 */
const getUsersConfig: FilterSearchConfig = {
  searchableFields: ['firstName', 'lastName', 'email', 'phone'],
  filterableFields: {
    isActive: { type: 'boolean' },
    role: { type: 'enum', enumValues: ['admin', 'user', 'customer', 'vendor'] },
    createdAt: { type: 'date', operators: ['range'] },
  },
};

export const getUsersHandler = withFilterSearch(
  (filters, pagination) => adminService.getUsers(filters, pagination),
  getUsersConfig,
  'Retrieved users',
);