import { Request, Response } from 'express';
import * as adminService from '@/modules/admin/services/admin.service';
import { AuthenticatedRequest } from '@/common/types';
import { AppError } from '@/core/errors/AppError';
import { sendCreated, sendSuccess } from '@/common/helpers/response';
import { parsePaginationQuery, buildPaginatedResponse } from '@/common/helpers/pagination';
import { InviteUserInput } from '@/modules/admin/admin.types';
import { withPagination } from '@/common/helpers/paginated-handler';


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
 * It supports pagination through query parameters and returns a structured response containing the users and pagination metadata.
 * endpoint: GET /api/v1/admin/users
 * 
 * @param req 
 * @param res
 */
export const getUsersHandler = withPagination(
    (pagination) => adminService.getUsers(pagination),
    'Retrieved all users',
);