import { Request, Response } from 'express';
import * as adminService from '@/modules/admin/services/admin.service';
import { AuthenticatedRequest } from '@/common/types';
import { AppError } from '@/core/errors/AppError';


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