import { Router } from 'express';
import { requireAuth } from '@/core/middleware/auth.middleware';
import { authorize } from '@/modules/access-control/middleware';
import { validate } from '@/core/middleware/validate.middleware';
import { inviteUserSchema, getUsersQuerySchema } from '@/modules/admin/validators/admin.validator';
import { inviteUserHandler, getUsersHandler } from '@/modules/admin/controllers/admin.controller';

// Admin router
// Mounted at /api/v1/admin

const router = Router();

router.use(requireAuth);
router.post('/invite-user', authorize('users.invite'), validate(inviteUserSchema), inviteUserHandler);
router.get('/users', authorize('users.read'), validate(getUsersQuerySchema, 'query'), getUsersHandler);

export default router;
