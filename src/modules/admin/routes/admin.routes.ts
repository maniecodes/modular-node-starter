import { Router } from 'express';
import { requireAuth } from '@/core/middleware/auth.middleware';
import { authorize } from '@/modules/access-control/middleware';
import { validate } from '@/core/middleware/validate.middleware';
import { inviteUserSchema } from '@/modules/admin/validators/admin.validator';
import { inviteUserHandler } from '@/modules/admin/controllers/admin.controller';

const router = Router();

router.use(requireAuth);
router.post('/invite-user', authorize('users.invite'), validate(inviteUserSchema), inviteUserHandler);

export default router;
