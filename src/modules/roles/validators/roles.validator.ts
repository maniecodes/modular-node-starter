import { z } from 'zod';

export const createRoleSchema = z.object({
  name: z.string().min(1).max(50),
  description: z.string().max(255).optional(),
});

export const createPermissionSchema = z.object({
  action: z.string().min(1).max(50),
  resource: z.string().min(1).max(50),
  description: z.string().max(255).optional(),
});

export const assignPermissionSchema = z.object({
  permissionId: z.string().min(1),
});

export const assignRoleSchema = z.object({
  userId: z.string().min(1),
});
