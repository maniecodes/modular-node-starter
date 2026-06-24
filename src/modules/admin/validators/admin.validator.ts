import { z } from 'zod';
const phoneSchema = z.string().regex(/^\+?[1-9]\d{7,14}$/, 'Invalid phone number format');

export const inviteUserSchema = z.object({
    email: z.string().email(),
    phone: phoneSchema.optional(),
    roles: z.array(z.string().min(2)).min(1, 'At least one role must be selected'),
    channel: z.enum(['email', 'whatsapp']).optional(),
}).refine((v) => (v.channel === 'whatsapp' ? Boolean(v.phone) : true), {
    message: 'phone is required when channel is whatsapp',
    path: ['phone'],
});

export const getUsersQuerySchema = z.object({
    page: z.coerce.number().int().positive().optional(),
    perPage: z.coerce.number().int().positive().max(100).optional(),
});