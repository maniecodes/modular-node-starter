import { z } from 'zod';

const phoneSchema = z.string().regex(/^\+?[1-9]\d{7,14}$/, 'Invalid phone number format');

const emailOrPhoneSchema = z
  .object({
    email: z.string().email().optional(),
    phone: phoneSchema.optional(),
  })
  .refine((v) => Boolean(v.email || v.phone), {
    message: 'Either email or phone is required',
    path: ['email'],
  })
  .refine((v) => !(v.email && v.phone), {
    message: 'Provide either email or phone, not both',
    path: ['email'],
  });

export const forgotPasswordSchema = emailOrPhoneSchema;

export const verifyOtpSchema = emailOrPhoneSchema.extend({
  purpose: z.enum(['REGISTRATION', 'PASSWORD_RESET']),
  otpCode: z.string().regex(/^\d{6}$/, 'OTP code must be 6 digits'),
});

export const inviteUserSchema = z.object({
  email: z.string().email(),
  phone: phoneSchema.optional(),
  roles: z.array(z.string().min(2)).min(1, 'At least one role must be selected'),
  channel: z.enum(['email', 'whatsapp']).optional(),
}).refine((v) => (v.channel === 'whatsapp' ? Boolean(v.phone) : true), {
  message: 'phone is required when channel is whatsapp',
  path: ['phone'],
});

export const acceptInviteSchema = z.object({
  token: z.string().min(1, 'Invite token is required'),
  firstName: z.string().min(2).max(100),
  lastName: z.string().min(2).max(100),
  password: z
    .string()
    .min(8)
    .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Must contain at least one number'),
});

export const registerSchema = emailOrPhoneSchema.extend({
  firstName: z.string().min(2).max(100),
  lastName: z.string().min(2).max(100),
  roles: z.array(z.string().min(2)).min(1, 'At least one role must be selected'),
  password: z
    .string()
    .min(8)
    .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Must contain at least one number'),
});

export const loginSchema = emailOrPhoneSchema.extend({
  password: z.string().min(1),
});

export const resetPasswordSchema = z.object({
  resetToken: z.string().min(1, 'Reset token is required'),
  newPassword: z
    .string()
    .min(8)
    .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Must contain at least one number'),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

export const resendOtpSchema = emailOrPhoneSchema.extend({
  purpose: z.enum(['REGISTRATION', 'PASSWORD_RESET']).optional(),
});

export const logoutSchema = z.object({
  refreshToken: z.string().min(1),
});
