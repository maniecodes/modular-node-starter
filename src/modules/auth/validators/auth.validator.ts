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
export const verifyOtpSchema = emailOrPhoneSchema
  .extend({
    purpose: z.enum(['REGISTRATION', 'PASSWORD_RESET']),
    otpCode: z.string().regex(/^\d{6}$/, 'OTP code must be 6 digits'),
    newPassword: z.string().optional(),
  })
  .refine((v) => (v.purpose === 'PASSWORD_RESET' ? Boolean(v.newPassword) : true), {
    message: 'newPassword is required for PASSWORD_RESET',
    path: ['newPassword'],
  })
  .refine(
    (v) =>
      v.purpose === 'REGISTRATION' ||
      (!!v.newPassword?.match(/[A-Z]/) &&
        !!v.newPassword?.match(/[0-9]/) &&
        v.newPassword.length >= 8),
    {
      message:
        'For PASSWORD_RESET, newPassword must be at least 8 chars and include one uppercase and one number',
      path: ['newPassword'],
    },
  );

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

export const resetPasswordSchema = emailOrPhoneSchema.extend({
  otpCode: z.string().regex(/^\d{6}$/, 'OTP code must be 6 digits'),
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
