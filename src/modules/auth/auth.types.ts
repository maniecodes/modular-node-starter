export interface RegisterInput {
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  roles: string[];
  password: string;
}
export interface LoginInput {
  email?: string;
  phone?: string;
  password: string;
}
export interface GoogleLoginInput {
  idToken: string;
}
export interface FacebookLoginInput {
  accessToken: string;
}
export interface OAuthCallbackQueryInput {
  code: string;
  redirectUri?: string;
}
export interface RequestOtpInput {
  email?: string;
  phone?: string;
}
export interface ResendOtpInput extends RequestOtpInput {
  purpose?: 'REGISTRATION' | 'PASSWORD_RESET';
}
export interface VerifyOtpInput {
  email?: string;
  phone?: string;
  otpCode: string;
}
export interface VerifyRegistrationOtpInput extends VerifyOtpInput { }
export interface VerifyPasswordResetOtpResult {
  resetToken: string;
}

export type InviteChannel = 'email' | 'whatsapp';

export interface AcceptInviteInput {
  token: string;
  firstName: string;
  lastName: string;
  password: string;
}

export interface ResetPasswordInput {
  resetToken: string;
  newPassword: string;
}
export interface RefreshInput {
  refreshToken: string;
}
export interface AuthResult {
  user: AuthUser;
  tokens: TokenPair;
}
export interface RegisterResult {
  user: AuthUser;
  requiresOtpVerification: true;
  otpCode: string;
  otpChannel: 'email' | 'phone';
}
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}
export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
}
export interface AuthUser {
  id: string;
  firstName: string;
  lastName: string;
  email?: string | null;
  phone?: string | null;
  verifiedMethods: Array<'EMAIL' | 'PHONE'>;
  roles: string[];
  permissions: string[];
}


