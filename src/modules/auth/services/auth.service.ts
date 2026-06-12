import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { OtpPurpose, OtpType } from '@prisma/client';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import {
  exchangeFacebookAuthorizationCode,
  exchangeGoogleAuthorizationCode,
  fetchFacebookProfile,
  verifyGoogleIdToken,
  verifyFacebookAccessToken,
} from '@/core/auth/social-auth-provider.service';
import { securityEvent } from '@/core/audit/security-events';
import { isLocked, recordFailedAttempt, clearAttempts } from '@/core/auth/login-protection';
import { generateOtpCode } from '@/common/crypto/token';
import { sendEmail } from '@/core/mail/mail.service';
import { userInviteTemplate } from '@/core/mail/templates/user-invite.template';
import { logger } from '@/common/utils/logger';
import { SOCIAL_AUTH_PROVIDERS } from '@/common/constants';
import * as authRepository from '../repositories/auth.repository';
import {
  AcceptInviteInput,
  AuthResult,
  AuthUser,
  FacebookLoginInput,
  GoogleLoginInput,
  InviteUserInput,
  InviteUserResult,
  LoginInput,
  OAuthCallbackQueryInput,
  RegisterInput,
  RegisterResult,
  ResendOtpInput,
  RequestContext,
  RequestOtpInput,
  ResetPasswordInput,
  TokenPair,
  VerifyOtpInput,
  VerifyPasswordResetOtpResult,
  VerifyRegistrationOtpInput,
} from '../auth.types';

type SelectedRole = {
  id: string;
  name: string;
  permissions: Array<{
    permission: {
      resource: string;
      action: string;
    };
  }>;
};

type SafeUserRecord = {
  id: string;
  firstName: string;
  lastName: string;
  email: string | null;
  phone: string | null;
  isVerified: boolean;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
};


/**
 * Signs a refresh token, stores its hash in DB, and returns the token string.
 * expiresIn is the JWT `exp` unix timestamp returned by verifyRefreshToken.
 */
async function issueRefreshToken(userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = signRefreshToken(userId);
  // Decode our own token to get the canonical expiry — avoids duplicating the
  // env.JWT_REFRESH_EXPIRES_IN parsing logic here.
  const { exp } = verifyRefreshToken(token);
  const expiresAt = new Date(exp * 1000);
  await authRepository.storeRefreshToken(userId, token, expiresAt);
  return { token, expiresAt };
}

/**
 *  Helper function to construct a safe user object for inclusion in API responses, 
 *  stripping out sensitive information and including only necessary details such as verified methods, roles, and permissions.
 * @param user The user record containing details such as ID, name, email, phone, and verification status.
 * @param roles The roles assigned to the user.
 * @param permissions The permissions granted to the user.
 * @returns A safe user object containing non-sensitive information and the user's roles and permissions for authorization purposes.
 */
function buildSafeUser(
  user: {
    id: string;
    firstName: string;
    lastName: string;
    email: string | null;
    phone: string | null;
    isEmailVerified: boolean;
    isPhoneVerified: boolean;
  },
  roles: string[] = [],
  permissions: string[] = [],
): AuthUser {
  const verifiedMethods: Array<'EMAIL' | 'PHONE'> = [];
  if (user.isEmailVerified) verifiedMethods.push('EMAIL');
  if (user.isPhoneVerified) verifiedMethods.push('PHONE');

  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone,
    verifiedMethods,
    roles,
    permissions,
  };
}

/**
 *  Finalizes the social login process by checking account status, 
 *  building a safe user object, issuing tokens, and logging the successful login event.
 * @param user The user record associated with the social login, containing details such as ID, name, email, phone, and verification status.
 * @param provider The social authentication provider (e.g., Google, Facebook).
 * @param context Optional request context containing IP address and user agent information.
 * @returns An object containing the authenticated user and their access and refresh tokens.
 */
async function finalizeSocialLogin(
  user: {
    id: string;
    firstName: string;
    lastName: string;
    email: string | null;
    phone: string | null;
    isActive: boolean;
    isEmailVerified: boolean;
    isPhoneVerified: boolean;
  },
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1],
  context?: RequestContext,
): Promise<AuthResult> {
  if (!user.isActive) {
    throw new AppError('Account is deactivated', 403);
  }

  const roleNames = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roleNames, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('login_success', {
    userId: user.id,
    email: user.email,
    authProvider: provider,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

/**
 *  Extracts the user's first and last name from the Google ID token payload.
 * @param payload The payload of the Google ID token, which may contain the user's email, given name, family name, and full name.
 * @returns An object containing the firstName and lastName extracted from the Google ID token payload
 */
function resolveGoogleNames(payload: {
  email: string;
  given_name?: string;
  family_name?: string;
  name?: string;
}): { firstName: string; lastName: string } {
  const givenName = payload.given_name?.trim();
  const familyName = payload.family_name?.trim();

  if (givenName && familyName) {
    return { firstName: givenName, lastName: familyName };
  }

  const fullName = payload.name?.trim();
  if (fullName) {
    const [firstName, ...rest] = fullName.split(/\s+/);
    const lastName = rest.join(' ');

    if (firstName && lastName) {
      return { firstName, lastName };
    }
  }

  // Fallback to using the email's local part as the first name if no other name information is available
  const localPart = payload.email.split('@')[0] || 'google.user';
  return {
    firstName: givenName || localPart,
    lastName: familyName || 'User',
  };
}

/**
 *  Resolves the redirect URI for the given social authentication provider.
 * @param provider The social authentication provider (e.g., Google, Facebook).
 * @param inputRedirectUri Optional redirect URI provided in the request.
 * @returns The resolved redirect URI.
 */
function resolveRedirectUri(
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1],
  inputRedirectUri?: string,
): string {
  const fallback = provider === SOCIAL_AUTH_PROVIDERS[0] ? env.GOOGLE_REDIRECT_URI : env.FACEBOOK_REDIRECT_URI;
  const redirectUri = inputRedirectUri ?? fallback;
  if (!redirectUri) {
    throw new AppError(
      `${provider} redirect URI is required for callback flow`,
      400,
    );
  }
  return redirectUri;
}

/**
 *  Creates user with social identity if not exists, or resolves existing user by linked social identity or email. 
 *  Also handles linking the social identity to the user account if not already linked, 
 *  and ensures that an email from the social provider is always associated with a user account for consistent identification.
 * @param provider The social authentication provider (e.g., Google, Facebook).
 * @param profile The profile information returned by the social authentication provider.
 * @param context Optional request context containing IP address and user agent information.
 * @returns The resolved or newly created user associated with the social identity.
 */
async function resolveOrProvisionSocialUser(
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1],
  profile: {
    providerUserId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    name?: string;
  },
  context?: RequestContext,
) {
  console.log('Resolving or provisioning social user with profile:', profile);
  const email = profile.email.toLowerCase();
  console.log('existing linked provider for user:', provider, profile.providerUserId);
  const linkedIdentity = await authRepository.findSocialIdentityUser(provider, profile.providerUserId);

  let user = linkedIdentity
    ? await authRepository.findUserById(linkedIdentity.userId)
    : await authRepository.findUserByEmail(email);

  console.log('user found by social identity:', user);
  if (!user) {
    const roles = await authRepository.findRolesByNames(['user']);
    const [defaultRole] = roles;
    if (!defaultRole || roles.length !== 1) {
      throw new AppError('Default role "user" is missing. Run seed before social login.', 500);
    }

    const { firstName, lastName } = resolveGoogleNames({
      email,
      given_name: profile.firstName,
      family_name: profile.lastName,
      name: profile.name,
    });

    const randomPassword = randomBytes(32).toString('hex');
    const password = await bcrypt.hash(randomPassword, env.BCRYPT_ROUNDS);

    await authRepository.createUserWithRoles(
      {
        firstName,
        lastName,
        email,
        password,
        isVerified: true,
        isEmailVerified: true,
        isPhoneVerified: false,
      },
      [defaultRole.id],
    );

    user = await authRepository.findUserByEmail(email);
    if (!user) {
      throw new AppError(`Unable to complete ${provider} signup`, 500);
    }

    securityEvent('register_success', {
      userId: user.id,
      email: user.email,
      authProvider: provider,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });
  }


  const existingLinkedProviderForUser = await authRepository.findSocialIdentityByUser(
    provider,
    user.id,
  );
  console.log('existing linked provider for user:', existingLinkedProviderForUser);
  if (
    existingLinkedProviderForUser &&
    existingLinkedProviderForUser.providerUserId !== profile.providerUserId
  ) {
    throw new AppError(`This account is already linked to a different ${provider} identity`, 409);
  }

  console.log('is account linked?', linkedIdentity);

  if (!linkedIdentity) {
    await authRepository.linkSocialIdentity({
      provider,
      providerUserId: profile.providerUserId,
      userId: user.id,
      providerEmail: email,
    });
  }

  return user;
}

/**
 *  Handler for verifying OTPs for both registration and password reset purposes.
 * @param input The input containing either email or phone to identify the user.
 * @returns An object containing the type of OTP (email or phone) and the target value (email or phone number).
 */
function resolveIdentifier(input: { email?: string; phone?: string }): {
  type: OtpType;
  target: string;
} {
  if (input.email && input.phone) {
    throw new AppError('Provide either email or phone', 400);
  }
  if (input.email) return { type: OtpType.EMAIL, target: input.email.toLowerCase() };
  if (input.phone) return { type: OtpType.PHONE, target: input.phone };
  throw new AppError('Either email or phone is required', 400);
}

/**
 *  Generates and stores an OTP code for a given target (email or phone) and purpose.
 *  The OTP is hashed before storage for security, and an expiry time is set based on the environment configuration.
 * @param target The email or phone number to which the OTP will be sent.
 * @param type The type of OTP (email or phone).
 * @param purpose The purpose of the OTP (e.g., registration, password reset).
 * @param context Optional context information such as IP address and user agent, which can be used for auditing or security purposes.
 * @returns An object containing the channel ('email' or 'phone') and the raw OTP code.
 */
async function generateAndStoreOtp(
  target: string,
  type: OtpType,
  purpose: OtpPurpose,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {

  const code = generateOtpCode();
  const encryptedCode = await bcrypt.hash(code, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  await authRepository.storeOtpCode(target, type, purpose, encryptedCode, expiresAt, context);

  return { channel: type === OtpType.EMAIL ? 'email' : 'phone', otpCode: code };
}

/**
 *  Generates an OTP payload for registration purposes, including the raw OTP code, its encrypted version, and the expiry time.
 * @param target The email or phone number to which the OTP will be sent.
 * @param type The type of OTP (email or phone).
 * @returns An object containing the raw OTP code, its encrypted version, and the expiry time.
 */
async function generateRegistrationOtpPayload(
  target: string,
  type: OtpType,
): Promise<{ otpCode: string; encryptedCode: string; expiresAt: Date }> {
  const otpCode = generateOtpCode();
  const encryptedCode = await bcrypt.hash(otpCode, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  return { otpCode, encryptedCode, expiresAt };
}

/**
 *  Consumes and validates an OTP code for a given target and purpose.
 * @param input The input containing either email or phone and the OTP code to validate.
 * @param purpose The purpose of the OTP (e.g., registration, password reset).
 * @param context Optional context information such as IP address and user agent, which can be used for auditing or security purposes.
 * @returns An object containing the user and the type of OTP (email or phone).
 */
async function consumeAndValidateOtp(
  input: VerifyOtpInput,
  purpose: OtpPurpose,
  context?: RequestContext,
) {
  const { type, target } = resolveIdentifier(input);
  const otpValid = await authRepository.consumeOtpCode(target, type, purpose, input.otpCode, context);
  if (!otpValid) throw new AppError('Invalid or expired OTP code', 401);

  const user =
    type === OtpType.EMAIL
      ? await authRepository.findUserByEmail(target)
      : await authRepository.findUserByPhone(target);
  if (!user) throw new AppError('Account not found', 404);

  return { user, type };
}

function buildInviteAcceptUrl(token: string): string {
  const baseUrl = process.env.APP_URL ?? `http://localhost:${env.PORT}`;
  return `${baseUrl}/accept-invite?token=${encodeURIComponent(token)}`;
}

/**
 *  Handler for user registration. It creates a new user account and sends a registration OTP to the user's email or phone for verification.
 * @param input The input containing user registration details such as email, phone, password, and roles.
 * @param context Optional context information such as IP address and user agent, which can be used for auditing or security purposes.
 * @returns An object containing the newly created user, a flag indicating if OTP verification is required, the OTP code, and the OTP channel.
 */
export async function register(
  input: RegisterInput,
  context?: RequestContext,
): Promise<RegisterResult> {
  if (input.email) {
    const existing = await authRepository.findUserByEmail(input.email.toLowerCase());
    if (existing) throw new AppError('Email is already in use', 409);
  }

  if (input.phone) {
    const existing = await authRepository.findUserByPhone(input.phone);
    if (existing) throw new AppError('Phone number is already in use', 409);
  }

  const normalizedRoles = [...new Set(input.roles.map((r) => r.trim().toLowerCase()))];
  if (normalizedRoles.length === 0) {
    throw new AppError('At least one role must be selected', 400);
  }

  const selectedRoles = (await authRepository.findRolesByNames(
    normalizedRoles,
  )) as unknown as SelectedRole[];

  if (selectedRoles.length !== normalizedRoles.length) {
    throw new AppError('One or more selected roles do not exist', 404);
  }

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);
  const otpTarget = input.email?.toLowerCase() ?? input.phone!;
  const otpType = input.email ? OtpType.EMAIL : OtpType.PHONE;
  const { otpCode, encryptedCode, expiresAt } = await generateRegistrationOtpPayload(
    otpTarget,
    otpType,
  );

  const user = (await authRepository.createUserWithRolesAndOtp(
    {
      firstName: input.firstName,
      lastName: input.lastName,
      email: input.email?.toLowerCase(),
      phone: input.phone,
      password: hashedPassword,
    },
    selectedRoles.map((r) => r.id),
    {
      target: otpTarget,
      type: otpType,
      purpose: OtpPurpose.REGISTRATION,
      code: encryptedCode,
      expiresAt,
    },
    context,
  )) as unknown as SafeUserRecord;

  const roleNames = selectedRoles.map((r) => r.name);
  const permissionKeys = [
    ...new Set(
      selectedRoles.flatMap((r) =>
        r.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];
  const otpChannel = otpType === OtpType.EMAIL ? 'email' : 'phone';

  securityEvent('register_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return {
    user: buildSafeUser(user, roleNames, permissionKeys),
    requiresOtpVerification: true,
    otpCode,
    otpChannel,
  };
}

/**
 *  Logins in a user by validating their credentials and returning access and refresh tokens.
 * @param input The input containing user login details such as email, phone, and password.
 * @param context Optional context information such as IP address and user agent, which can be used for auditing or security purposes.
 * @returns An object containing the authenticated user and their access and refresh tokens.
 */
export async function login(input: LoginInput, context?: RequestContext): Promise<AuthResult> {
  const identifier = input.email ?? input.phone;
  const password = input.password;
  if (!identifier) throw new AppError('Either email or phone is required', 400);

  // Check lockout before touching the DB — avoids unnecessary load under brute-force
  if (await isLocked(identifier)) {
    securityEvent('login_locked', { identifier });
    throw new AppError('Too many failed login attempts. Please try again later.', 429);
  }

  const user = input.email
    ? await authRepository.findUserByEmail(input.email.toLowerCase())
    : await authRepository.findUserByPhone(input.phone!);

  if (!user) {
    await recordFailedAttempt(identifier);
    securityEvent('login_failure', { identifier, reason: 'user_not_found' });
    throw new AppError('Invalid credentials', 401);
  }

  if (!user.isActive) {
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'account_deactivated',
    });
    throw new AppError('Account is deactivated', 403);
  }

  // check auth identity
  const authIdentity = await authRepository.findAuthIdentity(user.id);

  // This will allow user continue with google then set password in app
  if (authIdentity) {
    throw new AppError(`This account uses ${authIdentity.provider} sign-in. You can continue with ${authIdentity.provider} or set a password to enable email login.`);
  }

  const isLoginMethodVerified = identifier ? user.isEmailVerified : user.isPhoneVerified;

  if (!isLoginMethodVerified) {
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'account_not_verified',
    });
    await generateAndStoreOtp(
      identifier,
      input.email ? OtpType.EMAIL : OtpType.PHONE,
      OtpPurpose.REGISTRATION,
      context,
    );
    throw new AppError('Please verify this login channel with OTP before logging in', 403);
  }

  if (!user.password) {
    throw new AppError('This account uses social login. Please sign in with your provider.', 401)
  }

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    await recordFailedAttempt(identifier);
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'wrong_password',
    });
    throw new AppError('Invalid credentials', 401);
  }

  await clearAttempts(identifier);

  const roles = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roles, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('login_success', { userId: user.id, email: user.email, phone: user.phone });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

/**
 *  Login with Google by verifying the provided ID token, 
 *  resolving or provisioning a user account based on the Google profile information, 
 *  and finalizing the login process by issuing tokens and logging the event.
 * @param input 
 * @param context 
 * @returns An object containing the authentication result, including tokens and user information.
 */
export async function loginWithGoogle(
  input: GoogleLoginInput,
  context?: RequestContext,
): Promise<AuthResult> {
  if (!env.GOOGLE_CLIENT_ID) {
    throw new AppError('Google login is not configured', 503);
  }

  const payload = await verifyGoogleIdToken({
    idToken: input.idToken,
    audience: env.GOOGLE_CLIENT_ID,
  });

  if (!payload?.email) {
    throw new AppError('Google account email is required', 400);
  }

  if (!payload.email_verified) {
    throw new AppError('Google email is not verified', 403);
  }

  if (!payload.sub) {
    throw new AppError('Google subject is missing from ID token', 401);
  }

  const user = await resolveOrProvisionSocialUser(
    SOCIAL_AUTH_PROVIDERS[0],
    {
      providerUserId: payload.sub,
      email: payload.email.toLowerCase(),
      firstName: payload.given_name,
      lastName: payload.family_name,
      name: payload.name,
    },
    context,
  );

  return finalizeSocialLogin(user, SOCIAL_AUTH_PROVIDERS[0], context);
}

/**
 *  Login with Facebook by verifying the provided access token,
 *  resolving or provisioning a user account based on the Facebook profile information, 
 *  and finalizing the login process by issuing tokens and logging the event.
 * @param input 
 * @param context 
 * @returns An object containing the authentication result, including tokens and user information.
 */
export async function loginWithFacebook(
  input: FacebookLoginInput,
  context?: RequestContext,
): Promise<AuthResult> {
  if (!env.FACEBOOK_APP_ID || !env.FACEBOOK_APP_SECRET) {
    throw new AppError('Facebook login is not configured', 503);
  }

  const appAccessToken = `${env.FACEBOOK_APP_ID}|${env.FACEBOOK_APP_SECRET}`;
  const debugToken = await verifyFacebookAccessToken({
    userAccessToken: input.accessToken,
    appAccessToken,
  });

  if (debugToken.appId !== env.FACEBOOK_APP_ID) {
    throw new AppError('Facebook token app mismatch', 401);
  }

  const profile = await fetchFacebookProfile(input.accessToken);

  console.log('Facebook profile fetched:', profile);
  if (!profile.email) {
    throw new AppError('Facebook account email is required', 400);
  }

  if (profile.id && profile.id !== debugToken.userId) {
    throw new AppError('Facebook token/profile mismatch', 401);
  }

  console.log('Facebook debug token:', debugToken);
  console.log('Resolving or provisioning user for Facebook login with profile:', profile);
  const user = await resolveOrProvisionSocialUser(
    SOCIAL_AUTH_PROVIDERS[1],
    {
      providerUserId: debugToken.userId,
      email: profile.email,
      firstName: profile.first_name,
      lastName: profile.last_name,
      name: profile.name,
    },
    context,
  );

  return finalizeSocialLogin(user, SOCIAL_AUTH_PROVIDERS[1], context);
}

/**
 *  Handles the Google OAuth callback by exchanging the authorization code for an ID token,
 *  and then logging in the user with the obtained ID token.
 * @param input 
 * @param context 
 * @returns An object containing the authentication result, including tokens and user information.
 */
export async function loginWithGoogleCallback(
  input: OAuthCallbackQueryInput,
  context?: RequestContext,
): Promise<AuthResult> {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    throw new AppError('Google callback login is not configured', 503);
  }

  const redirectUri = resolveRedirectUri(SOCIAL_AUTH_PROVIDERS[0], input.redirectUri);
  const { idToken } = await exchangeGoogleAuthorizationCode({
    code: input.code,
    clientId: env.GOOGLE_CLIENT_ID,
    clientSecret: env.GOOGLE_CLIENT_SECRET,
    redirectUri,
  });

  return loginWithGoogle({ idToken }, context);
}

/**
 *  Handles the Facebook OAuth callback by exchanging the authorization code for an access token,
 *  and then logging in the user with the obtained access token.
 * @param input 
 * @param context 
 * @returns An object containing the authentication result, including tokens and user information.
 */
export async function loginWithFacebookCallback(
  input: OAuthCallbackQueryInput,
  context?: RequestContext,
): Promise<AuthResult> {
  if (!env.FACEBOOK_APP_ID || !env.FACEBOOK_APP_SECRET) {
    throw new AppError('Facebook callback login is not configured', 503);
  }

  const redirectUri = resolveRedirectUri(SOCIAL_AUTH_PROVIDERS[1], input.redirectUri);
  const { accessToken } = await exchangeFacebookAuthorizationCode({
    code: input.code,
    appId: env.FACEBOOK_APP_ID,
    appSecret: env.FACEBOOK_APP_SECRET,
    redirectUri,
  });

  return loginWithFacebook({ accessToken }, context);
}

/**
 *  Initiates the forgot password flow by generating and storing an OTP code for the user identified by email or phone, 
 *  and returning the OTP code and channel for sending to the user.
 *  The OTP code is generated securely and stored in a hashed form in the database, 
 *  with an expiry time set according to the environment configuration.
 * @param input 
 * @param context 
 * @returns An object containing the channel ('email' or 'phone') and the raw OTP code that can be sent to the user for password reset verification.
 */
export async function forgotPassword(
  input: RequestOtpInput,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {
  const { type, target } = resolveIdentifier(input);
  const user =
    type === OtpType.EMAIL
      ? await authRepository.findUserByEmail(target)
      : await authRepository.findUserByPhone(target);
  if (!user) throw new AppError('Account not found', 404);
  return generateAndStoreOtp(target, type, OtpPurpose.PASSWORD_RESET, context);
}

/**
 *  Allows administrators to invite new users to the platform by creating an invitation and sending an email to the invitee.
 * @param input The input containing the invitee's email, phone, roles, and optional invitation channel.
 * @param invitedByUserId The ID of the user who is sending the invitation.
 * @returns An object containing the invitation details, including the invite ID, accept URL, email, phone, channel, and expiration date.
 */
export async function inviteUser(
  input: InviteUserInput,
  invitedByUserId: string,
): Promise<InviteUserResult> {
  const email = input.email.toLowerCase();
  const channel = input.channel ?? 'email';
  if (channel === 'whatsapp' && !input.phone) {
    throw new AppError('Phone is required when invitation channel is WhatsApp', 400);
  }

  const existing = await authRepository.findUserByEmail(email);
  if (existing) throw new AppError('An account with this email already exists', 409);

  const normalizedRoles = [...new Set(input.roles.map((role) => role.trim().toLowerCase()))];
  if (normalizedRoles.length === 0) {
    throw new AppError('At least one role must be selected', 400);
  }

  const selectedRoles = (await authRepository.findRolesByNames(
    normalizedRoles,
  )) as unknown as Array<{ id: string; name: string }>;

  if (selectedRoles.length !== normalizedRoles.length) {
    throw new AppError('One or more selected roles do not exist', 404);
  }

  const inviter = await authRepository.findUserById(invitedByUserId);
  if (!inviter) throw new AppError('Inviter not found', 404);

  const { inviteId, rawToken, expiresAt } = await authRepository.createUserInvite({
    email,
    createdBy: invitedByUserId,
    roleIds: selectedRoles.map((role) => role.id),
  });

  const acceptUrl = buildInviteAcceptUrl(rawToken);
  const inviterName = `${inviter.firstName} ${inviter.lastName}`.trim();

  // TODO:: implement this later when we have email/whatsapp service setup
  // if (channel === 'email') {
  //   await sendEmail({
  //     to: email,
  //     subject: `${env.APP_NAME} staff invitation`,
  //     html: userInviteTemplate({
  //       appName: env.APP_NAME,
  //       inviteeEmail: email,
  //       invitedBy: inviterName,
  //       acceptUrl,
  //       expiresAt,
  //     }),
  //   });
  // } else {
  //   const message = `You are invited to join ${env.APP_NAME}. Accept invite: ${acceptUrl}`;
  //   logger.info('staff_invite_whatsapp_dispatch', {
  //     phone: input.phone,
  //     email,
  //     invitedByUserId,
  //     message,
  //   });
  // }

  securityEvent('staff_invite_created', {
    actorId: invitedByUserId,
    email,
    channel,
    inviteId,
    roleNames: selectedRoles.map((role) => role.name),
  });

  return {
    inviteId,
    acceptUrl,
    email,
    phone: input.phone,
    channel,
    expiresAt,
  };
}

/**
 *  Allows invitees to accept a user invitation by validating the invitation token and setting up their account with a password and optional name details.
 * @param input The input containing the invitation token, password, and optional name details.
 * @param context The request context, including IP address and user agent.
 * @returns An object containing the authenticated user and their tokens.
 */
export async function acceptInvite(
  input: AcceptInviteInput,
  context?: RequestContext,
): Promise<AuthResult> {
  const invite = await authRepository.consumeUserInvite(input.token);
  if (!invite) {
    throw new AppError('Invalid, expired, or already used invite token', 401);
  }

  const existing = await authRepository.findUserByEmail(invite.email);
  if (existing) throw new AppError('An account with this email already exists', 409);

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);
  const user = await authRepository.createInvitedUserWithRoles({
    firstName: input.firstName,
    lastName: input.lastName,
    email: invite.email,
    password: hashedPassword,
    roleIds: invite.roleIds,
    assignedBy: invite.createdBy,
  });

  const roles = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roles, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('staff_invite_accepted', {
    userId: user.id,
    email: user.email,
    invitedBy: invite.createdBy,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

/**
 *  Handler for verifying OTPs for registration purposes. 
 *  It validates the provided OTP code, marks the user's email or phone as verified, and returns the authenticated user along with access and refresh tokens.
 * @param input The input containing the OTP code and identifier (email or phone).
 * @param context The request context, including IP address and user agent.
 * @returns An object containing the authenticated user and their tokens.
 */
export async function verifyRegistrationOtp(
  input: VerifyRegistrationOtpInput,
  context?: RequestContext,
): Promise<AuthResult> {
  const { user, type } = await consumeAndValidateOtp(input, OtpPurpose.REGISTRATION, context);

  if (!user.isVerified) {
    await authRepository.markUserAsVerified(user.id, type);
    user.isVerified = true;

    if (type === OtpType.EMAIL) user.isEmailVerified = true;
    else user.isPhoneVerified = true;
  }

  const roles = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roles, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('otp_verification_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

/**
 *  Handler for verifying OTPs for password reset purposes. 
 *  It validates the provided OTP code, generates a password reset token, and returns it to the user for use in the password reset process.
 * @param input The input containing the OTP code and identifier (email or phone).
 * @param context The request context, including IP address and user agent.
 * @returns An object containing the password reset token.
 */
export async function verifyPasswordResetOtp(
  input: VerifyOtpInput,
  context?: RequestContext,
): Promise<VerifyPasswordResetOtpResult> {
  const { user } = await consumeAndValidateOtp(input, OtpPurpose.PASSWORD_RESET, context);

  const resetToken = await authRepository.storePasswordResetToken(user.id, context);

  securityEvent('otp_verification_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { resetToken };
}

/**
 *  Handler for resetting a user's password. 
 *  It validates the provided password reset token, updates the user's password, and revokes all existing refresh tokens to log the user out of all sessions.
 * @param input The input containing the password reset token and the new password.
 * @param context The request context, including IP address and user agent.
 */
export async function resetPassword(
  input: ResetPasswordInput,
  context?: RequestContext,
): Promise<void> {
  const userId = await authRepository.consumePasswordResetToken(input.resetToken);
  if (!userId) throw new AppError('Invalid or expired password reset token', 401);

  const user = await authRepository.findUserById(userId);
  if (!user) throw new AppError('Account not found', 404);

  const hashedPassword = await bcrypt.hash(input.newPassword, env.BCRYPT_ROUNDS);
  await authRepository.updateUserPassword(user.id, hashedPassword);
  await authRepository.revokeAllRefreshTokens(user.id);

  securityEvent('password_reset_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });
}

/**
 *  Handler for resending OTP codes for both registration and password reset purposes. 
 *  It generates a new OTP code, updates the existing OTP record in the database, and returns the new OTP code along with the channel through which it was sent.
 * @param input The input containing either email or phone and the purpose for which the OTP is being resent (registration or password reset).
 * @param context The request context, including IP address and user agent, which can be used for auditing or security purposes.
 * @returns An object containing the channel ('email' or 'phone') and the new OTP code.
 */
export async function resendOtp(
  input: ResendOtpInput,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {
  const { type, target } = resolveIdentifier(input);
  const otpCode = generateOtpCode();
  const encryptedCode = await bcrypt.hash(otpCode, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  const purpose = await authRepository.resendOtpCode(
    target,
    type,
    encryptedCode,
    expiresAt,
    input.purpose as OtpPurpose | undefined,
    context,
  );

  return { channel: type === OtpType.EMAIL ? 'email' : 'phone', otpCode };
}

/**
 *  Handler for refreshing access tokens using a valid refresh token. 
 *  It validates the provided refresh token, checks if it has been revoked or already used, and if valid, issues a new access token and refresh token pair.
 * @param rawToken The raw refresh token to be validated and used for issuing new tokens.
 * @returns A promise that resolves to an object containing the new access token and refresh token.
 */
export async function refreshTokens(rawToken: string): Promise<TokenPair> {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawToken);
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  const record = await authRepository.consumeRefreshToken(rawToken);
  if (!record) {
    securityEvent('refresh_replay_denied', { userId: payload.sub });
    throw new AppError('Refresh token has already been used or revoked', 401);
  }

  const user = await authRepository.findUserById(payload.sub);
  if (!user) throw new AppError('User not found', 401);
  if (!user.isActive) throw new AppError('Account is deactivated', 403);

  const { token: newRefreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('refresh_success', { userId: user.id });

  return { accessToken, refreshToken: newRefreshToken };
}

/**
 *  Handler for logging out a user. It invalidates the provided refresh token, effectively logging the user out of all sessions that use that token.
 * @param rawToken The raw refresh token to be invalidated.
 */
export async function logout(rawToken: string): Promise<void> {
  try {
    verifyRefreshToken(rawToken);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : '';
    if (!message.includes('expired')) {
      throw new AppError('Invalid refresh token', 400);
    }
  }
  await authRepository.revokeRefreshToken(rawToken);
  securityEvent('logout_success', {});
}
