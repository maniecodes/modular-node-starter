export const API_VERSION = 'v1';

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;

export const OTP_RESEND_COOLDOWN_MS = 60 * 1000; // 1 minute cooldown between OTP resend requests
export const OTP_EXPIRY_SKEW_MS = 5 * 1000; // Allow a 5 second skew for OTP expiry to account for potential clock differences between server and client
export const MAX_OTP_REQUESTS_PER_WINDOW = 3; // Maximum OTP requests allowed within the cooldown window before blocking further requests

export const PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = 15; // Password reset tokens are valid for 15 minutes
export const INVITE_TOKEN_EXPIRY_HOURS = 48; // Invite tokens are valid for 48 hours