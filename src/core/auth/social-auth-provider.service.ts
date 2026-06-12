import { AppError } from '@/core/errors/AppError';
import { OAuth2Client } from 'google-auth-library';

let googleClient: OAuth2Client | null = null;

function getGoogleClient(): OAuth2Client {
    if (!googleClient) {
        googleClient = new OAuth2Client();
    }
    return googleClient;
}

export type GoogleIdTokenPayload = {
    sub?: string;
    email?: string;
    email_verified?: boolean;
    given_name?: string;
    family_name?: string;
    name?: string;
};

export type FacebookDebugTokenResult = {
    userId: string;
    appId: string;
    isValid: boolean;
};

export type FacebookProfile = {
    id?: string;
    email?: string;
    first_name?: string;
    last_name?: string;
    name?: string;
};

export async function exchangeGoogleAuthorizationCode(input: {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
}): Promise<{ idToken: string }> {
    const body = new URLSearchParams({
        code: input.code,
        client_id: input.clientId,
        client_secret: input.clientSecret,
        redirect_uri: input.redirectUri,
        grant_type: 'authorization_code',
    });

    let tokenJson: { id_token?: string };
    try {
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
        });

        if (!tokenRes.ok) {
            throw new AppError('Unable to exchange Google authorization code', 401);
        }

        tokenJson = (await tokenRes.json()) as { id_token?: string };
    } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('Unable to exchange Google authorization code', 401);
    }

    if (!tokenJson.id_token) {
        throw new AppError('Google token exchange did not return id token', 401);
    }

    return { idToken: tokenJson.id_token };
}

export async function verifyGoogleIdToken(input: {
    idToken: string;
    audience: string;
}): Promise<GoogleIdTokenPayload> {
    try {
        const ticket = await getGoogleClient().verifyIdToken({
            idToken: input.idToken,
            audience: input.audience,
        });
        return (ticket.getPayload() ?? {}) as GoogleIdTokenPayload;
    } catch {
        throw new AppError('Invalid Google ID token', 401);
    }
}

export async function exchangeFacebookAuthorizationCode(input: {
    code: string;
    appId: string;
    appSecret: string;
    redirectUri: string;
}): Promise<{ accessToken: string }> {
    const tokenUrl = new URL('https://graph.facebook.com/v23.0/oauth/access_token');
    tokenUrl.searchParams.set('client_id', input.appId);
    tokenUrl.searchParams.set('client_secret', input.appSecret);
    tokenUrl.searchParams.set('redirect_uri', input.redirectUri);
    tokenUrl.searchParams.set('code', input.code);

    let tokenJson: { access_token?: string };
    try {
        const tokenRes = await fetch(tokenUrl);
        if (!tokenRes.ok) {
            throw new AppError('Unable to exchange Facebook authorization code', 401);
        }

        tokenJson = (await tokenRes.json()) as { access_token?: string };
    } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('Unable to exchange Facebook authorization code', 401);
    }

    if (!tokenJson.access_token) {
        throw new AppError('Facebook token exchange did not return access token', 401);
    }

    return { accessToken: tokenJson.access_token };
}

export async function verifyFacebookAccessToken(input: {
    userAccessToken: string;
    appAccessToken: string;
}): Promise<FacebookDebugTokenResult> {
    const debugUrl = new URL('https://graph.facebook.com/debug_token');
    debugUrl.searchParams.set('input_token', input.userAccessToken);
    debugUrl.searchParams.set('access_token', input.appAccessToken);

    try {
        const debugRes = await fetch(debugUrl);
        if (!debugRes.ok) {
            throw new AppError('Unable to verify Facebook access token', 401);
        }

        const debugJson = (await debugRes.json()) as {
            data?: { is_valid?: boolean; app_id?: string; user_id?: string };
        };

        if (!debugJson.data?.is_valid) {
            throw new AppError('Invalid Facebook access token', 401);
        }

        if (!debugJson.data.user_id || !debugJson.data.app_id) {
            throw new AppError('Facebook token verification response is incomplete', 401);
        }

        return {
            userId: debugJson.data.user_id,
            appId: debugJson.data.app_id,
            isValid: true,
        };
    } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('Unable to verify Facebook access token', 401);
    }
}

export async function fetchFacebookProfile(accessToken: string): Promise<FacebookProfile> {
    const profileUrl = new URL('https://graph.facebook.com/v23.0/me');
    profileUrl.searchParams.set('fields', 'id,email,first_name,last_name,name');
    profileUrl.searchParams.set('access_token', accessToken);

    try {
        const profileRes = await fetch(profileUrl);
        if (!profileRes.ok) {
            throw new AppError('Unable to fetch Facebook profile', 401);
        }

        return (await profileRes.json()) as FacebookProfile;
    } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('Unable to fetch Facebook profile', 401);
    }
}
