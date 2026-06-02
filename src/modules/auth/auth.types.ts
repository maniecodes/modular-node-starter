// src/modules/auth/auth.types.ts
export interface RegisterInput {
  name: string;
  email: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface RefreshInput {
  refreshToken: string;
}

export interface AuthUser {
  id: string;
  name: string;
  email: string;
}
