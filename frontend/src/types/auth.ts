import { UserRole } from './enums';

/**
 * Authentication & API Key DTOs
 * matching backend/crates/shared-types/src/auth.rs
 */

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string; // "Bearer"
  expires_in: number; // e.g. 900
  user: UserProfile;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface ApiKeyResponse {
  id: string;
  name: string;
  key_prefix: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface CreateApiKeyRequest {
  name: string;
  expires_at?: string | null;
}

export interface CreateApiKeyResponse {
  id: string;
  name: string;
  key_prefix: string;
  secret_key: string; // Exposed once upon creation
  expires_at: string | null;
  created_at: string;
}
