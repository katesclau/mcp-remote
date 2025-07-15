import { EventEmitter } from 'events'
import { OAuthClientInformationFull, OAuthClientMetadata } from '@modelcontextprotocol/sdk/shared/auth.js'
import { SAML2ProviderOptions } from './saml-types.js'

/**
 * Options for creating an OAuth client provider
 */
export interface OAuthProviderOptions {
  /** Server URL to connect to */
  serverUrl: string
  /** Port for the OAuth callback server */
  callbackPort: number
  /** Desired hostname for the OAuth callback server */
  host: string
  /** Path for the OAuth callback endpoint */
  callbackPath?: string
  /** Directory to store OAuth credentials */
  configDir?: string
  /** Client name to use for OAuth registration */
  clientName?: string
  /** Client URI to use for OAuth registration */
  clientUri?: string
  /** Software ID to use for OAuth registration */
  softwareId?: string
  /** Software version to use for OAuth registration */
  softwareVersion?: string
  /** Static OAuth client metadata to override default OAuth client metadata */
  staticOAuthClientMetadata?: StaticOAuthClientMetadata
  /** Static OAuth client information to use instead of OAuth registration */
  staticOAuthClientInfo?: StaticOAuthClientInformationFull
  /** Resource parameter to send to the authorization server */
  authorizeResource?: string
}

/**
 * OAuth callback server setup options
 */
export interface OAuthCallbackServerOptions {
  /** Port for the callback server */
  port: number
  /** Path for the callback endpoint */
  path: string
  /** Event emitter to signal when auth code is received */
  events: EventEmitter
}

// optional static OAuth client information
export type StaticOAuthClientMetadata = OAuthClientMetadata | null | undefined
export type StaticOAuthClientInformationFull = OAuthClientInformationFull | null | undefined

/**
 * Authentication provider options - can be OAuth or SAML2
 */
export interface AuthProviderOptions {
  /** Authentication type */
  authType: 'oauth' | 'saml2'
  /** OAuth provider options (when authType is 'oauth') */
  oauth?: OAuthProviderOptions
  /** SAML2 provider options (when authType is 'saml2') */
  saml2?: SAML2ProviderOptions
}

/**
 * Unified authentication provider interface
 */
export interface UnifiedAuthProvider {
  /** Get current access token/assertion for authorization */
  getCurrentToken(): Promise<string | undefined>
  /** Initialize authentication flow */
  initializeAuth(): Promise<{ 
    server: any; 
    waitForAuth: () => Promise<string | { response: string; relayState?: string }>; 
    skipBrowserAuth: boolean 
  }>
  /** Get authentication URL for browser redirect */
  getAuthUrl?(relayState?: string): Promise<{ url: string; requestId: string }>
  /** Process authentication response */
  processAuthResponse?(responseData: string | { response: string; relayState?: string }): Promise<any>
}
