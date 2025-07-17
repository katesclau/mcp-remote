import { EventEmitter } from 'events'

/**
 * SAML2 Configuration options
 */
export interface SAML2ProviderOptions {
  /** Server URL to connect to */
  serverUrl: string
  /** Port for the SAML callback server */
  callbackPort: number
  /** Desired hostname for the SAML callback server */
  host: string
  /** Path for the SAML ACS (Assertion Consumer Service) endpoint */
  acsPath?: string
  /** Path for the SAML SLS (Single Logout Service) endpoint */
  slsPath?: string
  /** Directory to store SAML credentials and metadata */
  configDir?: string
  /** Entity ID for the Service Provider (SP) */
  spEntityId?: string
  /** IdP metadata URL or XML content */
  idpMetadata?: string
  /** IdP SSO URL */
  idpSsoUrl?: string
  /** IdP SLS URL */
  idpSlsUrl?: string
  /** IdP Entity ID */
  idpEntityId?: string
  /** Private key for SAML signing */
  privateKey?: string
  /** Certificate for SAML signing */
  certificate?: string
  /** IdP certificate for signature validation */
  idpCert?: string
  /** Whether to sign SAML requests */
  signRequests?: boolean
  /** Whether to require signed assertions */
  requireSignedAssertions?: boolean
  /** NameID format to use */
  nameIdFormat?: string
  /** Force authentication */
  forceAuthn?: boolean
  /** Allow IdP-initiated SSO */
  allowIdpInitiated?: boolean
}

/**
 * SAML2 callback server setup options
 */
export interface SAML2CallbackServerOptions {
  /** Port for the callback server */
  port: number
  /** Path for the ACS endpoint */
  acsPath: string
  /** Path for the SLS endpoint */
  slsPath: string
  /** Event emitter to signal when SAML response is received */
  events: EventEmitter
}

/**
 * SAML2 User Claims extracted from SAML assertion
 */
export interface SAML2Claims {
  /** NameID from SAML assertion */
  nameId: string
  /** Session index for logout */
  sessionIndex?: string
  /** Email address */
  email?: string
  /** First name */
  firstName?: string
  /** Last name */
  lastName?: string
  /** Display name */
  displayName?: string
  /** Groups/roles */
  groups?: string[]
  /** Custom attributes */
  attributes?: Record<string, string | string[]>
  /** Assertion expiration time */
  expiresAt?: Date
  /** Assertion issued at time */
  issuedAt?: Date
  /** Issuer (IdP) entity ID */
  issuer?: string
}

/**
 * SAML2 Token - contains the Base64-encoded SAML assertion
 */
export interface SAML2Token {
  /** Base64-encoded SAML assertion */
  assertion: string
  /** Claims extracted from the assertion */
  claims: SAML2Claims
  /** Token expiration time */
  expiresAt: Date
  /** Token issued at time */
  issuedAt: Date
}

/**
 * SAML2 Authentication Request information
 */
export interface SAML2AuthRequest {
  /** Request ID */
  id: string
  /** Relay state for maintaining application state */
  relayState?: string
  /** Timestamp when request was created */
  timestamp: Date
}

/**
 * SAML2 Service Provider metadata
 */
export interface SAML2SPMetadata {
  /** SP Entity ID */
  entityId: string
  /** ACS URL */
  acsUrl: string
  /** SLS URL */
  slsUrl: string
  /** Metadata XML */
  metadataXml: string
  /** X.509 Certificate for verification */
  certificate?: string
}

/**
 * SAML2 Authentication Provider interface
 */
export interface SAML2Provider {
  /** Generate SAML authentication request URL */
  getAuthUrl(relayState?: string): Promise<{ url: string; requestId: string }>

  /** Process SAML response and extract token */
  processResponse(samlResponse: string, relayState?: string): Promise<SAML2Token>

  /** Generate SP metadata XML */
  getMetadata(): Promise<SAML2SPMetadata>

  /** Generate logout request URL */
  getLogoutUrl(nameId: string, sessionIndex?: string): Promise<{ url: string; requestId: string }>

  /** Process logout response */
  processLogoutResponse(samlResponse: string): Promise<boolean>

  /** Validate token (check expiration, etc.) */
  validateToken(token: SAML2Token): Promise<boolean>
}

/**
 * SAML2 Auth flow events
 */
export interface SAML2AuthEvents {
  'auth-request': (requestId: string, authUrl: string) => void
  'auth-response': (token: SAML2Token) => void
  'auth-error': (error: Error) => void
  'logout-request': (requestId: string, logoutUrl: string) => void
  'logout-response': (success: boolean) => void
}
