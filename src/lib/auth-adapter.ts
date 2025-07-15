import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import { OAuthTokens, OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js'
import { NodeSAML2ClientProvider } from './node-saml-client-provider'
import { debugLog, DEBUG } from './utils'

/**
 * Adapter that makes SAML2 providers compatible with the OAuth interface
 * expected by the MCP SDK transport layers
 */
export class SAML2ToOAuthAdapter implements OAuthClientProvider {
  constructor(private samlProvider: NodeSAML2ClientProvider) {}

  /**
   * Returns the SAML2 provider's state (not used in SAML2 flow)
   */
  state(): string {
    return 'saml2-adapter-state'
  }

  /**
   * Get redirect URL (adapted from SAML2 ACS URL)
   */
  get redirectUrl(): string {
    return this.samlProvider.acsUrl
  }

  /**
   * Get client metadata (adapted for SAML2)
   */
  get clientMetadata() {
    return {
      redirect_uris: [this.samlProvider.acsUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      client_name: 'SAML2 Client',
      client_uri: 'https://github.com/modelcontextprotocol/mcp-remote',
    }
  }

  /**
   * Code verifier (not used in SAML2, but required by interface)
   */
  codeVerifier(): Promise<string> {
    return Promise.resolve('saml2-code-verifier-placeholder')
  }

  /**
   * Save code verifier (not applicable for SAML2)
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (DEBUG) debugLog('saveCodeVerifier called on SAML2 adapter (no-op)', { codeVerifier })
  }

  /**
   * Converts SAML2 assertion to OAuth-like tokens structure
   * This allows the transport layer to use the same token logic
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    try {
      const assertion = await this.samlProvider.getCurrentToken()
      
      if (!assertion) {
        if (DEBUG) debugLog('No SAML2 assertion available')
        return undefined
      }

      // Get stored token for expiry information
      const storedToken = await this.samlProvider.getStoredToken()
      
      if (!storedToken) {
        if (DEBUG) debugLog('No stored SAML2 token found')
        return undefined
      }

      // Calculate expires_in (seconds until expiration)
      const now = new Date()
      const expiresIn = Math.max(0, Math.floor((storedToken.expiresAt.getTime() - now.getTime()) / 1000))

      // Create OAuth-like token structure using SAML assertion as access_token
      const oauthLikeTokens: OAuthTokens = {
        access_token: assertion, // Use Base64-encoded SAML assertion as access token
        token_type: 'Bearer',
        expires_in: expiresIn,
        // SAML2 doesn't have refresh tokens, but we can provide minimal compatibility
        refresh_token: undefined,
        scope: undefined
      }

      if (DEBUG) debugLog('Converted SAML2 assertion to OAuth-like tokens', {
        hasAssertion: !!assertion,
        expiresIn,
        expiresAt: storedToken.expiresAt
      })

      return oauthLikeTokens
    } catch (error) {
      if (DEBUG) debugLog('Error converting SAML2 assertion to OAuth tokens', error)
      return undefined
    }
  }

  /**
   * Save tokens (not applicable for SAML2, but required by interface)
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    // SAML2 tokens are managed by the SAML provider itself
    // This method is called by the transport after successful auth
    if (DEBUG) debugLog('saveTokens called on SAML2 adapter (no-op)', {
      hasAccessToken: !!tokens.access_token,
      expiresIn: tokens.expires_in
    })
  }

  /**
   * Get client information (not directly applicable to SAML2)
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    // SAML2 doesn't use OAuth client registration, but we can return minimal info
    return {
      client_id: 'saml2-client',
      client_name: 'SAML2 Client',
      redirect_uris: [this.samlProvider.acsUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
    }
  }

  /**
   * Redirect to authorization (adapted for SAML2)
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // For SAML2, we need to generate our own auth URL and redirect there instead
    try {
      const { url } = await this.samlProvider.getAuthUrl()
      
      if (DEBUG) debugLog('Redirecting to SAML2 authentication URL', { url })
      
      // Import open dynamically to avoid import issues
      const { default: open } = await import('open')
      await open(url)
      
      console.log(`\nPlease complete SAML2 authentication by visiting:\n${url}\n`)
    } catch (error) {
      console.error('Failed to redirect to SAML2 authentication:', error)
      throw error
    }
  }

  /**
   * Invalidate credentials (adapted for SAML2)
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    if (DEBUG) debugLog('Invalidating SAML2 credentials', { scope })
    
    // For SAML2, we primarily care about clearing the stored token
    if (scope === 'all' || scope === 'tokens') {
      try {
        // Clear the stored SAML token by calling the private method via reflection
        await (this.samlProvider as any).clearStoredToken()
        if (DEBUG) debugLog('SAML2 tokens cleared')
      } catch (error) {
        if (DEBUG) debugLog('Error clearing SAML2 tokens', error)
      }
    }
  }

  /**
   * Get the underlying SAML2 provider for direct access when needed
   */
  getSAMLProvider(): NodeSAML2ClientProvider {
    return this.samlProvider
  }
}

/**
 * Factory function to create the appropriate auth provider based on auth mode
 */
export function createAuthProvider(
  authMode: 'oauth' | 'saml2',
  oauthProvider?: any,
  samlProvider?: NodeSAML2ClientProvider
): OAuthClientProvider {
  if (authMode === 'saml2') {
    if (!samlProvider) {
      throw new Error('SAML2 provider is required when using SAML2 auth mode')
    }
    return new SAML2ToOAuthAdapter(samlProvider)
  } else {
    if (!oauthProvider) {
      throw new Error('OAuth provider is required when using OAuth auth mode')
    }
    return oauthProvider
  }
} 