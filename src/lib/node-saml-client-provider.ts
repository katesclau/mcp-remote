import open from 'open'
import { randomUUID } from 'node:crypto'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { 
  SAML2Provider, 
  SAML2ProviderOptions, 
  SAML2Token, 
  SAML2Claims, 
  SAML2SPMetadata, 
  SAML2AuthRequest 
} from './saml-types'
import { getServerUrlHash, log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'

// Import SAML library (with proper typing)
import * as saml2 from 'saml2-js'
import { parseString as parseXML } from 'xml2js'

// Type definitions for callback functions
type ParseXMLCallback = (err: any, result: any) => void
type SAMLCallback<T = any> = (err: any, ...args: any[]) => void

/**
 * Implements the SAML2Provider interface for Node.js environments.
 * Handles SAML2 authentication flow and assertion storage for MCP clients.
 */
export class NodeSAML2ClientProvider implements SAML2Provider {
  private serverUrlHash: string
  private acsPath: string
  private slsPath: string
  private spEntityId: string
  private nameIdFormat: string
  private sp: saml2.ServiceProvider | null = null
  private idp: saml2.IdentityProvider | null = null
  private pendingRequests: Map<string, SAML2AuthRequest> = new Map()

  /**
   * Creates a new NodeSAML2ClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: SAML2ProviderOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.acsPath = options.acsPath || '/saml/acs'
    this.slsPath = options.slsPath || '/saml/sls'
    this.spEntityId = options.spEntityId || 'mcp-remote-saml-sp'
    this.nameIdFormat = options.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    
    this.initializeSAML()
  }

  get acsUrl(): string {
    return `https://${this.options.host}:${this.options.callbackPort}${this.acsPath}`
  }

  get slsUrl(): string {
    return `https://${this.options.host}:${this.options.callbackPort}${this.slsPath}`
  }

  /**
   * Initialize SAML Service Provider and Identity Provider
   */
  private async initializeSAML(): Promise<void> {
    try {
      // Load or generate SP certificate and private key
      const { certificate, privateKey } = await this.loadOrGenerateCredentials()

      // Create Service Provider
      this.sp = new saml2.ServiceProvider({
        entity_id: this.spEntityId,
        private_key: privateKey,
        certificate: certificate,
        assert_endpoint: this.acsUrl,
        force_authn: this.options.forceAuthn || false,
        auth_context: {
          comparison: 'exact',
          class_refs: ['urn:oasis:names:tc:SAML:1.1:ac:classes:PasswordProtectedTransport']
        },
        nameid_format: this.nameIdFormat,
        sign_get_request: this.options.signRequests || false,
        allow_unencrypted_assertion: !this.options.requireSignedAssertions
      })

      // Initialize IdP from metadata or configuration
      await this.initializeIdP()

      if (DEBUG) debugLog('SAML2 provider initialized successfully')
    } catch (error) {
      log(`Failed to initialize SAML2 provider: ${(error as Error).message}`)
      throw error
    }
  }

  /**
   * Initialize Identity Provider from metadata or configuration
   */
  private async initializeIdP(): Promise<void> {
    if (!this.options.idpMetadata && (!this.options.idpSsoUrl || !this.options.idpEntityId)) {
      throw new Error('Either idpMetadata or idpSsoUrl+idpEntityId must be provided')
    }

    if (this.options.idpMetadata) {
      // Load IdP from metadata URL or XML
      if (this.options.idpMetadata.startsWith('http')) {
        // Fetch metadata from URL
        const response = await fetch(this.options.idpMetadata)
        const metadataXml = await response.text()
        this.idp = new saml2.IdentityProvider({ 
          sso_login_url: '', // Will be extracted from metadata
          sso_logout_url: '', // Will be extracted from metadata
          certificates: [], // Will be extracted from metadata
          force_authn: this.options.forceAuthn || false,
          sign_get_request: this.options.signRequests || false
        })
        // Parse metadata XML to extract URLs and certificates
        await this.parseIdPMetadata(metadataXml)
      } else {
        // Assume it's XML content
        this.idp = new saml2.IdentityProvider({
          sso_login_url: '', // Will be extracted from metadata
          sso_logout_url: '', // Will be extracted from metadata
          certificates: [], // Will be extracted from metadata
          force_authn: this.options.forceAuthn || false,
          sign_get_request: this.options.signRequests || false
        })
        await this.parseIdPMetadata(this.options.idpMetadata)
      }
    } else {
      // Create IdP from direct configuration
      this.idp = new saml2.IdentityProvider({
        sso_login_url: this.options.idpSsoUrl!,
        sso_logout_url: this.options.idpSlsUrl || '',
        certificates: [], // TODO: Load from configuration
        force_authn: this.options.forceAuthn || false,
        sign_get_request: this.options.signRequests || false
      })
    }
  }

  /**
   * Parse IdP metadata XML to extract SSO URLs and certificates
   */
  private async parseIdPMetadata(metadataXml: string): Promise<void> {
    return new Promise((resolve, reject) => {
      parseXML(metadataXml, (err: any, result: any) => {
        if (err) {
          reject(new Error(`Failed to parse IdP metadata: ${err.message}`))
          return
        }

        try {
          // Extract SSO URL, SLS URL, and certificates from metadata
          // This is a simplified parser - in production, you'd want more robust parsing
          const descriptor = result?.EntityDescriptor || result?.['md:EntityDescriptor']
          if (!descriptor) {
            throw new Error('Invalid metadata: EntityDescriptor not found')
          }

          // TODO: Implement proper metadata parsing
          // For now, use provided URLs if metadata parsing fails
          resolve()
        } catch (error) {
          reject(error)
        }
      })
    })
  }

  /**
   * Load existing or generate new SP credentials
   */
  private async loadOrGenerateCredentials(): Promise<{ certificate: string; privateKey: string }> {
    try {
      // Try to load existing credentials
      const certificate = await readTextFile(this.serverUrlHash, 'saml_certificate.pem')
      const privateKey = await readTextFile(this.serverUrlHash, 'saml_private_key.pem')
      
      if (certificate && privateKey) {
        if (DEBUG) debugLog('Loaded existing SAML credentials')
        return { certificate, privateKey }
      }
    } catch (error) {
      if (DEBUG) debugLog('No existing SAML credentials found, will generate new ones')
    }

    // Generate new credentials if none exist or provided in options
    if (this.options.certificate && this.options.privateKey) {
      await writeTextFile(this.serverUrlHash, 'saml_certificate.pem', this.options.certificate)
      await writeTextFile(this.serverUrlHash, 'saml_private_key.pem', this.options.privateKey)
      return {
        certificate: this.options.certificate,
        privateKey: this.options.privateKey
      }
    }

    // For now, throw an error if no credentials are provided
    // In a full implementation, you might generate self-signed certificates
    throw new Error('SAML credentials must be provided in options.certificate and options.privateKey')
  }

  /**
   * Generate SAML authentication request URL
   */
  async getAuthUrl(relayState?: string): Promise<{ url: string; requestId: string }> {
    if (!this.sp || !this.idp) {
      throw new Error('SAML provider not initialized')
    }

    const requestId = randomUUID()
    const authRequest: SAML2AuthRequest = {
      id: requestId,
      relayState,
      timestamp: new Date()
    }

    // Store pending request
    this.pendingRequests.set(requestId, authRequest)

    return new Promise((resolve, reject) => {
      this.sp!.create_login_request_url(this.idp!, {}, (err: any, login_url: any, request_id: any) => {
        if (err) {
          this.pendingRequests.delete(requestId)
          reject(new Error(`Failed to create SAML login request: ${err.message || err}`))
          return
        }

        if (DEBUG) debugLog('Generated SAML auth URL', { requestId, login_url })
        resolve({ url: login_url, requestId })
      })
    })
  }

  /**
   * Process SAML response and extract token
   */
  async processResponse(samlResponse: string, relayState?: string): Promise<SAML2Token> {
    if (!this.sp || !this.idp) {
      throw new Error('SAML provider not initialized')
    }

    return new Promise((resolve, reject) => {
      const options = {
        request_body: {
          SAMLResponse: samlResponse,
          RelayState: relayState
        },
        allow_unencrypted_assertion: !this.options.requireSignedAssertions
      }

      this.sp!.post_assert(this.idp!, options, async (err: any, saml_response: any) => {
        if (err) {
          reject(new Error(`Failed to process SAML response: ${err.message || err}`))
          return
        }

        try {
          // Extract claims from SAML response
          const claims = this.extractClaims(saml_response)
          
          // Create token with Base64-encoded assertion
          const assertion = Buffer.from(samlResponse, 'utf8').toString('base64')
          const token: SAML2Token = {
            assertion,
            claims,
            issuedAt: new Date(),
            expiresAt: claims.expiresAt || new Date(Date.now() + 30 * 60 * 1000) // Default 30 minutes
          }

          // Store token
          await this.storeToken(token)

          if (DEBUG) debugLog('Processed SAML response successfully', { 
            nameId: claims.nameId,
            email: claims.email,
            expiresAt: token.expiresAt
          })

          resolve(token)
        } catch (error) {
          reject(new Error(`Failed to extract claims from SAML response: ${(error as Error).message}`))
        }
      })
    })
  }

  /**
   * Extract claims from SAML response
   */
  private extractClaims(samlResponse: any): SAML2Claims {
    const claims: SAML2Claims = {
      nameId: samlResponse.user?.name_id || '',
      sessionIndex: samlResponse.user?.session_index,
      email: samlResponse.user?.attributes?.email?.[0] || samlResponse.user?.attributes?.Email?.[0],
      firstName: samlResponse.user?.attributes?.firstName?.[0] || samlResponse.user?.attributes?.FirstName?.[0],
      lastName: samlResponse.user?.attributes?.lastName?.[0] || samlResponse.user?.attributes?.LastName?.[0],
      displayName: samlResponse.user?.attributes?.displayName?.[0] || samlResponse.user?.attributes?.DisplayName?.[0],
      attributes: samlResponse.user?.attributes || {},
      issuer: samlResponse.response_header?.destination
    }

    // Parse groups if present
    const groups = samlResponse.user?.attributes?.groups || samlResponse.user?.attributes?.Groups
    if (groups) {
      claims.groups = Array.isArray(groups) ? groups : [groups]
    }

    // Set expiration based on conditions
    if (samlResponse.user?.session_not_on_or_after) {
      claims.expiresAt = new Date(samlResponse.user.session_not_on_or_after)
    }

    return claims
  }

  /**
   * Generate SP metadata XML
   */
  async getMetadata(): Promise<SAML2SPMetadata> {
    if (!this.sp) {
      throw new Error('SAML provider not initialized')
    }

    return new Promise((resolve, reject) => {
      this.sp!.create_metadata((err: any, metadata: any) => {
        if (err) {
          reject(new Error(`Failed to generate SP metadata: ${err.message || err}`))
          return
        }

        const spMetadata: SAML2SPMetadata = {
          entityId: this.spEntityId,
          acsUrl: this.acsUrl,
          slsUrl: this.slsUrl,
          metadataXml: metadata,
          certificate: this.options.certificate
        }

        resolve(spMetadata)
      })
    })
  }

  /**
   * Generate logout request URL
   */
  async getLogoutUrl(nameId: string, sessionIndex?: string): Promise<{ url: string; requestId: string }> {
    if (!this.sp || !this.idp) {
      throw new Error('SAML provider not initialized')
    }

    const requestId = randomUUID()

    return new Promise((resolve, reject) => {
      const options = {
        name_id: nameId,
        session_index: sessionIndex
      }

      this.sp!.create_logout_request_url(this.idp!, options, (err: any, logout_url: any) => {
        if (err) {
          reject(new Error(`Failed to create SAML logout request: ${err.message || err}`))
          return
        }

        if (DEBUG) debugLog('Generated SAML logout URL', { requestId, logout_url })
        resolve({ url: logout_url, requestId })
      })
    })
  }

  /**
   * Process logout response
   */
  async processLogoutResponse(samlResponse: string): Promise<boolean> {
    // For simplicity, assume logout was successful
    // In a full implementation, you'd validate the logout response
    await this.clearStoredToken()
    return true
  }

  /**
   * Validate token (check expiration, etc.)
   */
  async validateToken(token: SAML2Token): Promise<boolean> {
    const now = new Date()
    
    // Check if token is expired
    if (token.expiresAt && now > token.expiresAt) {
      if (DEBUG) debugLog('Token is expired', { expiresAt: token.expiresAt, now })
      return false
    }

    // Token is valid
    return true
  }

  /**
   * Get stored SAML token
   */
  async getStoredToken(): Promise<SAML2Token | undefined> {
    try {
      const tokenData = await readJsonFile<any>(this.serverUrlHash, 'saml_token.json', undefined)
      if (!tokenData) return undefined

      const token: SAML2Token = {
        assertion: tokenData.assertion,
        claims: tokenData.claims,
        issuedAt: new Date(tokenData.issuedAt),
        expiresAt: new Date(tokenData.expiresAt)
      }

      // Validate token before returning
      const isValid = await this.validateToken(token)
      if (!isValid) {
        await this.clearStoredToken()
        return undefined
      }

      return token
    } catch (error) {
      if (DEBUG) debugLog('No stored SAML token found or failed to read')
      return undefined
    }
  }

  /**
   * Store SAML token
   */
  private async storeToken(token: SAML2Token): Promise<void> {
    const tokenData = {
      assertion: token.assertion,
      claims: token.claims,
      issuedAt: token.issuedAt.toISOString(),
      expiresAt: token.expiresAt.toISOString()
    }

    await writeJsonFile(this.serverUrlHash, 'saml_token.json', tokenData)
    if (DEBUG) debugLog('Stored SAML token')
  }

  /**
   * Clear stored token
   */
  private async clearStoredToken(): Promise<void> {
    try {
      await deleteConfigFile(this.serverUrlHash, 'saml_token.json')
      if (DEBUG) debugLog('Cleared stored SAML token')
    } catch (error) {
      // Ignore errors when clearing
    }
  }

  /**
   * Get current token for authorization
   */
  async getCurrentToken(): Promise<string | undefined> {
    const token = await this.getStoredToken()
    return token?.assertion
  }
} 