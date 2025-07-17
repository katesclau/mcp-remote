import open from 'open'
import { randomUUID } from 'node:crypto'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { SAML2Provider, SAML2ProviderOptions, SAML2Token, SAML2Claims, SAML2SPMetadata, SAML2AuthRequest } from './saml-types'
import { getServerUrlHash, log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'

// Import new SAML library
import { SAML, Profile } from '@node-saml/node-saml'
import { parseString as parseXML } from 'xml2js'

// Type definitions for callback functions
type ParseXMLCallback = (err: any, result: any) => void

/**
 * Implements the SAML2Provider interface for Node.js environments using @node-saml/node-saml.
 * Handles SAML2 authentication flow and assertion storage for MCP clients.
 */
export class NodeSAML2ClientProvider implements SAML2Provider {
  private serverUrlHash: string
  private acsPath: string
  private slsPath: string
  private spEntityId: string
  private nameIdFormat: string
  private saml: SAML | null = null
  private pendingRequests: Map<string, SAML2AuthRequest> = new Map()
  private initializationPromise: Promise<void>

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

    this.initializationPromise = this.initializeSAML()
  }

  get acsUrl(): string {
    // For HTTPS URLs, don't include port number (use standard 443)
    return `https://${this.options.host}${this.acsPath}`
  }

  get slsUrl(): string {
    // For HTTPS URLs, don't include port number (use standard 443)
    return `https://${this.options.host}${this.slsPath}`
  }

  /**
   * Initialize SAML Service Provider
   */
  private async initializeSAML(): Promise<void> {
    try {
      // Load or generate SP certificate and private key
      const { certificate, privateKey } = await this.loadOrGenerateCredentials()

      // Initialize IdP configuration
      const idpConfig = await this.initializeIdPConfig()

      // Create SAML instance with node-saml configuration
      this.saml = new SAML({
        // Service Provider configuration
        issuer: this.spEntityId,
        callbackUrl: this.acsUrl,
        privateKey: privateKey,
        publicCert: certificate,

        // Identity Provider configuration
        entryPoint: idpConfig.ssoUrl,
        logoutUrl: idpConfig.logoutUrl || idpConfig.ssoUrl,
        // Enable IdP certificate for signature validation
        idpCert: this.options.idpCert || [],

        // Authentication settings (enable signature validation)
        wantAssertionsSigned: this.options.requireSignedAssertions !== false,
        wantAuthnResponseSigned: this.options.requireSignedAssertions !== false,
        signatureAlgorithm: 'sha256',
        digestAlgorithm: 'sha256',

        // Request signing  
        authnRequestBinding: 'HTTP-Redirect',

        // NameID format
        identifierFormat: this.nameIdFormat,

        // Additional options
        forceAuthn: this.options.forceAuthn || false,
        skipRequestCompression: false,
        disableRequestedAuthnContext: true,
        acceptedClockSkewMs: 0,
        maxAssertionAgeMs: 3600000, // 1 hour
        cacheProvider: {
          saveAsync: async (key: string, value: string) => {
            // Simple cache implementation - in production, use Redis or similar
            return Promise.resolve({ createdAt: Date.now(), value })
          },
          getAsync: async (key: string) => {
            // Simple cache implementation
            return Promise.resolve(null)
          },
          removeAsync: async (key: string) => {
            return Promise.resolve(null)
          }
        }
      })

      if (DEBUG) debugLog('SAML2 provider initialized successfully', {
        hasIdpCert: 'disabled for testing',
        idpCertLength: 0,
        wantAssertionsSigned: false,
        wantAuthnResponseSigned: false
      })
    } catch (error) {
      log(`Failed to initialize SAML2 provider: ${(error as Error).message}`)
      throw error
    }
  }

  /**
   * Initialize Identity Provider configuration from metadata or direct config
   */
  private async initializeIdPConfig(): Promise<{
    ssoUrl: string
    logoutUrl?: string
    certificates: string | string[]
  }> {
    if (!this.options.idpMetadata && (!this.options.idpSsoUrl || !this.options.idpEntityId)) {
      throw new Error('Either idpMetadata or idpSsoUrl+idpEntityId must be provided')
    }

    if (this.options.idpMetadata) {
      // Load IdP from metadata URL or XML
      let metadataXml: string

      if (this.options.idpMetadata.startsWith('http')) {
        // Fetch metadata from URL
        const response = await fetch(this.options.idpMetadata)
        metadataXml = await response.text()
      } else {
        // Assume it's XML content
        metadataXml = this.options.idpMetadata
      }

      // Parse metadata XML to extract URLs and certificates
      return await this.parseIdPMetadata(metadataXml)
    } else {
      // Create IdP from direct configuration
      return {
        ssoUrl: this.options.idpSsoUrl!,
        logoutUrl: this.options.idpSlsUrl,
        certificates: [], // TODO: Load from configuration if needed
      }
    }
  }

  /**
   * Parse IdP metadata XML to extract SSO URLs and certificates
   */
  private async parseIdPMetadata(metadataXml: string): Promise<{
    ssoUrl: string
    logoutUrl?: string
    certificates: string[]
  }> {
    return new Promise((resolve, reject) => {
      parseXML(metadataXml, (err: any, result: any) => {
        if (err) {
          reject(new Error(`Failed to parse IdP metadata: ${err.message}`))
          return
        }

        try {
          const descriptor = result.EntityDescriptor || result['md:EntityDescriptor']
          if (!descriptor) {
            throw new Error('Invalid metadata: no EntityDescriptor found')
          }

          const ssoDescriptor = descriptor.IDPSSODescriptor?.[0] || descriptor['md:IDPSSODescriptor']?.[0]
          if (!ssoDescriptor) {
            throw new Error('Invalid metadata: no IDPSSODescriptor found')
          }

          // Extract SSO service URL
          const ssoServices = ssoDescriptor.SingleSignOnService || ssoDescriptor['md:SingleSignOnService'] || []
          const redirectBinding = ssoServices.find(
            (service: any) => service.$.Binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          )

          if (!redirectBinding) {
            throw new Error('No HTTP-Redirect SSO service found in metadata')
          }

          const ssoUrl = redirectBinding.$.Location

          // Extract logout service URL (optional)
          const logoutServices = ssoDescriptor.SingleLogoutService || ssoDescriptor['md:SingleLogoutService'] || []
          const logoutService = logoutServices.find(
            (service: any) => service.$.Binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          )
          const logoutUrl = logoutService?.$.Location

          // Extract certificates
          const keyDescriptors = ssoDescriptor.KeyDescriptor || ssoDescriptor['md:KeyDescriptor'] || []
          const certificates: string[] = []

          for (const keyDescriptor of keyDescriptors) {
            const keyInfo = keyDescriptor.KeyInfo?.[0] || keyDescriptor['ds:KeyInfo']?.[0]
            const x509Data = keyInfo?.X509Data?.[0] || keyInfo?.[`ds:X509Data`]?.[0]
            const x509Certificate = x509Data?.X509Certificate?.[0] || x509Data?.[`ds:X509Certificate`]?.[0]

            if (x509Certificate) {
              // Clean up certificate (remove whitespace) and format as PEM
              const cleanCert = x509Certificate.replace(/\s+/g, '')
              // Add PEM headers and format with line breaks every 64 characters
              const formattedCert = cleanCert.match(/.{1,64}/g)?.join('\n') || cleanCert
              const pemCert = `-----BEGIN CERTIFICATE-----\n${formattedCert}\n-----END CERTIFICATE-----`
              certificates.push(pemCert)
            }
          }

          if (DEBUG) debugLog('Parsed IdP metadata', { ssoUrl, logoutUrl, certificateCount: certificates.length })

          resolve({
            ssoUrl,
            logoutUrl,
            certificates,
          })
        } catch (error) {
          reject(new Error(`Failed to parse IdP metadata: ${(error as Error).message}`))
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
      if (DEBUG) debugLog('No existing SAML credentials found, will use provided ones')
    }

    // Use credentials from options
    if (this.options.certificate && this.options.privateKey) {
      await writeTextFile(this.serverUrlHash, 'saml_certificate.pem', this.options.certificate)
      await writeTextFile(this.serverUrlHash, 'saml_private_key.pem', this.options.privateKey)
      return {
        certificate: this.options.certificate,
        privateKey: this.options.privateKey,
      }
    }

    // For now, throw an error if no credentials are provided
    throw new Error('SAML credentials must be provided in options.certificate and options.privateKey')
  }

  /**
   * Generate SAML authentication request URL
   */
  async getAuthUrl(relayState?: string): Promise<{ url: string; requestId: string }> {
    // Ensure initialization is complete
    await this.initializationPromise

    if (!this.saml) {
      throw new Error('SAML provider not initialized')
    }

    const requestId = randomUUID()
    const authRequest: SAML2AuthRequest = {
      id: requestId,
      relayState,
      timestamp: new Date(),
    }

    // Store pending request
    this.pendingRequests.set(requestId, authRequest)

        try {
      const loginUrl = await this.saml.getAuthorizeUrlAsync(relayState || '', this.options.host || '', {})
      
      if (DEBUG) debugLog('Generated SAML auth URL', { requestId, loginUrl })
      return { url: loginUrl, requestId }
    } catch (error) {
      this.pendingRequests.delete(requestId)
      throw new Error(`Failed to create SAML login request: ${(error as Error).message}`)
    }
  }

  /**
   * Process SAML response and extract token
   */
  async processResponse(samlResponse: string, relayState?: string): Promise<SAML2Token> {
    // Ensure initialization is complete
    await this.initializationPromise

    if (!this.saml) {
      throw new Error('SAML provider not initialized')
    }

    try {
      if (DEBUG) debugLog('Processing SAML response', { 
        responseLength: samlResponse.length,
        hasIdpCert: !!this.options.idpCert,
        wantAssertionsSigned: this.options.requireSignedAssertions,
        idpCertLength: this.options.idpCert?.length || 0
      })

      // Decode and log the SAML response for debugging
      if (DEBUG) {
        try {
          const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf8')
          
          // Count signatures and their locations
          const responseSignatures = (decodedResponse.match(/<ds:Signature[^>]*>/g) || []).length
          const assertionSignatures = decodedResponse.includes('<saml:Assertion') && decodedResponse.includes('<ds:Signature')
          
          // Check signature position
          const responseHasSignature = decodedResponse.indexOf('<ds:Signature') > 0 && 
                                       decodedResponse.indexOf('<ds:Signature') < decodedResponse.indexOf('<saml:Assertion')
          
          debugLog('SAML response signature analysis', { 
            preview: decodedResponse.substring(0, 800) + '...',
            totalSignatures: responseSignatures,
            responseHasSignature,
            assertionSignatures,
            signaturePositions: (decodedResponse.match(/<ds:Signature[^>]*>/g) || []).map((_, i) => decodedResponse.indexOf('<ds:Signature', i > 0 ? decodedResponse.indexOf('<ds:Signature') + 1 : 0))
          })
        } catch (e) {
          debugLog('Failed to decode SAML response for analysis')
        }
      }

      // Log SAML configuration for debugging
      if (DEBUG && this.saml) {
        debugLog('SAML validation configuration', {
          wantAuthnResponseSigned: (this.saml as any).options?.wantAuthnResponseSigned,
          wantAssertionsSigned: (this.saml as any).options?.wantAssertionsSigned,
          hasIdpCert: !!(this.saml as any).options?.idpCert?.length,
          idpCertCount: (this.saml as any).options?.idpCert?.length || 0
        })
      }

      // Validate and parse SAML response
      const result = await this.saml.validatePostResponseAsync({
        SAMLResponse: samlResponse,
        RelayState: relayState || '',
      })

      if (DEBUG) debugLog('SAML response validated successfully')

      if (!result.profile) {
        throw new Error('No profile returned from SAML response')
      }

      // Extract claims from profile
      const claims = this.extractClaims(result.profile)

      // Create token
      const token: SAML2Token = {
        assertion: samlResponse, // Base64-encoded SAML response
        claims,
        issuedAt: new Date(),
        expiresAt: claims.expiresAt || new Date(Date.now() + 3600000), // Default 1 hour
      }

      // Store token
      await this.storeToken(token)

      if (DEBUG) debugLog('Processed SAML response successfully', { nameId: claims.nameId })
      return token
    } catch (error) {
      if (DEBUG) {
        debugLog('SAML response processing error details', {
          errorMessage: (error as Error).message,
          errorStack: (error as Error).stack?.split('\n').slice(0, 5),
          errorName: (error as Error).name
        })
      }
      
      // Check if this is a signature validation error
      if ((error as Error).message.includes('Invalid document signature')) {
        throw new Error(`Failed to process SAML response: Document signature validation failed. This may be due to Keycloak only signing assertions but not the full document, or a certificate/algorithm mismatch. Original error: ${(error as Error).message}`)
      }
      
      throw new Error(`Failed to process SAML response: ${(error as Error).message}`)
    }
  }

  /**
   * Extract claims from SAML profile
   */
  private extractClaims(profile: Profile): SAML2Claims {
    const claims: SAML2Claims = {
      nameId: profile.nameID || '',
      sessionIndex: profile.sessionIndex,
      issuedAt: new Date(),
      issuer: profile.issuer,
    }

    // Extract standard attributes
    if (profile.email && typeof profile.email === 'string') claims.email = profile.email
    if (profile.firstName && typeof profile.firstName === 'string') claims.firstName = profile.firstName
    if (profile.lastName && typeof profile.lastName === 'string') claims.lastName = profile.lastName
    if (profile.displayName && typeof profile.displayName === 'string') claims.displayName = profile.displayName

    // Extract custom attributes
    if (profile.attributes) {
      claims.attributes = {}
      for (const [key, value] of Object.entries(profile.attributes)) {
        claims.attributes[key] = Array.isArray(value) ? value : [value as string]
      }

      // Map common attribute names
      const emailAttrs = ['email', 'emailAddress', 'mail', 'Email']
      const firstNameAttrs = ['firstName', 'givenName', 'FirstName', 'GivenName']
      const lastNameAttrs = ['lastName', 'surname', 'LastName', 'Surname']
      const displayNameAttrs = ['displayName', 'cn', 'commonName', 'DisplayName']
      const groupAttrs = ['groups', 'memberOf', 'Groups', 'MemberOf']

      for (const attr of emailAttrs) {
        if (claims.attributes[attr] && !claims.email) {
          claims.email = Array.isArray(claims.attributes[attr]) ? claims.attributes[attr][0] : (claims.attributes[attr] as string)
        }
      }

      for (const attr of firstNameAttrs) {
        if (claims.attributes[attr] && !claims.firstName) {
          claims.firstName = Array.isArray(claims.attributes[attr]) ? claims.attributes[attr][0] : (claims.attributes[attr] as string)
        }
      }

      for (const attr of lastNameAttrs) {
        if (claims.attributes[attr] && !claims.lastName) {
          claims.lastName = Array.isArray(claims.attributes[attr]) ? claims.attributes[attr][0] : (claims.attributes[attr] as string)
        }
      }

      for (const attr of displayNameAttrs) {
        if (claims.attributes[attr] && !claims.displayName) {
          claims.displayName = Array.isArray(claims.attributes[attr]) ? claims.attributes[attr][0] : (claims.attributes[attr] as string)
        }
      }

      for (const attr of groupAttrs) {
        if (claims.attributes[attr] && !claims.groups) {
          claims.groups = Array.isArray(claims.attributes[attr])
            ? (claims.attributes[attr] as string[])
            : [claims.attributes[attr] as string]
        }
      }
    }

    // Set expiration from session info if available
    if (profile.sessionNotOnOrAfter && (typeof profile.sessionNotOnOrAfter === 'string' || typeof profile.sessionNotOnOrAfter === 'number')) {
      claims.expiresAt = new Date(profile.sessionNotOnOrAfter)
    }

    return claims
  }

  /**
   * Generate SP metadata XML
   */
  async getMetadata(): Promise<SAML2SPMetadata> {
    // Ensure initialization is complete
    await this.initializationPromise

    if (!this.saml) {
      throw new Error('SAML provider not initialized')
    }

    try {
      const metadata = this.saml.generateServiceProviderMetadata(
        this.options.certificate || null,
        this.options.certificate || null, // Using same cert for both signing and encryption
      )

      const spMetadata: SAML2SPMetadata = {
        entityId: this.spEntityId,
        acsUrl: this.acsUrl,
        slsUrl: this.slsUrl,
        metadataXml: metadata,
        certificate: this.options.certificate,
      }

      return spMetadata
    } catch (error) {
      throw new Error(`Failed to generate SP metadata: ${(error as Error).message}`)
    }
  }

  /**
   * Generate logout request URL
   */
  async getLogoutUrl(nameId: string, sessionIndex?: string): Promise<{ url: string; requestId: string }> {
    // Ensure initialization is complete
    await this.initializationPromise

    if (!this.saml) {
      throw new Error('SAML provider not initialized')
    }

    const requestId = randomUUID()

    try {
      const logoutUrl = await this.saml.getLogoutUrlAsync({
        nameID: nameId,
        sessionIndex: sessionIndex,
        issuer: this.spEntityId,
        nameIDFormat: this.nameIdFormat
      }, '', {})

      if (DEBUG) debugLog('Generated SAML logout URL', { requestId, logoutUrl })
      return { url: logoutUrl, requestId }
    } catch (error) {
      throw new Error(`Failed to create SAML logout request: ${(error as Error).message}`)
    }
  }

  /**
   * Process logout response
   */
  async processLogoutResponse(samlResponse: string): Promise<boolean> {
    try {
      // For simplicity, assume logout was successful
      // In a full implementation, you'd validate the logout response using this.saml.validatePostResponseAsync
      await this.clearStoredToken()
      return true
    } catch (error) {
      if (DEBUG) debugLog('Error processing logout response:', error)
      return false
    }
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
        expiresAt: new Date(tokenData.expiresAt),
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
      expiresAt: token.expiresAt.toISOString(),
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
