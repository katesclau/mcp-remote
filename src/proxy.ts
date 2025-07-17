#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { createServer } from 'http'
import {
  connectToRemoteServer,
  log,
  debugLog,
  DEBUG,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  getServerUrlHash,
  TransportStrategy,
} from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata, AuthProviderOptions } from './lib/types'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { NodeSAML2ClientProvider } from './lib/node-saml-client-provider'
import { createLazyAuthCoordinator, createLazySAML2AuthCoordinator } from './lib/coordination'
import { SAML2ProviderOptions } from './lib/saml-types'
import { createAuthProvider } from './lib/auth-adapter'

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  host: string,
  useHttpLocal: boolean,
  authMode: 'oauth' | 'saml2' = 'oauth',
  // OAuth options
  staticOAuthClientMetadata?: StaticOAuthClientMetadata,
  staticOAuthClientInfo?: StaticOAuthClientInformationFull,
  authorizeResource?: string,
  // SAML2 options
  saml2Options?: SAML2ProviderOptions,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Get the server URL hash for lockfile operations
  const serverUrlHash = getServerUrlHash(serverUrl)

  // Create auth coordinator and provider based on auth mode
  let authCoordinator: any
  let rawAuthProvider: any
  let authProvider: any

  if (authMode === 'saml2') {
    log('Using SAML2 authentication mode')

    if (!saml2Options) {
      throw new Error('SAML2 options must be provided when using SAML2 authentication mode')
    }

    // Create SAML2 auth coordinator
    authCoordinator = createLazySAML2AuthCoordinator(serverUrlHash, callbackPort, events)

    // Create SAML2 client provider
    rawAuthProvider = new NodeSAML2ClientProvider({
      ...saml2Options,
      serverUrl,
      callbackPort,
      host,
    })

    // Create adapter to make SAML2 provider compatible with OAuth interface
    authProvider = createAuthProvider('saml2', undefined, rawAuthProvider)
  } else {
    log('Using OAuth authentication mode')

    // Create OAuth auth coordinator
    authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events)

    // Create OAuth client provider
    rawAuthProvider = new NodeOAuthClientProvider({
      serverUrl,
      callbackPort,
      host,
      clientName: 'MCP CLI Proxy',
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authorizeResource,
    })

    // Use OAuth provider directly (no adapter needed)
    authProvider = createAuthProvider('oauth', rawAuthProvider, undefined)
  }

  // Create the appropriate transport for local connections
  let localTransport: StdioServerTransport | StreamableHTTPServerTransport
  let httpServer: any = null
  const localPort = process.env.PORT ? parseInt(process.env.PORT) : 3000 // Port for HTTP server when using HTTP transport

  if (useHttpLocal) {
    // Use HTTP transport
    localTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // Stateless mode
    })

    // Create HTTP server and bind to port
    httpServer = createServer(async (req, res) => {
      await (localTransport as StreamableHTTPServerTransport).handleRequest(req, res)
    })
  } else {
    // Use STDIO transport (default)
    localTransport = new StdioServerTransport()
  }

  // Create MCP server
  const mcpServer = new Server(
    {
      name: 'mcp-remote-proxy',
      version: '1.0.0',
    },
    {
      capabilities: {
        resources: {},
        tools: {},
        prompts: {},
        logging: {},
      },
    },
  )

  // Connect server to transport
  await mcpServer.connect(localTransport)

  // Keep track of the server instances for cleanup
  let server: any = null
  let remoteTransport: any = null

  // Define an auth initializer function that works with both OAuth and SAML2
  const authInitializer = async () => {
    let authState: any

    if (authMode === 'saml2') {
      authState = await authCoordinator.initializeSAMLAuth()
    } else {
      authState = await authCoordinator.initializeAuth()
    }

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, just log that we'll use the auth from disk
    if (authState.skipBrowserAuth) {
      const authType = authMode === 'saml2' ? 'SAML2' : 'OAuth'
      log(`${authType} authentication was completed by another instance - will use tokens from disk`)
      // TODO: remove, the callback is happening before the tokens are exchanged
      //  so we're slightly too early
      await new Promise((res) => setTimeout(res, 1_000))
    }

    // Return unified interface for both auth types
    return {
      waitForAuthCode:
        authMode === 'saml2'
          ? async () => {
              const samlResponse = await authState.waitForSAMLResponse()
              // For SAML2, we need to process the response and extract the assertion
              if (typeof samlResponse === 'string') {
                return samlResponse
              } else {
                // Process the SAML response to create and store the token
                try {
                  const token = await rawAuthProvider.processResponse(samlResponse.response, samlResponse.relayState)
                  if (DEBUG)
                    debugLog('SAML2 response processed successfully', {
                      nameId: token.claims.nameId,
                      expiresAt: token.expiresAt,
                    })
                  // Return the assertion for the transport layer to use
                  return token.assertion
                } catch (error) {
                  log('Failed to process SAML response:', error)
                  throw error
                }
              }
            }
          : authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication
    remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
    })

    if (useHttpLocal) {
      // Start the HTTP server
      httpServer.listen(localPort, () => {
        log(`Local HTTP server running on port ${localPort}`)
        log(`Proxy established successfully between local HTTP server and remote ${remoteTransport.constructor.name}`)
        log('Press Ctrl+C to exit')
      })
    } else {
      // Start the STDIO server
      await localTransport.start()
      log('Local STDIO server running')
      log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
      log('Press Ctrl+C to exit')
    }

    // Setup cleanup handler
    const cleanup = async () => {
      await remoteTransport.close()
      await localTransport.close()
      if (httpServer) {
        httpServer.close()
      }
      // Only close the server if it was initialized
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx proxy.ts <https://server-url> [callback-port] [--debug] [--http-local]')
  .then(
    ({
      serverUrl,
      callbackPort,
      headers,
      transportStrategy,
      host,
      debug,
      useHttpLocal,
      authMode,
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authorizeResource,
      saml2Config,
    }) => {
      return runProxy(
        serverUrl,
        callbackPort,
        headers,
        transportStrategy,
        host,
        useHttpLocal,
        authMode,
        staticOAuthClientMetadata,
        staticOAuthClientInfo,
        authorizeResource,
        saml2Config,
      )
    },
  )
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
