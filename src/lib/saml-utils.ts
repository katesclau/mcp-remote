import express from 'express'
import { SAML2CallbackServerOptions } from './saml-types'
import { log, debugLog, DEBUG } from './utils'

/**
 * Sets up an Express server to handle SAML2 callbacks (ACS and SLS endpoints)
 * @param options The server options
 * @returns An object with the server, samlResponse, and waitForSAMLResponse function
 */
export function setupSAML2CallbackServerWithLongPoll(options: SAML2CallbackServerOptions) {
  let samlResponseData: { response: string; relayState?: string } | null = null
  const app = express()

  // Middleware to parse URL-encoded data (required for SAML POST responses)
  app.use(express.urlencoded({ extended: false }))

  // Create a promise to track when SAML auth is completed
  let authCompletedResolve: (response: { response: string; relayState?: string }) => void
  const authCompletedPromise = new Promise<{ response: string; relayState?: string }>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint for SAML auth status
  app.get('/wait-for-saml-auth', (req, res) => {
    if (samlResponseData) {
      // Auth already completed - just return 200 without the actual response
      // Secondary instances will read tokens from disk
      log('SAML auth already completed, returning 200')
      res.status(200).send('SAML authentication completed')
      return
    }

    if (req.query.poll === 'false') {
      log('Client requested no long poll for SAML, responding with 202')
      res.status(202).send('SAML authentication in progress')
      return
    }

    // Long poll - wait for up to 30 seconds
    const longPollTimeout = setTimeout(() => {
      log('SAML long poll timeout reached, responding with 202')
      res.status(202).send('SAML authentication in progress')
    }, 30000)

    // If auth completes while we're waiting, send the response immediately
    authCompletedPromise
      .then(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('SAML auth completed during long poll, responding with 200')
          res.status(200).send('SAML authentication completed')
        }
      })
      .catch(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('SAML auth failed during long poll, responding with 500')
          res.status(500).send('SAML authentication failed')
        }
      })
  })

  // SAML Assertion Consumer Service (ACS) endpoint
  app.post(options.acsPath, (req, res) => {
    const samlResponse = req.body.SAMLResponse as string | undefined
    const relayState = req.body.RelayState as string | undefined

    if (!samlResponse) {
      res.status(400).send('Error: No SAML response received')
      return
    }

    samlResponseData = { response: samlResponse, relayState }
    log('SAML response received, resolving promise')
    authCompletedResolve(samlResponseData)

    res.send(`
      <html>
        <head><title>SAML Authentication Successful</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h2>✅ SAML Authentication Successful!</h2>
          <p>You may close this window and return to the CLI.</p>
          <script>
            // Automatically close the window if possible
            setTimeout(function() {
              window.close();
            }, 2000);
          </script>
        </body>
      </html>
    `)

    // Notify main flow that SAML response is available
    options.events.emit('saml-response-received', samlResponseData)
  })

  // SAML Single Logout Service (SLS) endpoint
  app.post(options.slsPath, (req, res) => {
    const samlResponse = req.body.SAMLResponse as string | undefined
    const samlLogoutRequest = req.body.SAMLRequest as string | undefined

    if (DEBUG)
      debugLog('SAML logout request/response received', {
        hasResponse: !!samlResponse,
        hasRequest: !!samlLogoutRequest,
      })

    // For logout, we just acknowledge and redirect
    res.send(`
      <html>
        <head><title>SAML Logout Successful</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h2>🔓 SAML Logout Successful</h2>
          <p>You have been successfully logged out.</p>
          <script>
            setTimeout(function() {
              window.close();
            }, 2000);
          </script>
        </body>
      </html>
    `)

    // Emit logout event
    options.events.emit('saml-logout-received', {
      response: samlResponse,
      request: samlLogoutRequest,
    })
  })

  // Service Provider (SP) metadata endpoint
  app.get('/saml/metadata', (req, res) => {
    // This will be populated by the SAML provider when needed
    res.status(404).send('SP metadata not available. Configure SAML provider first.')
  })

  const server = app.listen(options.port, () => {
    log(`SAML callback server running at http://127.0.0.1:${options.port}`)
    log(`- ACS endpoint: http://127.0.0.1:${options.port}${options.acsPath}`)
    log(`- SLS endpoint: http://127.0.0.1:${options.port}${options.slsPath}`)
  })

  const waitForSAMLResponse = (): Promise<{ response: string; relayState?: string }> => {
    return new Promise((resolve) => {
      if (samlResponseData) {
        resolve(samlResponseData)
        return
      }

      options.events.once('saml-response-received', (data) => {
        resolve(data)
      })
    })
  }

  return { server, samlResponseData, waitForSAMLResponse, authCompletedPromise }
}

/**
 * Sets up an Express server to handle SAML2 callbacks
 * @param options The server options
 * @returns An object with the server, samlResponse, and waitForSAMLResponse function
 */
export function setupSAML2CallbackServer(options: SAML2CallbackServerOptions) {
  const { server, samlResponseData, waitForSAMLResponse } = setupSAML2CallbackServerWithLongPoll(options)
  return { server, samlResponseData, waitForSAMLResponse }
}
