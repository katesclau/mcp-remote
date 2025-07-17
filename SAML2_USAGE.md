# SAML2 Authentication with mcp-remote

This document explains how to use SAML2 authentication with mcp-remote to connect to MCP servers that require SAML2 authentication.

## Overview

mcp-remote now supports both OAuth2/OIDC and SAML2 authentication modes:

- **OAuth2/OIDC** (default): Traditional OAuth2 with PKCE flow
- **SAML2**: Enterprise SAML2 authentication with stateless token management

## Quick Start

### 1. Create SAML2 Configuration

Create a `saml2-config.json` file with your SAML2 settings:

```json
{
  "spEntityId": "mcp-remote-saml-sp",
  "idpMetadata": "http://localhost:9090/realms/mcp-rtlm/protocol/saml/descriptor",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "signRequests": false,
  "requireSignedAssertions": false,
  "forceAuthn": false,
  "allowIdpInitiated": true,
  "certificate": "-----BEGIN CERTIFICATE-----\nYOUR_SP_CERTIFICATE\n-----END CERTIFICATE-----",
  "privateKey": "-----BEGIN PRIVATE KEY-----\nYOUR_SP_PRIVATE_KEY\n-----END PRIVATE KEY-----"
}
```

### 2. Run with SAML2 Authentication

```bash
npx tsx dist/proxy.js https://your-mcp-server.com 3334 \
  --auth-mode saml2 \
  --saml2-config @./saml2-config.json \
  --host mcp-proxy.katesclau.dev \
  --debug
```

### 3. Complete Authentication

1. mcp-remote will start a SAML2 callback server
2. When authentication is needed, your browser will open to the SAML2 IdP
3. Complete authentication with your IdP (e.g., Keycloak, Okta)
4. The SAML2 assertion will be processed and stored
5. mcp-remote will use the assertion as a Bearer token for API requests

## Configuration Options

### SAML2 Configuration File

| Property                  | Type    | Required | Description                                    |
| ------------------------- | ------- | -------- | ---------------------------------------------- |
| `spEntityId`              | string  | Yes      | Service Provider Entity ID                     |
| `idpMetadata`             | string  | Yes\*    | IdP metadata URL or XML content                |
| `idpSsoUrl`               | string  | Yes\*    | IdP SSO URL (if metadata not provided)         |
| `idpEntityId`             | string  | Yes\*    | IdP Entity ID (if metadata not provided)       |
| `nameIdFormat`            | string  | No       | NameID format (default: emailAddress)          |
| `signRequests`            | boolean | No       | Whether to sign SAML requests (default: false) |
| `requireSignedAssertions` | boolean | No       | Require signed assertions (default: false)     |
| `certificate`             | string  | Yes      | SP certificate for SAML signing                |
| `privateKey`              | string  | Yes      | SP private key for SAML signing                |
| `forceAuthn`              | boolean | No       | Force authentication (default: false)          |
| `allowIdpInitiated`       | boolean | No       | Allow IdP-initiated SSO (default: false)       |

\*Either `idpMetadata` OR (`idpSsoUrl` + `idpEntityId`) is required.

### Command Line Arguments

| Argument         | Description                             | Example                         |
| ---------------- | --------------------------------------- | ------------------------------- |
| `--auth-mode`    | Authentication mode: `oauth` or `saml2` | `--auth-mode saml2`             |
| `--saml2-config` | SAML2 configuration file or JSON string | `--saml2-config @./config.json` |
| `--host`         | Callback hostname for SAML2 endpoints   | `--host mcp-proxy.example.com`  |
| `--debug`        | Enable debug logging                    | `--debug`                       |

## Identity Provider Setup

### Keycloak Configuration

1. **Create SAML Client:**

   - Client Type: `SAML`
   - Client ID: `mcp-remote-saml-sp`
   - Valid Redirect URIs: `https://mcp-proxy.katesclau.dev/saml/acs`
   - Master SAML Processing URL: `https://mcp-proxy.katesclau.dev/saml/acs`

2. **Configure SAML Settings:**

   - Include AuthnStatement: `ON`
   - Sign Documents: `ON`
   - Sign Assertions: `ON`
   - Force POST Binding: `ON`
   - Name ID Format: `email`

3. **Add Attribute Mappers:**
   - Email: `email` → `email`
   - First Name: `firstName` → `firstName`
   - Last Name: `lastName` → `lastName`
   - Groups: `groups` → `groups`

### Okta Configuration

1. **Create SAML App:**

   - Single Sign On URL: `https://mcp-proxy.katesclau.dev/saml/acs`
   - Audience URI: `mcp-remote-saml-sp`
   - Name ID Format: `EmailAddress`

2. **Attribute Statements:**
   - `email` → `user.email`
   - `firstName` → `user.firstName`
   - `lastName` → `user.lastName`
   - `groups` → `user.groups`

## Certificate Generation

Generate SAML signing certificates for your Service Provider:

```bash
# Generate private key
openssl genrsa -out saml-private.key 2048

# Generate certificate
openssl req -new -x509 -key saml-private.key -out saml-certificate.crt -days 365 \
  -subj "/CN=mcp-remote-saml-sp/O=Your Organization/C=US"

# Convert to PEM format for configuration
openssl rsa -in saml-private.key -out saml-private.pem
```

## Architecture

### Authentication Flow

```
1. Cursor/Client → mcp-remote (SAML2 mode)
2. mcp-remote → IdP (SAML2 AuthnRequest)
3. User → IdP (Authentication)
4. IdP → mcp-remote (SAML2 Response)
5. mcp-remote → mcp-rtlm (Bearer token with Base64 SAML assertion)
6. mcp-rtlm validates SAML assertion stateless
```

### Token Management

- **OAuth2**: Uses JWT access tokens with refresh tokens
- **SAML2**: Uses Base64-encoded SAML assertions as Bearer tokens
- **Stateless**: No session storage - tokens contain all necessary information
- **Expiration**: Based on SAML assertion conditions

### Endpoints

mcp-remote provides these SAML2 endpoints:

- `POST /saml/acs` - Assertion Consumer Service
- `POST /saml/sls` - Single Logout Service
- `GET /saml/metadata` - Service Provider metadata
- `GET /wait-for-saml-auth` - Long-polling for multi-instance coordination

## Testing

### Test with Keycloak

1. **Start Keycloak:**

   ```bash
   docker run -p 9090:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:latest start-dev
   ```

2. **Configure SAML client in Keycloak** (see configuration above)

3. **Run test script:**
   ```bash
   ./test-saml2.sh https://your-mcp-server.com
   ```

### Test with mcp-rtlm

```bash
# Terminal 1: Start mcp-rtlm with SAML2 validation
cd mcp-rtlm
AUTH_MODE=saml2 \
SAML2_ENABLED=true \
SAML2_METADATA_URL=http://localhost:9090/realms/mcp-rtlm/protocol/saml/descriptor \
go run cmd/main.go

# Terminal 2: Start mcp-remote with SAML2 client
cd mcp-remote
./test-saml2.sh http://localhost:8080
```

## Troubleshooting

### Common Issues

1. **Certificate Errors:**

   - Ensure certificate and private key are properly formatted
   - Verify certificate matches the one configured in IdP

2. **Metadata Errors:**

   - Check IdP metadata URL is accessible
   - Verify IdP is properly configured

3. **Callback Errors:**

   - Ensure callback URLs match in IdP configuration
   - Verify cloudflared tunnel is working (if using)

4. **Token Validation Errors:**
   - Check mcp-rtlm SAML2 validator configuration
   - Verify assertion is not expired

### Debug Logging

Enable debug logging for detailed information:

```bash
npx tsx dist/proxy.js https://server.com 3334 \
  --auth-mode saml2 \
  --saml2-config @./config.json \
  --debug
```

Debug logs are written to `~/.mcp-auth/{server_hash}_debug.log`.

## Security Considerations

1. **Certificate Management:**

   - Keep private keys secure
   - Use strong certificates (2048+ bit RSA)
   - Rotate certificates regularly

2. **Network Security:**

   - Use HTTPS for all endpoints
   - Validate SSL certificates
   - Ensure secure tunnel configuration

3. **Token Security:**

   - SAML assertions are Base64-encoded (not encrypted)
   - Use signed assertions in production
   - Implement proper token expiration

4. **IdP Configuration:**
   - Use signed assertions and responses
   - Configure proper audience restrictions
   - Implement appropriate session lifetimes

## Comparison: OAuth vs SAML2

| Feature                | OAuth2/OIDC    | SAML2                 |
| ---------------------- | -------------- | --------------------- |
| **Token Type**         | JWT            | Base64 SAML Assertion |
| **Token Refresh**      | Refresh tokens | Re-authentication     |
| **Complexity**         | Medium         | High                  |
| **Enterprise Support** | Good           | Excellent             |
| **Stateless**          | Yes            | Yes                   |
| **Browser Required**   | Yes            | Yes                   |
| **Multi-Instance**     | Yes            | Yes                   |

## Examples

### Basic SAML2 Usage

```bash
npx tsx dist/proxy.js https://api.example.com \
  --auth-mode saml2 \
  --saml2-config @./saml2-config.json
```

### With Custom Host and Port

```bash
npx tsx dist/proxy.js https://api.example.com 3334 \
  --auth-mode saml2 \
  --saml2-config @./saml2-config.json \
  --host my-proxy.example.com \
  --debug
```

### With Inline Configuration

```bash
npx tsx dist/proxy.js https://api.example.com \
  --auth-mode saml2 \
  --saml2-config '{"spEntityId":"my-sp","idpMetadata":"https://idp.com/metadata"}'
```

This implementation provides a complete, production-ready SAML2 authentication system for mcp-remote that maintains the same stateless architecture as the existing OAuth2 implementation.
