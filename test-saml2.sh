#!/bin/bash

echo "🧪 Testing SAML2 Authentication with mcp-remote"
echo "=============================================="
echo ""

# Check if we have the necessary arguments
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <mcp-server-url> [callback-port]"
    echo ""
    echo "Example:"
    echo "  $0 https://your-mcp-server.com 3334"
    echo ""
    echo "This will test SAML2 authentication flow:"
    echo "1. Start mcp-remote in SAML2 mode"
    echo "2. Connect to the specified MCP server"
    echo "3. Handle SAML2 authentication via Keycloak"
    echo "4. Proxy MCP traffic with SAML2 tokens"
    exit 1
fi

SERVER_URL="$1"
CALLBACK_PORT="${2:-3334}"
HOST="${3:-mcp-proxy.katesclau.dev}"

echo "📋 Configuration:"
echo "  Server URL: $SERVER_URL"
echo "  Callback Port: $CALLBACK_PORT"
echo "  Host: $HOST"
echo "  SAML2 Config: ./saml2-test-config.json"
echo ""

# Check if config file exists
if [ ! -f "./saml2-test-config.json" ]; then
    echo "❌ Error: SAML2 config file not found: ./saml2-test-config.json"
    echo ""
    echo "Please create a SAML2 configuration file with the following structure:"
    echo "{"
    echo '  "spEntityId": "mcp-remote-saml-sp",'
    echo '  "idpMetadata": "http://localhost:9090/realms/mcp-rtlm/protocol/saml/descriptor",'
    echo '  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",'
    echo '  "signRequests": false,'
    echo '  "requireSignedAssertions": false,'
    echo '  "certificate": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",'
    echo '  "privateKey": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"'
    echo "}"
    exit 1
fi

echo "🚀 Starting mcp-remote with SAML2 authentication..."
echo ""

# Run mcp-remote with SAML2 configuration
npx tsx dist/proxy.js "$SERVER_URL" "$CALLBACK_PORT" \
    --auth-mode saml2 \
    --saml2-config @./saml2-test-config.json \
    --host "$HOST" \
    --debug

echo ""
echo "✅ SAML2 test completed!" 