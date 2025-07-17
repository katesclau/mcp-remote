#!/bin/bash

echo "🧪 Testing SAML2 Authentication: mcp-remote ↔ mcp-rtlm"
echo "======================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MCP_RTLM_DIR="../mcp-rtlm"
KEYCLOAK_URL="http://localhost:9090"
REALM="mcp-rtlm"
TUNNEL_URL="https://mcp-proxy.katesclau.dev"
CALLBACK_PORT="3000"
MCP_RTLM_URL="http://localhost:8080/api/v1/mcp"
CONFIG_FILE="./saml2-mcp-rtlm-config.json"

echo "📋 Test Configuration:"
echo "  🏛️  Keycloak URL: $KEYCLOAK_URL"
echo "  🌐 Tunnel URL: $TUNNEL_URL"
echo "  📡 Callback Port: $CALLBACK_PORT"
echo "  🎯 MCP-RTLM URL: $MCP_RTLM_URL"
echo "  📄 Config File: $CONFIG_FILE"
echo ""

# Function to check if service is running
check_service() {
    local url=$1
    local name=$2
    local timeout=${3:-5}
    
    echo -n "Checking $name... "
    if curl -s --connect-timeout $timeout "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Running${NC}"
        return 0
    else
        echo -e "${RED}✗ Not available${NC}"
        return 1
    fi
}

# Function to wait for service
wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=${3:-30}
    local attempt=1
    
    echo "⏳ Waiting for $name to be ready..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s --connect-timeout 2 "$url" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $name is ready!${NC}"
            return 0
        fi
        echo "   Attempt $attempt/$max_attempts..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}❌ $name failed to start within timeout${NC}"
    return 1
}

# Step 1: Check prerequisites
echo "🔍 Step 1: Checking prerequisites..."
echo "=================================="

# Check if mcp-rtlm directory exists
if [ ! -d "$MCP_RTLM_DIR" ]; then
    echo -e "${RED}❌ mcp-rtlm directory not found: $MCP_RTLM_DIR${NC}"
    exit 1
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ SAML2 config file not found: $CONFIG_FILE${NC}"
    echo "Please create the config file first."
    exit 1
fi

# Check if source files exist (we'll use tsx directly)
if [ ! -f "./src/proxy.ts" ]; then
    echo -e "${RED}❌ mcp-remote source files not found${NC}"
    exit 1
fi

# Install dependencies if needed
if [ ! -d "./node_modules" ]; then
    echo -e "${YELLOW}⚠️  Installing dependencies...${NC}"
    npm install
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Step 2: Check mcp-rtlm services
echo "🚀 Step 2: Checking mcp-rtlm services..."
echo "======================================="

# Check if Keycloak is running
if ! check_service "$KEYCLOAK_URL/health/ready" "Keycloak"; then
    echo -e "${YELLOW}⚠️  Keycloak not running. Please start mcp-rtlm services first:${NC}"
    echo "   cd $MCP_RTLM_DIR && docker-compose up -d"
    exit 1
fi

# Check if mcp-rtlm is running
if ! check_service "$MCP_RTLM_URL" "MCP-RTLM Server"; then
    echo -e "${YELLOW}⚠️  MCP-RTLM server not running. Please start it first:${NC}"
    echo "   cd $MCP_RTLM_DIR && make run"
    echo "   (or use 'make' for hot reload with air)"
    exit 1
fi

# Check Keycloak realm and client
echo "🔧 Checking Keycloak SAML configuration..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
    | jq -r '.access_token')

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}❌ Failed to get Keycloak admin token${NC}"
    exit 1
fi

# Check if SAML client exists
CLIENT_EXISTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=mcp-rtlm-saml" \
    | jq '.[0].id // "null"')

if [ "$CLIENT_EXISTS" == "null" ]; then
    echo -e "${RED}❌ SAML client 'mcp-rtlm-saml' not found in Keycloak${NC}"
    echo "Please configure the SAML client in Keycloak admin console first."
    exit 1
fi

echo -e "${GREEN}✅ Keycloak SAML client configured${NC}"
echo -e "${GREEN}✅ MCP-RTLM server is running and ready${NC}"
echo ""

# Step 3: Test MCP-RTLM endpoint directly
echo "🧪 Step 3: Testing MCP-RTLM endpoint..."
echo "======================================"

# Test without authentication (should fail)
echo "Testing unauthenticated request to MCP-RTLM..."
RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null "$MCP_RTLM_URL")
if [ "$RESPONSE" = "401" ] || [ "$RESPONSE" = "403" ]; then
    echo -e "${GREEN}✅ MCP-RTLM correctly requires authentication (HTTP $RESPONSE)${NC}"
else
    echo -e "${YELLOW}⚠️  MCP-RTLM returned HTTP $RESPONSE (expected 401/403)${NC}"
fi

echo ""

# Step 4: Test SAML2 flow with mcp-remote
echo "🔐 Step 4: Testing SAML2 authentication flow..."
echo "=============================================="

echo "🚀 Starting mcp-remote with SAML2 configuration..."
echo ""
echo -e "${BLUE}🌐 mcp-remote will start on port $CALLBACK_PORT${NC}"
echo -e "${BLUE}🔗 Accessible via Cloudflare tunnel: $TUNNEL_URL${NC}"
echo -e "${BLUE}🎯 Target MCP server: $MCP_RTLM_URL${NC}"
echo ""
echo -e "${YELLOW}📝 Authentication Flow:${NC}"
echo "1. mcp-remote will start and wait for SAML2 authentication"
echo "2. Your browser should open to Keycloak login"
echo "3. Login with: testuser / testpass123"
echo "4. After successful auth, mcp-remote will proxy to mcp-rtlm"
echo "5. mcp-rtlm will validate the SAML2 Bearer token"
echo "6. You can test MCP endpoints through the proxy"
echo ""
echo -e "${YELLOW}📝 Test URLs (after authentication):${NC}"
echo "  • Health check: $TUNNEL_URL/health"
echo "  • MCP Initialize: $TUNNEL_URL/api/v1/mcp"
echo ""
echo "Press Ctrl+C to stop the test"
echo ""

# Run mcp-remote with SAML2 configuration (using tsx directly to avoid bundling issues)
npx tsx src/proxy.ts "$MCP_RTLM_URL" "$CALLBACK_PORT" \
    --auth-mode saml2 \
    --saml2-config "@$CONFIG_FILE" \
    --host "mcp-proxy.katesclau.dev" \
    --debug

echo ""
echo -e "${GREEN}✅ Test completed!${NC}" 