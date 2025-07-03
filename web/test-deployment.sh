#!/bin/bash

# SeeVee Deployment Test Script
# Tests Railway deployment endpoints

set -e

# Configuration
API_URL="${1:-https://your-app.railway.app}"
API_KEY="${2:-your-api-key}"

echo "🧪 Testing SeeVee API Deployment"
echo "URL: $API_URL"
echo "================================"

# Test 1: Health Check (No auth required)
echo "1️⃣  Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$API_URL/health" || echo "FAILED")
if [[ "$HEALTH_RESPONSE" == *"healthy"* ]]; then
    echo "✅ Health check passed"
    echo "   Response: $HEALTH_RESPONSE"
else
    echo "❌ Health check failed"
    echo "   Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test 2: Root endpoint 
echo ""
echo "2️⃣  Testing root endpoint..."
ROOT_RESPONSE=$(curl -s "$API_URL/" || echo "FAILED")
if [[ "$ROOT_RESPONSE" == *"SeeVee Web API"* ]]; then
    echo "✅ Root endpoint passed"
else
    echo "❌ Root endpoint failed"
    echo "   Response: $ROOT_RESPONSE"
fi

# Test 3: Authenticated endpoint
echo ""
echo "3️⃣  Testing authenticated endpoint..."
if [ "$API_KEY" != "your-api-key" ]; then
    STATS_RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" "$API_URL/stats" || echo "FAILED")
    if [[ "$STATS_RESPONSE" == *"cve_count"* ]]; then
        echo "✅ Authentication working"
        echo "   Database stats retrieved"
    else
        echo "⚠️  Authentication failed or database not ready"
        echo "   Response: $STATS_RESPONSE"
    fi
else
    echo "⚠️  Skipping auth test (no API key provided)"
fi

# Test 4: CVE Lookup
echo ""
echo "4️⃣  Testing CVE lookup..."
if [ "$API_KEY" != "your-api-key" ]; then
    CVE_RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" "$API_URL/cve/CVE-2021-44228" || echo "FAILED")
    if [[ "$CVE_RESPONSE" == *"CVE-2021-44228"* ]]; then
        echo "✅ CVE lookup working"
    else
        echo "⚠️  CVE lookup failed (database may not be populated yet)"
        echo "   Try updating database: curl -X POST \"$API_URL/update\" -H \"X-API-Key: $API_KEY\""
    fi
else
    echo "⚠️  Skipping CVE test (no API key provided)"
fi

echo ""
echo "🎉 Deployment test completed!"
echo ""
echo "📋 Next steps:"
echo "   1. If database stats show 0 CVEs, run: curl -X POST \"$API_URL/update\" -H \"X-API-Key: $API_KEY\""
echo "   2. Update frontend config with this URL: $API_URL"
echo "   3. Deploy frontend to Netlify" 