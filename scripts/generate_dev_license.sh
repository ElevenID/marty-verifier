#!/bin/bash
# Generate a development JWT license for testing
# This license is NOT cryptographically signed - only works with empty public_key (dev mode)

# Calculate timestamps
NOW=$(date +%s)
EXP=$((NOW + 365*24*60*60))  # 1 year from now

# Create claims
HEADER=$(echo -n '{"alg":"EdDSA","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
CLAIMS=$(cat << CLAIMS_END
{
  "iss": "marty-license-issuer",
  "sub": "dev-org-001",
  "iat": $NOW,
  "exp": $EXP,
  "jti": "dev-license-$(date +%Y%m%d)",
  "features": ["mdl", "emrtd", "oid4vp", "sd-jwt", "usb-sync", "reporting"],
  "deployment_mode": "development",
  "max_verifications_total": 100000,
  "org_name": "Development License",
  "update_channels": ["stable", "beta", "dev"],
  "grace_period_days": 90
}
CLAIMS_END
)

CLAIMS_B64=$(echo -n "$CLAIMS" | base64 | tr '+/' '-_' | tr -d '=')

# For dev mode, signature is not validated, so we can use a fake one
SIGNATURE="dev_mode_signature_not_validated"

echo ""
echo "=== Development License Token ==="
echo ""
echo "${HEADER}.${CLAIMS_B64}.${SIGNATURE}"
echo ""
echo "=== Decoded Claims ==="
echo "$CLAIMS" | jq .
