package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// APITokenHashPrefix identifies the one-way verifier representation stored in
// emberboot.yaml. The hint is non-secret and exists only so operators can tell
// credentials apart in the dashboard.
const APITokenHashPrefix = "sha256:"

// APITokenRecord returns the persistent representation of a plaintext API
// token. API tokens are generated with 192 random bits, so a SHA-256 verifier
// permits authentication without retaining the bearer credential itself.
func APITokenRecord(token string) string {
	hint := token
	if len(hint) > 8 {
		hint = hint[:8]
	}
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%s%s:%s", APITokenHashPrefix, hint, hex.EncodeToString(sum[:]))
}

// NormalizeLegacyAPITokens converts plaintext compatibility records to
// one-way verifiers. The input is never mutated.
func NormalizeLegacyAPITokens(tokens []string) (normalized []string, changed int) {
	normalized = append([]string(nil), tokens...)
	for i, token := range normalized {
		if token != "" && !strings.HasPrefix(token, APITokenHashPrefix) {
			normalized[i] = APITokenRecord(token)
			changed++
		}
	}
	return normalized, changed
}

// apiTokenCredentialKey returns a canonical digest key for duplicate
// detection. Plaintext and verifier forms of the same credential deliberately
// produce the same key, and the human-readable verifier hint is ignored.
func apiTokenCredentialKey(token string) (string, error) {
	if !strings.HasPrefix(token, APITokenHashPrefix) {
		sum := sha256.Sum256([]byte(token))
		return hex.EncodeToString(sum[:]), nil
	}
	parts := strings.Split(token, ":")
	if len(parts) != 3 || parts[1] == "" {
		return "", fmt.Errorf("malformed SHA-256 token verifier")
	}
	digest, err := hex.DecodeString(parts[2])
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("malformed SHA-256 token verifier")
	}
	return hex.EncodeToString(digest), nil
}
