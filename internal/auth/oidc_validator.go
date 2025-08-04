package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDC configuration and key cache
type OIDCConfig struct {
	Issuer                string    `json:"issuer"`
	AuthorizationEndpoint string    `json:"authorization_endpoint"`
	TokenEndpoint         string    `json:"token_endpoint"`
	JwksURI              string    `json:"jwks_uri"`
	UserInfoEndpoint     string    `json:"userinfo_endpoint"`
	SupportedScopes      []string  `json:"scopes_supported"`
	SupportedResponseTypes []string `json:"response_types_supported"`
	SupportedSubjectTypes  []string `json:"subject_types_supported"`
	SupportedSigningAlgs   []string `json:"id_token_signing_alg_values_supported"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X5C []string `json:"x5c,omitempty"`
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Scope             string `json:"scope,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
}

type OIDCValidator struct {
	issuer          string
	audience        string
	clientID        string
	oidcConfig      *OIDCConfig
	keyCache        map[string]*rsa.PublicKey
	keyMutex        sync.RWMutex
	configLastFetch time.Time
	configTTL       time.Duration
	httpClient      *http.Client
}

// NewOIDCValidator creates a new OIDC token validator
func NewOIDCValidator(issuer, audience, clientID string) *OIDCValidator {
	return &OIDCValidator{
		issuer:     issuer,
		audience:   audience,
		clientID:   clientID,
		keyCache:   make(map[string]*rsa.PublicKey),
		configTTL:  30 * time.Minute, // Cache OIDC config for 30 minutes
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// validateOIDCTokenSecure performs comprehensive OIDC token validation
func (v *OIDCValidator) ValidateOIDCToken(ctx context.Context, token string) (bool, error) {
	// Initialize OIDC validator with configuration
	validator := v

	// Step 1: Discover and validate OIDC configuration
	if err := validator.loadOIDCConfig(ctx); err != nil {
		return false, fmt.Errorf("failed to load OIDC configuration: %w", err)
	}

	// Step 2: Parse and validate JWT structure
	claims := &CustomClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return validator.getSigningKey(ctx, token)
	})

	if err != nil {
		return false, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !jwtToken.Valid {
		return false, errors.New("invalid JWT token")
	}

	// Step 3: Validate standard JWT claims
	if err := validator.validateStandardClaims(claims); err != nil {
		return false, fmt.Errorf("standard claims validation failed: %w", err)
	}

	// Step 4: Validate OIDC-specific claims
	if err := validator.validateOIDCClaims(claims); err != nil {
		return false, fmt.Errorf("OIDC claims validation failed: %w", err)
	}

	// Step 5: Validate required scopes
	if err := validator.validateScopes(claims); err != nil {
		return false, fmt.Errorf("scope validation failed: %w", err)
	}

	// Step 6: Additional security validations
	if err := validator.validateSecurityConstraints(claims); err != nil {
		return false, fmt.Errorf("security validation failed: %w", err)
	}

	return true, nil
}

// loadOIDCConfig discovers and loads OIDC provider configuration
func (v *OIDCValidator) loadOIDCConfig(ctx context.Context) error {
	// Check if we need to refresh the configuration
	if v.oidcConfig != nil && time.Since(v.configLastFetch) < v.configTTL {
		return nil
	}

	// Construct well-known configuration URL
	wellKnownURL := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC configuration endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var config OIDCConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	// Validate the discovered configuration
	if err := v.validateOIDCConfiguration(&config); err != nil {
		return fmt.Errorf("invalid OIDC configuration: %w", err)
	}

	v.oidcConfig = &config
	v.configLastFetch = time.Now()
	return nil
}

// validateOIDCConfiguration validates the discovered OIDC configuration
func (v *OIDCValidator) validateOIDCConfiguration(config *OIDCConfig) error {
	if config.Issuer != v.issuer {
		return fmt.Errorf("issuer mismatch: expected %s, got %s", v.issuer, config.Issuer)
	}

	if config.JwksURI == "" {
		return errors.New("jwks_uri is required")
	}

	if config.TokenEndpoint == "" {
		return errors.New("token_endpoint is required")
	}

	// Validate supported algorithms include secure options
	hasSecureAlg := false
	secureAlgs := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
	for _, supported := range config.SupportedSigningAlgs {
		for _, secure := range secureAlgs {
			if supported == secure {
				hasSecureAlg = true
				break
			}
		}
		if hasSecureAlg {
			break
		}
	}

	if !hasSecureAlg {
		return fmt.Errorf("no secure signing algorithms supported: %v", config.SupportedSigningAlgs)
	}

	// Reject none algorithm
	for _, alg := range config.SupportedSigningAlgs {
		if strings.ToLower(alg) == "none" {
			return errors.New("'none' algorithm is not allowed for security reasons")
		}
	}

	return nil
}

// getSigningKey retrieves and validates the signing key for JWT verification
func (v *OIDCValidator) getSigningKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if err := v.validateSigningMethod(token); err != nil {
		return nil, err
	}

	// Get key ID from JWT header
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid in JWT header")
	}

	// Check cache first
	v.keyMutex.RLock()
	if key, exists := v.keyCache[kid]; exists {
		v.keyMutex.RUnlock()
		return key, nil
	}
	v.keyMutex.RUnlock()

	// Fetch JWKS if key not in cache
	key, err := v.fetchAndCacheKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signing key: %w", err)
	}

	return key, nil
}

// validateSigningMethod ensures the JWT uses an approved signing algorithm
func (v *OIDCValidator) validateSigningMethod(token *jwt.Token) error {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA, *jwt.SigningMethodRSAPSS:
		// Approved asymmetric methods
		return nil
	default:
		return fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
}

// fetchAndCacheKey fetches the public key from JWKS endpoint and caches it
func (v *OIDCValidator) fetchAndCacheKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.oidcConfig.JwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Find the key with matching kid
	var targetJWK *JWK
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			targetJWK = &key
			break
		}
	}

	if targetJWK == nil {
		return nil, fmt.Errorf("signing key with kid %s not found", kid)
	}

	// Convert JWK to RSA public key
	publicKey, err := v.jwkToRSAPublicKey(targetJWK)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to RSA public key: %w", err)
	}

	// Cache the key
	v.keyMutex.Lock()
	v.keyCache[kid] = publicKey
	v.keyMutex.Unlock()

	return publicKey, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func (v *OIDCValidator) jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	// Validate key size (minimum 2048 bits for security)
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key size too small: %d bits (minimum 2048)", n.BitLen())
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// validateStandardClaims validates standard JWT claims
func (v *OIDCValidator) validateStandardClaims(claims *CustomClaims) error {
	now := time.Now()

	// Validate issuer
	if claims.Issuer != v.issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
	}

	// Validate audience - check if our audience is in the token's audience list
	found := false
	for _, aud := range claims.Audience {
		if aud == v.audience {
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("invalid audience: expected %s, got %v", v.audience, claims.Audience)
	}

	// Validate expiration
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.Before(now) {
		return errors.New("token has expired")
	}

	// Validate not before (if present)
	if claims.NotBefore != nil && claims.NotBefore.Time.After(now) {
		return errors.New("token not yet valid")
	}

	// Validate issued at (if present)
	if claims.IssuedAt != nil {
		// Allow 5 minutes clock skew
		maxAge := 5 * time.Minute
		if claims.IssuedAt.Time.After(now.Add(maxAge)) {
			return errors.New("token issued in the future")
		}
	}

	// Validate token ID is present (optional for some OIDC providers)
	// Note: Some OIDC providers like Dex don't always include jti
	if claims.ID == "" {
		// Log warning but don't fail validation
		// In production, you might want to log this for monitoring
		// log.Printf("Warning: Token missing jti (token ID) claim from issuer %s", claims.Issuer)
	}

	// Validate subject is present
	if claims.Subject == "" {
		return errors.New("missing sub (subject) claim")
	}

	return nil
}

// validateOIDCClaims validates OIDC-specific claims
func (v *OIDCValidator) validateOIDCClaims(claims *CustomClaims) error {
	// Validate client ID matches expected
	if v.clientID != "" && claims.ClientID != "" && claims.ClientID != v.clientID {
		return fmt.Errorf("invalid client_id: expected %s, got %s", v.clientID, claims.ClientID)
	}

	// Validate auth_time is recent (if present)
	if claims.AuthTime > 0 {
		authTime := time.Unix(claims.AuthTime, 0)
		maxAuthAge := 24 * time.Hour // Maximum authentication age
		if time.Since(authTime) > maxAuthAge {
			return errors.New("authentication too old")
		}
	}

	// Validate email is verified (if email claim is present)
	if claims.Email != "" && !claims.EmailVerified {
		return errors.New("email not verified")
	}

	return nil
}

// validateScopes validates that the token has required scopes
func (v *OIDCValidator) validateScopes(claims *CustomClaims) error {
	// Some OIDC providers (like Dex) don't include scope in access tokens
	// Scope validation is more relevant for authorization servers
	if claims.Scope == "" {
		// Log info but don't fail validation for access tokens
		// In production, you might want to log this for monitoring
		// log.Printf("Info: No scope claim found in token from issuer %s", claims.Issuer)
		return nil
	}

	scopes := strings.Split(claims.Scope, " ")
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	// If scope claim is present, require openid scope for OIDC compliance
	if !scopeMap["openid"] {
		return errors.New("missing required 'openid' scope")
	}

	// Additional scope requirements can be configured here if needed
	// For now, we'll be lenient since many providers handle scopes differently
	
	return nil
}

// validateSecurityConstraints performs additional security validations
func (v *OIDCValidator) validateSecurityConstraints(claims *CustomClaims) error {
	// Check token lifetime is reasonable (not too long)
	if claims.ExpiresAt != nil && claims.IssuedAt != nil {
		lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
		maxLifetime := 24 * time.Hour // Maximum token lifetime
		if lifetime > maxLifetime {
			return fmt.Errorf("token lifetime too long: %v (maximum %v)", lifetime, maxLifetime)
		}
	}

	// Validate subject format (should not be empty or contain dangerous chars)
	if len(claims.Subject) < 1 || len(claims.Subject) > 255 {
		return errors.New("invalid subject length")
	}

	// Basic sanitization check for subject
	if strings.ContainsAny(claims.Subject, "\n\r\t") {
		return errors.New("subject contains invalid characters")
	}

	// Additional security checks can be added here:
	// - Rate limiting based on subject
	// - Blacklist checking
	// - Geolocation validation
	// - Device fingerprinting

	return nil
}

// Additional configuration struct for the service
type OIDCServiceConfig struct {
	OIDCIssuer    string
	OIDCAudience  string
	OIDCClientID  string
	OIDCEnabled   bool
}
