// Update internal/auth/service.go with secure OIDC validation

//go:build !noauth

package auth

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/registry/internal/config"
	"github.com/modelcontextprotocol/registry/internal/model"
)

// ServiceImpl implements the Service interface
type ServiceImpl struct {
	config        *config.Config
	githubAuth    *GitHubDeviceAuth
	oidcValidator *OIDCValidator
}

// NewAuthService creates a new authentication service
//
//nolint:ireturn // Factory function intentionally returns interface for dependency injection
func NewAuthService(cfg *config.Config) Service {
	githubConfig := GitHubOAuthConfig{
		ClientID:     cfg.GithubClientID,
		ClientSecret: cfg.GithubClientSecret,
	}

	service := &ServiceImpl{
		config:     cfg,
		githubAuth: NewGitHubDeviceAuth(githubConfig),
	}

	// Initialize OIDC validator if OIDC is enabled
	if cfg.OIDCEnabled && cfg.OIDCIssuer != "" {
		service.oidcValidator = NewOIDCValidator(
			cfg.OIDCIssuer,
			cfg.OIDCAudience,
			cfg.OIDCClientID,
		)
	}

	return service
}

func (s *ServiceImpl) StartAuthFlow(_ context.Context, _ model.AuthMethod,
	_ string) (map[string]string, string, error) {
	// return not implemented error
	return nil, "", fmt.Errorf("not implemented")
}

func (s *ServiceImpl) CheckAuthStatus(_ context.Context, _ string) (string, error) {
	// return not implemented error
	return "", fmt.Errorf("not implemented")
}

// ValidateAuth validates authentication credentials
func (s *ServiceImpl) ValidateAuth(ctx context.Context, auth model.Authentication) (bool, error) {
	// Never allow empty authentication method
	if auth.Method == "" {
		return false, ErrAuthRequired
	}

	switch auth.Method {
	case model.AuthMethodGitHub:
		if s.githubAuth == nil {
			return false, fmt.Errorf("GitHub authentication not configured")
		}
		return s.githubAuth.ValidateToken(ctx, auth.Token, auth.RepoRef)
		
	case model.AuthMethodOIDC:
		if s.oidcValidator == nil {
			return false, fmt.Errorf("OIDC authentication not configured")
		}
		return s.validateOIDCToken(ctx, auth.Token)
		
	case model.AuthMethodNone:
		// In production, this should be forbidden
		if os.Getenv("ENVIRONMENT") == "production" {
			return false, ErrAuthRequired
		}
		// Only allow in development/testing environments
		return false, fmt.Errorf("no authentication method not allowed")
		
	default:
		return false, ErrUnsupportedAuthMethod
	}
}

// validateOIDCToken performs comprehensive OIDC token validation using the secure implementation
func (s *ServiceImpl) validateOIDCToken(ctx context.Context, token string) (bool, error) {
	if s.oidcValidator == nil {
		return false, fmt.Errorf("OIDC validator not initialized")
	}

	// Step 1: Basic token format validation
	if token == "" {
		return false, fmt.Errorf("empty token")
	}

	// Ensure token is properly formatted JWT (3 parts)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Step 2: Use the validator's comprehensive validation
	return s.oidcValidator.ValidateOIDCToken(ctx, token)
}
