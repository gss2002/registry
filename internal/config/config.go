package config

import (
	env "github.com/caarlos0/env/v11"
)

type DatabaseType string

const (
	DatabaseTypeMongoDB DatabaseType = "mongodb"
	DatabaseTypeMemory  DatabaseType = "memory"
)

// Config holds the application configuration
type Config struct {
	ServerAddress      string       `env:"SERVER_ADDRESS" envDefault:":8080"`
	DatabaseType       DatabaseType `env:"DATABASE_TYPE" envDefault:"mongodb"`
	DatabaseURL        string       `env:"DATABASE_URL" envDefault:"mongodb://localhost:27017"`
	DatabaseName       string       `env:"DATABASE_NAME" envDefault:"mcp-registry"`
	CollectionName     string       `env:"COLLECTION_NAME" envDefault:"servers_v2"`
	LogLevel           string       `env:"LOG_LEVEL" envDefault:"info"`
	SeedFilePath       string       `env:"SEED_FILE_PATH" envDefault:"data/seed.json"`
	SeedImport         bool         `env:"SEED_IMPORT" envDefault:"true"`
	Version            string       `env:"VERSION" envDefault:"dev"`
	GithubClientID     string       `env:"GITHUB_CLIENT_ID" envDefault:""`
	GithubClientSecret string       `env:"GITHUB_CLIENT_SECRET" envDefault:""`
        // OIDC Configuration
	OIDCEnabled        bool         `env:"OIDC_ENABLED" envDefault:"false"`
	OIDCIssuer         string       `env:"OIDC_ISSUER_URL" envDefault:""`
	OIDCAudience       string       `env:"OIDC_AUDIENCE" envDefault:""`
	OIDCClientID       string       `env:"OIDC_CLIENT_ID" envDefault:""`
	OIDCRequiredScopes []string     `env:"OIDC_REQUIRED_SCOPES" envDefault:"openid,profile" envSeparator:","`
	OIDCMaxTokenAge    string       `env:"OIDC_MAX_TOKEN_AGE" envDefault:"24h"`
	OIDCClockSkew      string       `env:"OIDC_CLOCK_SKEW" envDefault:"5m"`
}

// NewConfig creates a new configuration with default values
func NewConfig() *Config {
	var cfg Config
	err := env.ParseWithOptions(&cfg, env.Options{
		Prefix: "MCP_REGISTRY_",
	})
	if err != nil {
		panic(err)
	}
	// Validate OIDC configuration if enabled
	if cfg.OIDCEnabled {
		if cfg.OIDCIssuer == "" {
			panic("OIDC_ISSUER_URL is required when OIDC is enabled")
		}
		if cfg.OIDCAudience == "" {
			panic("OIDC_AUDIENCE is required when OIDC is enabled")
		}
	}
	return &cfg
}
