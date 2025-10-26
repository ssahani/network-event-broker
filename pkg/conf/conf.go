// SPDX-License-Identifier: Apache-2.0

package conf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func init() {
	// Initialize Zerolog global logger with JSON output (console for dev).
	log.Logger = log.With().Timestamp().Logger()
}

// Constants for configuration paths and defaults.
const (
	Version           = "0.1"
	ConfPath          = "/etc/network-broker"
	ConfFile          = "network-broker"
	DHClientLeaseFile = "/var/lib/dhclient/dhclient.leases"
	NetworkdLeasePath = "/run/systemd/netif/leases"
	ManagerStateDir   = "manager.d"
	RoutesModifiedDir = "routes.d"
	RouteTableBase    = 9999
	DefaultLogLevel   = "info"
	DefaultLogFormat  = "text"
)

// Network holds network-related configuration.
type Network struct {
	Links              string `mapstructure:"Links"`
	RoutingPolicyRules string `mapstructure:"RoutingPolicyRules"`
	UseDNS             bool   `mapstructure:"UseDNS"`
	UseDomain          bool   `mapstructure:"UseDomain"`
	UseHostname        bool   `mapstructure:"UseHostname"`
	EmitJSON           bool   `mapstructure:"EmitJSON"`
}

// System holds system-related configuration.
type System struct {
	Generator string `mapstructure:"Generator"`
	LogLevel  string `mapstructure:"LogLevel"`
	LogFormat string `mapstructure:"LogFormat"`
}

// Config holds the complete configuration structure.
type Config struct {
	Network Network `mapstructure:"Network"`
	System  System  `mapstructure:"System"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.System.LogLevel != "" {
		_, err := zerolog.ParseLevel(c.System.LogLevel)
		if err != nil {
			return fmt.Errorf("invalid log level: %s", c.System.LogLevel)
		}
	}
	if c.System.LogFormat != "" && c.System.LogFormat != "json" && c.System.LogFormat != "text" {
		return fmt.Errorf("invalid log format: %s", c.System.LogFormat)
	}
	return nil
}

// createEventScriptDirs creates directories for event scripts.
func createEventScriptDirs() error {
	eventStateDirs := []string{
		"no-carrier.d",
		"carrier.d",
		"degraded.d",
		"routable.d",
		"configured.d",
		ManagerStateDir,
		RoutesModifiedDir,
	}

	for _, dir := range eventStateDirs {
		fullPath := filepath.Join(ConfPath, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", fullPath, err)
		}
	}
	return nil
}

// SetLogLevel configures the logging level for the application.
func SetLogLevel(level string) error {
	if level == "" {
		return errors.New("log level cannot be empty")
	}

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Str("level", level).Msgf("Invalid log level, falling back to %q", DefaultLogLevel)
		return fmt.Errorf("invalid log level: %w", err)
	}

	zerolog.SetGlobalLevel(lvl)
	return nil
}

// SetLogFormat configures the logging format for the application.
func SetLogFormat(format string) error {
	if format == "" {
		return errors.New("log format cannot be empty")
	}

	// Zerolog is JSON by default; for text, switch to ConsoleWriter.
	if format == "text" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	} else if format != "json" {
		log.Warn().Str("format", format).Msgf("Invalid log format, falling back to %q", DefaultLogFormat)
		return fmt.Errorf("invalid log format: %s", format)
	}
	return nil
}

// Parse loads and parses the configuration from a file.
func Parse() (*Config, error) {
	viper.SetConfigName(ConfFile)
	viper.AddConfigPath(ConfPath)
	viper.SetConfigType("toml")

	// Set default values.
	viper.SetDefault("System.LogLevel", DefaultLogLevel)
	viper.SetDefault("System.LogFormat", DefaultLogFormat)

	// Read configuration file.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warn().Msg("Configuration file not found, using defaults")
		} else {
			log.Error().Err(err).Str("file", ConfPath+"/"+ConfFile+".toml").Msg("Failed to read configuration file")
			return nil, fmt.Errorf("failed to read configuration: %w", err)
		}
	}

	// Unmarshal configuration into struct.
	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		log.Error().Err(err).Str("file", ConfPath+"/"+ConfFile+".toml").Msg("Failed to parse configuration file")
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Validate configuration.
	if err := cfg.Validate(); err != nil {
		log.Error().Err(err).Msg("Invalid configuration")
		return nil, err
	}

	// Configure logging from environment variables or config.
	logLevel := viper.GetString("NETWORK_EVENT_LOG_LEVEL")
	if logLevel == "" {
		logLevel = cfg.System.LogLevel
	}
	if err := SetLogLevel(logLevel); err != nil {
		log.Warn().Str("level", logLevel).Msgf("Failed to set log level, using default %q", DefaultLogLevel)
		cfg.System.LogLevel = DefaultLogLevel
		if err := SetLogLevel(DefaultLogLevel); err != nil {
			log.Fatal().Str("level", DefaultLogLevel).Err(err).Msg("Failed to set default log level")
		}
	}

	logFormat := viper.GetString("NETWORK_EVENT_LOG_FORMAT")
	if logFormat == "" {
		logFormat = cfg.System.LogFormat
	}
	if err := SetLogFormat(logFormat); err != nil {
		log.Warn().Str("format", logFormat).Msgf("Failed to set log format, using default %q", DefaultLogFormat)
		cfg.System.LogFormat = DefaultLogFormat
		if err := SetLogFormat(DefaultLogFormat); err != nil {
			log.Fatal().Str("format", DefaultLogFormat).Err(err).Msg("Failed to set default log format")
		}
	}

	// Log configuration details.
	log.Debug().Str("level", zerolog.GlobalLevel().String()).Msg("Log level set")
	if cfg.System.Generator != "" {
		log.Info().Str("generator", cfg.System.Generator).Msg("Generator")
	}
	if cfg.Network.Links != "" {
		log.Info().Str("links", cfg.Network.Links).Msg("Links")
	}
	if cfg.Network.RoutingPolicyRules != "" {
		log.Info().Str("rules", cfg.Network.RoutingPolicyRules).Msg("RoutingPolicyRules")
	}

	// Create event script directories.
	if err := createEventScriptDirs(); err != nil {
		log.Error().Err(err).Msg("Failed to create event script directories")
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cfg, nil
}
