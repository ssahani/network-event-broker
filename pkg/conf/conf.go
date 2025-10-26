// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package conf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

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
		if _, err := logrus.ParseLevel(c.System.LogLevel); err != nil {
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

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Warnf("Invalid log level %q, falling back to %q", level, DefaultLogLevel)
		return fmt.Errorf("invalid log level: %w", err)
	}

	logrus.SetLevel(lvl)
	return nil
}

// SetLogFormat configures the logging format for the application.
func SetLogFormat(format string) error {
	if format == "" {
		return errors.New("log format cannot be empty")
	}

	switch format {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			DisableTimestamp: true,
		})
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})
	default:
		logrus.Warnf("Invalid log format %q, falling back to %q", format, DefaultLogFormat)
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
			logrus.Warn("Configuration file not found, using defaults")
		} else {
			logrus.Errorf("Failed to read configuration file %s/%s.toml: %v", ConfPath, ConfFile, err)
			return nil, fmt.Errorf("failed to read configuration: %w", err)
		}
	}

	// Unmarshal configuration into struct.
	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		logrus.Errorf("Failed to parse configuration file %s/%s.toml: %v", ConfPath, ConfFile, err)
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Validate configuration.
	if err := cfg.Validate(); err != nil {
		logrus.Errorf("Invalid configuration: %v", err)
		return nil, err
	}

	// Configure logging from environment variables or config.
	logLevel := viper.GetString("NETWORK_EVENT_LOG_LEVEL")
	if logLevel == "" {
		logLevel = cfg.System.LogLevel
	}
	if err := SetLogLevel(logLevel); err != nil {
		logrus.Warnf("Failed to set log level %q, using default %q", logLevel, DefaultLogLevel)
		cfg.System.LogLevel = DefaultLogLevel
		if err := SetLogLevel(DefaultLogLevel); err != nil {
			logrus.Fatalf("Failed to set default log level %q: %v", DefaultLogLevel, err)
		}
	}

	logFormat := viper.GetString("NETWORK_EVENT_LOG_FORMAT")
	if logFormat == "" {
		logFormat = cfg.System.LogFormat
	}
	if err := SetLogFormat(logFormat); err != nil {
		logrus.Warnf("Failed to set log format %q, using default %q", logFormat, DefaultLogFormat)
		cfg.System.LogFormat = DefaultLogFormat
		if err := SetLogFormat(DefaultLogFormat); err != nil {
			logrus.Fatalf("Failed to set default log format %q: %v", DefaultLogFormat, err)
		}
	}

	// Log configuration details.
	logrus.Debugf("Log level set to %q", logrus.GetLevel().String())
	if cfg.System.Generator != "" {
		logrus.Infof("Generator: %s", cfg.System.Generator)
	}
	if cfg.Network.Links != "" {
		logrus.Infof("Links: %s", cfg.Network.Links)
	}
	if cfg.Network.RoutingPolicyRules != "" {
		logrus.Infof("RoutingPolicyRules: %s", cfg.Network.RoutingPolicyRules)
	}

	// Create event script directories.
	if err := createEventScriptDirs(); err != nil {
		logrus.Errorf("Failed to create event script directories: %v", err)
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cfg, nil
}
