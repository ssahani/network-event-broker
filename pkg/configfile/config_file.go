// SPDX-License-Identifier: Apache-2.0

package configfile

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// Meta represents a YAML configuration file and its parsed content.
type Meta struct {
	Path    string
	Data    map[string]interface{}
	Section string // Current section for operations like SetKeyToNewSectionString.
}

// Load reads and parses a YAML configuration file from the given path.
func Load(path string) (*Meta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Error().Str("path", path).Err(err).Msg("Failed to read YAML file")
		return nil, fmt.Errorf("failed to read YAML file %s: %w", path, err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Error().Str("path", path).Err(err).Msg("Failed to parse YAML file")
		return nil, fmt.Errorf("failed to parse YAML file %s: %w", path, err)
	}

	log.Debug().Str("path", path).Msg("Successfully loaded YAML configuration")
	return &Meta{
		Path: path,
		Data: config,
	}, nil
}

// Save writes the configuration back to the file.
func (m *Meta) Save() error {
	data, err := yaml.Marshal(m.Data)
	if err != nil {
		log.Error().Str("path", m.Path).Err(err).Msg("Failed to marshal YAML data")
		return fmt.Errorf("failed to marshal YAML data: %w", err)
	}

	if err := os.WriteFile(m.Path, data, 0644); err != nil {
		log.Error().Str("path", m.Path).Err(err).Msg("Failed to save YAML file")
		return fmt.Errorf("failed to save YAML file %s: %w", m.Path, err)
	}

	log.Debug().Str("path", m.Path).Msg("Successfully saved YAML configuration")
	return nil
}

// ParseKeyFromSectionString retrieves a value for a key in a specified section.
func ParseKeyFromSectionString(path, section, key string) (string, error) {
	if section == "" || key == "" {
		return "", fmt.Errorf("section or key cannot be empty")
	}

	m, err := Load(path)
	if err != nil {
		return "", err
	}

	sectionData, ok := m.Data[section]
	if !ok {
		log.Debug().Str("path", path).Str("section", section).Msg("Section not found")
		return "", errors.New("section not found")
	}

	sectionMap, ok := sectionData.(map[string]interface{})
	if !ok {
		log.Debug().Str("path", path).Str("section", section).Msg("Invalid section format")
		return "", errors.New("invalid section format")
	}

	value, ok := sectionMap[key]
	if !ok {
		log.Debug().Str("path", path).Str("section", section).Str("key", key).Msg("Key not found")
		return "", errors.New("key not found")
	}

	strValue, ok := value.(string)
	if !ok {
		// Handle non-string values (e.g., boolean, integer) by converting to string.
		strValue = fmt.Sprintf("%v", value)
	}

	log.Debug().Str("path", path).Str("section", section).Str("key", key).Str("value", strValue).Msg("Parsed key value")
	return strValue, nil
}

// SetKeySectionString sets a key-value pair in the specified section.
func (m *Meta) SetKeySectionString(section, key, value string) error {
	if section == "" || key == "" {
		return fmt.Errorf("section or key cannot be empty")
	}

	if m.Data == nil {
		m.Data = make(map[string]interface{})
	}

	sectionData, ok := m.Data[section]
	if !ok {
		sectionData = make(map[string]interface{})
		m.Data[section] = sectionData
	}

	sectionMap, ok := sectionData.(map[string]interface{})
	if !ok {
		log.Warn().Str("section", section).Msg("Invalid section format, creating new section")
		sectionMap = make(map[string]interface{})
		m.Data[section] = sectionMap
	}

	sectionMap[key] = strings.ToLower(value)
	log.Debug().Str("section", section).Str("key", key).Str("value", value).Msg("Set key in section")
	return nil
}

// NewSection creates a new section in the configuration.
func (m *Meta) NewSection(section string) error {
	if section == "" {
		return fmt.Errorf("section cannot be empty")
	}

	if m.Data == nil {
		m.Data = make(map[string]interface{})
	}

	if _, exists := m.Data[section]; exists {
		log.Warn().Str("section", section).Msg("Section already exists")
	} else {
		m.Data[section] = make(map[string]interface{})
		log.Debug().Str("section", section).Msg("Created new section")
	}

	m.Section = section
	return nil
}

// SetKeyToNewSectionString sets a key-value pair in the current section.
func (m *Meta) SetKeyToNewSectionString(key, value string) error {
	if m.Section == "" {
		return fmt.Errorf("no section selected")
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	return m.SetKeySectionString(m.Section, key, value)
}

// MapTo maps a section's key-value pairs to a struct.
func MapTo(cfg *Meta, section string, v interface{}) error {
	if cfg == nil || cfg.Data == nil {
		return fmt.Errorf("configuration data is nil")
	}

	sectionData, ok := cfg.Data[section]
	if !ok {
		log.Debug().Str("section", section).Msg("Section not found for mapping")
		return fmt.Errorf("section %s not found", section)
	}

	data, err := yaml.Marshal(sectionData)
	if err != nil {
		log.Error().Str("section", section).Err(err).Msg("Failed to marshal section data")
		return fmt.Errorf("failed to marshal section %s: %w", section, err)
	}

	if err := yaml.Unmarshal(data, v); err != nil {
		log.Error().Str("section", section).Err(err).Msg("Failed to unmarshal section to struct")
		return fmt.Errorf("failed to unmarshal section %s to struct: %w", section, err)
	}

	log.Debug().Str("section", section).Msg("Successfully mapped section to struct")
	return nil
}
