// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 VMware, Inc.

package listeners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/rs/zerolog/log"

	"github.com/vmware/network-event-broker/pkg/bus"
	"github.com/vmware/network-event-broker/pkg/conf"
	"github.com/vmware/network-event-broker/pkg/network"
	"github.com/vmware/network-event-broker/pkg/system"
)

// Constants for DBus interfaces, paths, and timeouts.
const (
	networkInterface         = "org.freedesktop.network1"
	networkObjectPath        = "/org/freedesktop/network1"
	networkInterfaceLink     = networkInterface + ".Link"
	networkInterfaceLinkBase = networkObjectPath + "/link/_3"
	defaultRequestTimeout    = 5 * time.Second
)

// executeNetworkdLinkStateScripts runs scripts in the appropriate state directory for a link state change.
func executeNetworkdLinkStateScripts(link string, index int, key, value string, cfg *conf.Config) error {
	if link == "" || key == "" || value == "" {
		return fmt.Errorf("invalid input: link=%q, key=%q, value=%q", link, key, value)
	}

	scriptDirs, err := system.ReadAllScriptDirs(conf.ConfPath)
	if err != nil {
		log.Error().Err(err).Str("path", conf.ConfPath).Msg("Failed to read script directories")
		return fmt.Errorf("failed to read script directories: %w", err)
	}

	stateDir := value + ".d"
	for _, dir := range scriptDirs {
		if dir != stateDir {
			continue
		}

		dirPath := filepath.Join(conf.ConfPath, dir)
		scripts, err := system.ReadAllScriptInConfDir(dirPath)
		if err != nil {
			log.Warn().Err(err).Str("dir", dirPath).Msg("Failed to read scripts in directory")
			continue
		}

		if len(scripts) == 0 {
			log.Debug().Str("dir", dir).Msg("No scripts found in directory")
			continue
		}

		// Prepare environment variables.
		env := append(os.Environ(),
			"LINK="+link,
			fmt.Sprintf("LINKINDEX=%d", index),
			fmt.Sprintf("%s=%s", key, value),
		)

		// Add DHCP lease information if available.
		leaseFile := filepath.Join(conf.NetworkdLeasePath, strconv.Itoa(index))
		if leaseLines, err := system.ReadLines(leaseFile); err == nil && len(leaseLines) > 0 {
			env = append(env, "DHCP_LEASE="+strings.Join(leaseLines, " "))
		} else {
			log.Debug().Str("file", leaseFile).Err(err).Msg("Failed to read lease file")
		}

		// Add JSON data if enabled.
		if cfg.Network.EmitJSON {
			if linkData, err := acquireLink(link); err == nil {
				if jsonBytes, err := json.Marshal(linkData); err == nil {
					env = append(env, "JSON="+string(jsonBytes))
					log.Debug().Str("link", link).Str("json", string(jsonBytes)).Msg("Generated JSON data")
				} else {
					log.Warn().Str("link", link).Err(err).Msg("Failed to marshal link data")
				}
			} else {
				log.Warn().Str("link", link).Err(err).Msg("Failed to acquire link data for JSON")
			}
		}

		// Execute scripts.
		for _, script := range scripts {
			scriptPath := filepath.Join(dirPath, script)
			log.Debug().Str("script", scriptPath).Str("link", link).Str("state", value).Msg("Executing script")

			ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
			defer cancel()

			cmd := exec.CommandContext(ctx, scriptPath)
			cmd.Env = env

			if err := cmd.Run(); err != nil {
				log.Error().Str("script", scriptPath).Err(err).Msg("Failed to execute script")
				continue
			}

			log.Debug().Str("script", scriptPath).Str("link", link).Msg("Successfully executed script")
		}
	}

	return nil
}

// executeNetworkdManagerScripts runs scripts in the manager state directory for a manager state change.
func executeNetworkdManagerScripts(key, value string) error {
	if key == "" || value == "" {
		return fmt.Errorf("invalid input: key=%q, value=%q", key, value)
	}

	managerStatePath := filepath.Join(conf.ConfPath, conf.ManagerStateDir)
	scripts, err := system.ReadAllScriptInConfDir(managerStatePath)
	if err != nil {
		log.Error().Err(err).Str("dir", managerStatePath).Msg("Failed to read manager script directory")
		return fmt.Errorf("failed to read manager script directory: %w", err)
	}

	if len(scripts) == 0 {
		log.Debug().Str("dir", managerStatePath).Msg("No scripts found in manager directory")
		return nil
	}

	for _, script := range scripts {
		scriptPath := filepath.Join(managerStatePath, script)
		log.Debug().Str("script", scriptPath).Str("key", key).Str("value", value).Msg("Executing manager script")

		ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, scriptPath)
		cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", key, value))

		if err := cmd.Run(); err != nil {
			log.Error().Str("script", scriptPath).Err(err).Msg("Failed to execute manager script")
			continue
		}

		log.Debug().Str("script", scriptPath).Msg("Successfully executed manager script")
	}

	return nil
}

// processDBusLinkMessage processes a DBus signal for a link state change.
func processDBusLinkMessage(n *network.Network, v *dbus.Signal, cfg *conf.Config) error {
	if !strings.HasPrefix(string(v.Path), networkInterfaceLinkBase) {
		return nil
	}

	strIndex := strings.TrimPrefix(string(v.Path), networkInterfaceLinkBase)
	index, err := strconv.Atoi(strIndex)
	if err != nil {
		log.Error().Str("ifindex", strIndex).Err(err).Msg("Failed to parse interface index")
		return nil
	}

	if n.LinksByIndex == nil || n.LinksByIndex[index] == "" {
		log.Warn().Int("ifindex", index).Msg("Unknown link index")
		return nil
	}

	link := n.LinksByIndex[index]
	log.Debug().Int("ifindex", index).Str("link", link).Msg("Received DBus link signal")

	linkState, ok := v.Body[1].(map[string]dbus.Variant)
	if !ok {
		log.Error().Int("ifindex", index).Msg("Invalid link state format")
		return fmt.Errorf("invalid link state format for ifindex %d", index)
	}

	for key, variant := range linkState {
		value := strings.Trim(variant.String(), "\"")
		log.Debug().Str("link", link).Int("ifindex", index).Str("key", key).Str("value", value).Msg("Link state changed")

		// Execute scripts only if the link is in the configured list or no list is specified.
		if cfg.Network.Links == "" || strings.Contains(cfg.Network.Links, link) {
			if err := executeNetworkdLinkStateScripts(link, index, key, value, cfg); err != nil {
				log.Warn().Str("link", link).Int("ifindex", index).Err(err).Msg("Failed to execute link state scripts")
			}
		}

		// Configure routing policies if the link is routable and in the policy rules.
		if value == "routable" && cfg.Network.RoutingPolicyRules != "" && strings.Contains(cfg.Network.RoutingPolicyRules, link) {
			if err := network.ConfigureNetwork(link, n); err != nil {
				log.Warn().Str("link", link).Err(err).Msg("Failed to configure network")
			}
		}
	}

	return nil
}

// processDBusManagerMessage processes a DBus signal for a manager state change.
func processDBusManagerMessage(n *network.Network, v *dbus.Signal) error {
	state, ok := v.Body[1].(map[string]dbus.Variant)
	if !ok {
		log.Error().Msg("Invalid manager state format")
		return fmt.Errorf("invalid manager state format")
	}

	for key, variant := range state {
		value := strings.Trim(variant.String(), "\"")
		log.Debug().Str("key", key).Str("value", value).Msg("Manager state changed")

		if err := executeNetworkdManagerScripts(key, value); err != nil {
			log.Warn().Err(err).Str("key", key).Str("value", value).Msg("Failed to execute manager scripts")
		}
	}

	return nil
}

// WatchNetworkd monitors systemd-networkd DBus signals for link and manager state changes.
func WatchNetworkd(n *network.Network, cfg *conf.Config, finished chan bool) error {
	if n == nil || cfg == nil {
		return fmt.Errorf("network or config cannot be nil")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to system bus")
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close DBus connection")
		}
		finished <- true
	}()

	opts := []dbus.MatchOption{
		dbus.WithMatchSender(networkInterface),
		dbus.WithMatchInterface(bus.DBusProperties),
		dbus.WithMatchMember("PropertiesChanged"),
	}

	if err := conn.AddMatchSignal(opts...); err != nil {
		log.Error().Err(err).Str("interface", networkInterface).Msg("Failed to add DBus match signal")
		return fmt.Errorf("failed to add DBus match signal: %w", err)
	}

	log.Info().Msg("Listening to systemd-networkd DBus events")
	sigChannel := make(chan *dbus.Signal, 512)
	conn.Signal(sigChannel)

	for v := range sigChannel {
		if v == nil || len(v.Body) < 1 {
			log.Warn().Msg("Received invalid DBus signal")
			continue
		}

		iface, ok := v.Body[0].(string)
		if !ok {
			log.Warn().Msg("Invalid DBus signal interface format")
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
		if strings.HasPrefix(iface, networkInterfaceLink) {
			log.Debug().Str("interface", iface).Msg("Processing link DBus signal")
			go func() {
				defer cancel()
				if err := processDBusLinkMessage(n, v, cfg); err != nil {
					log.Warn().Err(err).Str("interface", iface).Msg("Failed to process link signal")
				}
			}()
		} else if strings.HasPrefix(iface, dbusManagerInterface) {
			log.Debug().Str("interface", iface).Msg("Processing manager DBus signal")
			go func() {
				defer cancel()
				if err := processDBusManagerMessage(n, v); err != nil {
					log.Warn().Err(err).Str("interface", iface).Msg("Failed to process manager signal")
				}
			}()
		} else {
			cancel()
		}
	}

	return nil
}
