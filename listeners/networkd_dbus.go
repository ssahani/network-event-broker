// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 VMware, Inc.

package listeners

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/rs/zerolog/log"

	"github.com/vmware/network-event-broker/pkg/bus"
)

// Constants for DBus interface and paths.
const (
	dbusInterface        = "org.freedesktop.network1"
	dbusPath             = "/org/freedesktop/network1"
	dbusManagerInterface = dbusInterface + ".Manager"
	dbusReconfigureLink  = dbusManagerInterface + ".ReconfigureLink"
	dbusReload           = dbusManagerInterface + ".Reload"
	dbusDescribe         = dbusManagerInterface + ".Describe"
)

// SDConnection manages a DBus connection to the network1 service.
type SDConnection struct {
	conn   *dbus.Conn
	object dbus.BusObject
}

// NewSDConnection establishes a new DBus connection to the network1 service.
func NewSDConnection() (*SDConnection, error) {
	conn, err := bus.SystemBusPrivateConn()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to system bus")
		return nil, fmt.Errorf("failed to connect to system bus: %w", err)
	}

	log.Debug().Str("interface", dbusInterface).Str("path", dbusPath).Msg("Established DBus connection")
	return &SDConnection{
		conn:   conn,
		object: conn.Object(dbusInterface, dbus.ObjectPath(dbusPath)),
	}, nil
}

// Close terminates the DBus connection.
func (c *SDConnection) Close() {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close DBus connection")
		} else {
			log.Debug().Msg("Closed DBus connection")
		}
	}
}

// DBusNetworkReconfigureLink reconfigures a network link by interface index.
func (c *SDConnection) DBusNetworkReconfigureLink(ctx context.Context, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid interface index: %d", index)
	}

	log.Debug().Int("ifindex", index).Msg("Reconfiguring network link")
	if err := c.object.CallWithContext(ctx, dbusReconfigureLink, 0, index).Err; err != nil {
		log.Error().Int("ifindex", index).Err(err).Msg("Failed to reconfigure network link")
		return fmt.Errorf("failed to reconfigure link %d: %w", index, err)
	}

	log.Debug().Int("ifindex", index).Msg("Successfully reconfigured network link")
	return nil
}

// DBusNetworkReload reloads the network configuration.
func (c *SDConnection) DBusNetworkReload(ctx context.Context) error {
	log.Debug().Msg("Reloading network configuration")
	if err := c.object.CallWithContext(ctx, dbusReload, 0).Err; err != nil {
		log.Error().Err(err).Msg("Failed to reload network configuration")
		return fmt.Errorf("failed to reload network configuration: %w", err)
	}

	log.Debug().Msg("Successfully reloaded network configuration")
	return nil
}

// DBusLinkDescribe retrieves network link descriptions via DBus.
func (c *SDConnection) DBusLinkDescribe(ctx context.Context) (*LinksDescribe, error) {
	var props string

	log.Debug().Msg("Describing network links via DBus")
	if err := c.object.CallWithContext(ctx, dbusDescribe, 0).Store(&props); err != nil {
		log.Error().Err(err).Msg("Failed to describe network links")
		return nil, fmt.Errorf("failed to describe network links: %w", err)
	}

	var links LinksDescribe
	if err := json.Unmarshal([]byte(props), &links); err != nil {
		log.Error().Err(err).Str("props", props).Msg("Failed to unmarshal link description")
		return nil, fmt.Errorf("failed to unmarshal link description: %w", err)
	}

	log.Debug().Int("interfaces", len(links.Interfaces)).Msg("Successfully described network links")
	return &links, nil
}
