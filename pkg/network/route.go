// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Route represents a network route configuration.
type Route struct {
	Table   int    `json:"Table"`   // Routing table ID.
	IfIndex int    `json:"IfIndex"` // Interface index.
	Gw      string `json:"Gw"`      // Gateway IP address.
}

// getIPv4GatewayByLink retrieves the first IPv4 gateway for a specific link.
func getIPv4GatewayByLink(ifIndex int) (string, error) {
	if ifIndex < 0 {
		return "", fmt.Errorf("invalid interface index: %d", ifIndex)
	}

	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		log.Error().Int("ifindex", ifIndex).Err(err).Msg("Failed to list IPv4 routes")
		return "", fmt.Errorf("failed to list IPv4 routes: %w", err)
	}

	for _, route := range routes {
		if route.LinkIndex == ifIndex && route.Gw != nil {
			gw := route.Gw.To4()
			if gw == nil {
				log.Warn().Int("ifindex", ifIndex).Str("gw", route.Gw.String()).Msg("Gateway is not IPv4")
				continue
			}
			log.Debug().Int("ifindex", ifIndex).Str("gw", gw.String()).Msg("Found IPv4 gateway")
			return gw.String(), nil
		}
	}

	log.Debug().Int("ifindex", ifIndex).Msg("No IPv4 gateway found for link")
	return "", errors.New("no IPv4 gateway found")
}

// getDefaultIPv4GatewayByLink retrieves the default IPv4 gateway for a specific link.
func getDefaultIPv4GatewayByLink(ifIndex int) (string, error) {
	if ifIndex < 0 {
		return "", fmt.Errorf("invalid interface index: %d", ifIndex)
	}

	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		log.Error().Int("ifindex", ifIndex).Err(err).Msg("Failed to list IPv4 routes")
		return "", fmt.Errorf("failed to list IPv4 routes: %w", err)
	}

	for _, route := range routes {
		if route.LinkIndex == ifIndex && (route.Dst == nil || route.Dst.String() == "0.0.0.0/0") {
			if route.Gw == nil {
				log.Warn().Int("ifindex", ifIndex).Msg("Default route found but no gateway specified")
				continue
			}
			gw := route.Gw.To4()
			if gw == nil {
				log.Warn().Int("ifindex", ifIndex).Str("gw", route.Gw.String()).Msg("Default gateway is not IPv4")
				continue
			}
			log.Debug().Int("ifindex", ifIndex).Str("gw", gw.String()).Msg("Found default IPv4 gateway")
			return gw.String(), nil
		}
	}

	log.Debug().Int("ifindex", ifIndex).Msg("No default IPv4 gateway found for link")
	return "", errors.New("no default IPv4 gateway found")
}

// getDefaultIPv4Gateway retrieves the system-wide default IPv4 gateway.
func getDefaultIPv4Gateway() (string, error) {
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list IPv4 routes")
		return "", fmt.Errorf("failed to list IPv4 routes: %w", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			if route.Gw == nil {
				log.Warn().Msg("Default route found but no gateway specified")
				return "", errors.New("default route found but no gateway specified")
			}
			gw := route.Gw.To4()
			if gw == nil {
				log.Warn().Str("gw", route.Gw.String()).Msg("Default gateway is not IPv4")
				return "", errors.New("default gateway is not IPv4")
			}
			log.Debug().Str("gw", gw.String()).Msg("Found system-wide default IPv4 gateway")
			return gw.String(), nil
		}
	}

	log.Debug().Msg("No system-wide default IPv4 gateway found")
	return "", errors.New("no default IPv4 gateway found")
}

// GetIPv4Gateway retrieves the IPv4 gateway for a link, prioritizing default routes.
func GetIPv4Gateway(ifIndex int) (string, error) {
	if ifIndex < 0 {
		return "", fmt.Errorf("invalid interface index: %d", ifIndex)
	}

	// Try default gateway for the link first.
	gw, err := getDefaultIPv4GatewayByLink(ifIndex)
	if err == nil && gw != "" {
		return gw, nil
	}
	log.Debug().Int("ifindex", ifIndex).Err(err).Msg("No default gateway found, trying any gateway")

	// Fallback to any gateway for the link.
	gw, err = getIPv4GatewayByLink(ifIndex)
	if err == nil && gw != "" {
		return gw, nil
	}
	log.Debug().Int("ifindex", ifIndex).Err(err).Msg("No link-specific gateway found, trying system-wide default")

	// Final fallback to system-wide default gateway.
	gw, err = getDefaultIPv4Gateway()
	if err != nil {
		log.Error().Int("ifindex", ifIndex).Err(err).Msg("Failed to find any IPv4 gateway")
		return "", fmt.Errorf("failed to find IPv4 gateway for ifindex %d: %w", ifIndex, err)
	}

	return gw, nil
}

// RouteAdd adds a route to the system routing table.
func (r *Route) RouteAdd() error {
	if r == nil {
		return errors.New("route cannot be nil")
	}
	if r.IfIndex < 0 {
		return fmt.Errorf("invalid interface index: %d", r.IfIndex)
	}
	if r.Gw == "" {
		return fmt.Errorf("gateway cannot be empty")
	}

	gwIP := net.ParseIP(r.Gw)
	if gwIP == nil {
		log.Error().Str("gw", r.Gw).Int("ifindex", r.IfIndex).Msg("Invalid gateway IP")
		return fmt.Errorf("invalid gateway IP: %s", r.Gw)
	}
	gw := gwIP.To4()
	if gw == nil {
		log.Error().Str("gw", r.Gw).Int("ifindex", r.IfIndex).Msg("Gateway is not IPv4")
		return fmt.Errorf("gateway %s is not IPv4", r.Gw)
	}

	rt := netlink.Route{
		LinkIndex: r.IfIndex,
		Gw:        gw,
		Table:     r.Table,
	}

	if err := netlink.RouteAdd(&rt); err != nil && err.Error() != "file exists" {
		log.Error().Int("ifindex", r.IfIndex).Str("gw", r.Gw).Int("table", r.Table).Err(err).Msg("Failed to add route")
		return fmt.Errorf("failed to add route (ifindex %d, gw %s, table %d): %w", r.IfIndex, r.Gw, r.Table, err)
	}

	log.Debug().Int("ifindex", r.IfIndex).Str("gw", r.Gw).Int("table", r.Table).Msg("Successfully added route")
	return nil
}

// RouteRemove removes a route from the system routing table.
func (r *Route) RouteRemove() error {
	if r == nil {
		return errors.New("route cannot be nil")
	}
	if r.IfIndex < 0 {
		return fmt.Errorf("invalid interface index: %d", r.IfIndex)
	}
	if r.Gw == "" {
		return fmt.Errorf("gateway cannot be empty")
	}

	gwIP := net.ParseIP(r.Gw)
	if gwIP == nil {
		log.Error().Str("gw", r.Gw).Int("ifindex", r.IfIndex).Msg("Invalid gateway IP")
		return fmt.Errorf("invalid gateway IP: %s", r.Gw)
	}
	gw := gwIP.To4()
	if gw == nil {
		log.Error().Str("gw", r.Gw).Int("ifindex", r.IfIndex).Msg("Gateway is not IPv4")
		return fmt.Errorf("gateway %s is not IPv4", r.Gw)
	}

	rt := netlink.Route{
		LinkIndex: r.IfIndex,
		Gw:        gw,
		Table:     r.Table,
	}

	if err := netlink.RouteDel(&rt); err != nil {
		log.Error().Int("ifindex", r.IfIndex).Str("gw", r.Gw).Int("table", r.Table).Err(err).Msg("Failed to remove route")
		return fmt.Errorf("failed to remove route (ifindex %d, gw %s, table %d): %w", r.IfIndex, r.Gw, r.Table, err)
	}

	log.Debug().Int("ifindex", r.IfIndex).Str("gw", r.Gw).Int("table", r.Table).Msg("Successfully removed route")
	return nil
}
