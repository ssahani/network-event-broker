// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

// getIPv4AddressesByLink retrieves IPv4 addresses for a given network link.
func getIPv4AddressesByLink(name string) (map[string]struct{}, error) {
	if name == "" {
		log.Error().Msg("Link name cannot be empty")
		return nil, fmt.Errorf("link name cannot be empty")
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		log.Error().Str("link", name).Err(err).Msg("Failed to get link by name")
		return nil, fmt.Errorf("failed to get link %s: %w", name, err)
	}

	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Error().Str("link", name).Err(err).Msg("Failed to list IPv4 addresses")
		return nil, fmt.Errorf("failed to list IPv4 addresses for link %s: %w", name, err)
	}

	addrMap := make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		if ip := addr.IPNet.IP.To4(); ip == nil {
			log.Debug().Str("link", name).Str("address", addr.IPNet.String()).Msg("Skipping non-IPv4 address")
			continue
		}
		addrStr := addr.IPNet.String()
		addrMap[addrStr] = struct{}{}
		log.Debug().Str("link", name).Str("address", addrStr).Msg("Found IPv4 address")
	}

	if len(addrMap) == 0 {
		log.Debug().Str("link", name).Msg("No IPv4 addresses found for link")
	}

	return addrMap, nil
}
