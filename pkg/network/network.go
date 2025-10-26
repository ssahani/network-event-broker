// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/vmware/network-event-broker/pkg/conf"
)

// Network manages network links, routes, and routing rules with thread-safe operations.
type Network struct {
	LinksByName               map[string]int          // Maps link names to their indices.
	LinksByIndex              map[int]string          // Maps link indices to their names.
	RoutesByIndex             map[int]*Route          // Maps link indices to their routes.
	RoutingRulesByAddressFrom map[string]*RoutingRule // Maps source addresses to routing rules.
	RoutingRulesByAddressTo   map[string]*RoutingRule // Maps destination addresses to routing rules.
	Mutex                     *sync.Mutex             // Protects concurrent access to maps.
}

// New creates and initializes a new Network instance.
func New() *Network {
	return &Network{
		LinksByName:               make(map[string]int),
		LinksByIndex:              make(map[int]string),
		RoutesByIndex:             make(map[int]*Route),
		RoutingRulesByAddressFrom: make(map[string]*RoutingRule),
		RoutingRulesByAddressTo:   make(map[string]*RoutingRule),
		Mutex:                     &sync.Mutex{},
	}
}

// ConfigureNetwork adds a default gateway and routing rules for a specified link.
func ConfigureNetwork(link string, n *Network) error {
	if n == nil {
		log.Error().Msg("Network instance cannot be nil")
		return errors.New("network instance cannot be nil")
	}
	if link == "" {
		log.Error().Msg("Link name cannot be empty")
		return errors.New("link name cannot be empty")
	}

	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	index, ok := n.LinksByName[link]
	if !ok {
		log.Error().Str("link", link).Msg("Link not found in LinksByName")
		return fmt.Errorf("link %q not found", link)
	}

	gw, err := GetIPv4Gateway(index)
	if err != nil {
		log.Warn().Str("link", link).Int("ifindex", index).Err(err).Msg("Failed to find IPv4 gateway")
		return fmt.Errorf("failed to find IPv4 gateway for link %s (ifindex %d): %w", link, index, err)
	}

	rt := &Route{
		IfIndex: index,
		Gw:      gw,
		Table:   conf.ROUTE_TABLE_BASE + index,
	}

	if err := rt.RouteAdd(); err != nil {
		log.Warn().
			Str("link", link).
			Int("ifindex", index).
			Str("gw", gw).
			Int("table", rt.Table).
			Err(err).
			Msg("Failed to add default gateway")
		return fmt.Errorf("failed to add default gateway for link %s (ifindex %d, gw %s, table %d): %w", link, index, gw, rt.Table, err)
	}

	n.RoutesByIndex[index] = rt
	log.Info().
		Str("link", link).
		Int("ifindex", index).
		Str("gw", gw).
		Int("table", rt.Table).
		Msg("Successfully added default gateway")

	addresses, err := getIPv4AddressesByLink(link)
	if err != nil {
		log.Error().
			Str("link", link).
			Int("ifindex", index).
			Err(err).
			Msg("Failed to fetch IPv4 addresses")
		return fmt.Errorf("failed to fetch IPv4 addresses for link %s (ifindex %d): %w", link, index, err)
	}

	for address := range addresses {
		if err := n.addAddressRule(address, link, index); err != nil {
			log.Warn().
				Str("link", link).
				Int("ifindex", index).
				Str("address", address).
				Err(err).
				Msg("Failed to add routing rule")
			continue
		}
	}

	return nil
}

// addAddressRule adds source and destination routing rules for an address.
func (n *Network) addAddressRule(address, link string, index int) error {
	if address == "" {
		log.Error().Str("link", link).Int("ifindex", index).Msg("Address cannot be empty")
		return fmt.Errorf("address cannot be empty")
	}
	if link == "" || index < 0 {
		log.Error().Str("link", link).Int("ifindex", index).Str("address", address).Msg("Invalid link or interface index")
		return fmt.Errorf("invalid link %q or interface index %d", link, index)
	}

	// Validate IP address format.
	addr := strings.TrimSuffix(strings.Split(address, "/")[0], "/")
	if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
		log.Error().Str("address", address).Str("link", link).Int("ifindex", index).Msg("Invalid IPv4 address")
		return fmt.Errorf("invalid IPv4 address: %s", address)
	}

	table := conf.ROUTE_TABLE_BASE + index

	// Add 'from' routing rule.
	fromRule := &RoutingRule{
		From:  addr,
		Table: table,
	}
	if err := fromRule.RoutingPolicyRuleAdd(); err != nil {
		log.Warn().
			Str("address", address).
			Str("link", link).
			Int("ifindex", index).
			Int("table", table).
			Err(err).
			Msg("Failed to add 'from' routing policy rule")
		return fmt.Errorf("failed to add 'from' routing policy rule for address %s on link %s (ifindex %d, table %d): %w", address, link, index, table, err)
	}
	n.RoutingRulesByAddressFrom[address] = fromRule
	log.Debug().
		Str("address", address).
		Str("link", link).
		Int("ifindex", index).
		Int("table", table).
		Msg("Successfully added 'from' routing policy rule")

	// Add 'to' routing rule.
	toRule := &RoutingRule{
		To:    addr,
		Table: table,
	}
	if err := toRule.RoutingPolicyRuleAdd(); err != nil {
		log.Warn().
			Str("address", address).
			Str("link", link).
			Int("ifindex", index).
			Int("table", table).
			Err(err).
			Msg("Failed to add 'to' routing policy rule")
		// Attempt to clean up 'from' rule if 'to' rule fails.
		if err := fromRule.RoutingPolicyRuleRemove(); err != nil {
			log.Error().
				Str("address", address).
				Str("link", link).
				Int("ifindex", index).
				Int("table", table).
				Err(err).
				Msg("Failed to cleanup 'from' routing policy rule")
		}
		delete(n.RoutingRulesByAddressFrom, address)
		return fmt.Errorf("failed to add 'to' routing policy rule for address %s on link %s (ifindex %d, table %d): %w", address, link, index, table, err)
	}
	n.RoutingRulesByAddressTo[address] = toRule
	log.Debug().
		Str("address", address).
		Str("link", link).
		Int("ifindex", index).
		Int("table", table).
		Msg("Successfully added 'to' routing policy rule")

	return nil
}

// IsRulesByTableEmpty checks if there are no routing rules for a given table.
func (n *Network) IsRulesByTableEmpty(table int) bool {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	fromCount := 0
	toCount := 0

	for _, rule := range n.RoutingRulesByAddressFrom {
		if rule.Table == table {
			fromCount++
		}
	}
	for _, rule := range n.RoutingRulesByAddressTo {
		if rule.Table == table {
			toCount++
		}
	}

	isEmpty := fromCount == 0 && toCount == 0
	log.Debug().
		Int("table", table).
		Bool("empty", isEmpty).
		Int("from_count", fromCount).
		Int("to_count", toCount).
		Msg("Checked routing rules for table")
	return isEmpty
}
