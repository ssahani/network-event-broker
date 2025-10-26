// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/vmware/network-event-broker/pkg/system"
)

// WatchNetwork starts goroutines to monitor network addresses, routes, and links.
func WatchNetwork(n *Network) {
	if n == nil {
		log.Fatal().Msg("Network instance cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go n.watchAddresses(ctx)
	go n.watchRoutes(ctx)
	go n.watchLinks(ctx)

	// Handle graceful shutdown on context cancellation.
	<-ctx.Done()
	log.Info().Msg("Network watchers stopped")
}

// watchAddresses monitors IP address updates and applies/removes routing rules.
func (n *Network) watchAddresses(ctx context.Context) {
	const maxChannelSize = 1024
	updates := make(chan netlink.AddrUpdate, maxChannelSize)
	done := make(chan struct{}, maxChannelSize)

	if err := netlink.AddrSubscribeWithOptions(updates, done, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Error().Err(err).Msg("Error in IP address update subscription")
		},
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to IP address updates")
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping address watcher")
			close(done)
			return
		case <-done:
			log.Warn().Msg("Address watcher terminated unexpectedly")
			return
		case update, ok := <-updates:
			if !ok {
				log.Warn().Msg("Address update channel closed")
				return
			}

			addr := update.LinkAddress.IP.String()
			if strings.HasPrefix(addr, "fe80") {
				log.Debug().Str("address", addr).Msg("Skipping link-local IPv6 address")
				continue
			}

			mask, _ := update.LinkAddress.Mask.Size()
			ip := addr + "/" + strconv.Itoa(mask)
			log.Info().
				Str("address", ip).
				Int("ifindex", update.LinkIndex).
				Bool("new", update.NewAddr).
				Msg("Received IP address update")

			if update.NewAddr {
				linkName, exists := n.LinksByIndex[update.LinkIndex]
				if !exists {
					log.Warn().Int("ifindex", update.LinkIndex).Msg("Link not found for address update")
					continue
				}
				if err := n.addAddressRule(ip, linkName, update.LinkIndex); err != nil {
					log.Error().
						Str("address", ip).
						Str("link", linkName).
						Int("ifindex", update.LinkIndex).
						Err(err).
						Msg("Failed to add routing rule")
				}
			} else {
				n.dropConfiguration(update.LinkIndex, ip)
			}
		}
	}
}

// watchRoutes monitors route updates and triggers scripts for link changes.
func (n *Network) watchRoutes(ctx context.Context) {
	const maxChannelSize = 1024
	updates := make(chan netlink.RouteUpdate, maxChannelSize)
	done := make(chan struct{}, maxChannelSize)

	if err := netlink.RouteSubscribe(updates, done); err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to route updates")
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping route watcher")
			close(done)
			return
		case <-done:
			log.Warn().Msg("Route watcher terminated unexpectedly")
			return
		case update, ok := <-updates:
			if !ok {
				log.Warn().Msg("Route update channel closed")
				return
			}

			link, err := net.InterfaceByIndex(update.LinkIndex)
			if err != nil {
				log.Error().Int("ifindex", update.LinkIndex).Err(err).Msg("Failed to get link by index")
				continue
			}

			log.Debug().
				Str("link", link.Name).
				Int("ifindex", update.LinkIndex).
				Str("route", update.String()).
				Msg("Received route update")

			if err := system.ExecuteScripts(link.Name, update.LinkIndex); err != nil {
				log.Error().
					Str("link", link.Name).
					Int("ifindex", update.LinkIndex).
					Err(err).
					Msg("Failed to execute scripts for route update")
			}
		}
	}
}

// watchLinks monitors link updates and updates the Network's link mappings.
func (n *Network) watchLinks(ctx context.Context) {
	const maxChannelSize = 1024
	updates := make(chan netlink.LinkUpdate, maxChannelSize)
	done := make(chan struct{}, maxChannelSize)

	if err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Error().Err(err).Msg("Error in link update subscription")
		},
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to link updates")
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping link watcher")
			close(done)
			return
		case <-done:
			log.Warn().Msg("Link watcher terminated unexpectedly")
			return
		case update, ok := <-updates:
			if !ok {
				log.Warn().Msg("Link update channel closed")
				return
			}

			log.Info().
				Str("link", update.Attrs().Name).
				Int("ifindex", int(update.Index)).
				Str("type", update.Header.Type.String()).
				Msg("Received link update")

			n.updateLink(update)
		}
	}
}

// updateLink updates the Network's link mappings based on link updates.
func (n *Network) updateLink(update netlink.LinkUpdate) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	name := update.Attrs().Name
	if name == "" {
		log.Warn().Int("ifindex", int(update.Index)).Msg("Link update missing name")
		return
	}

	switch update.Header.Type {
	case unix.RTM_DELLINK:
		delete(n.LinksByIndex, int(update.Index))
		delete(n.LinksByName, name)
		log.Debug().Str("link", name).Int("ifindex", int(update.Index)).Msg("Link removed")

	case unix.RTM_NEWLINK:
		n.LinksByIndex[int(update.Index)] = name
		n.LinksByName[name] = int(update.Index)
		log.Debug().Str("link", name).Int("ifindex", int(update.Index)).Msg("Link added")
	}
}

// dropConfiguration removes routing rules and routes for a given address and interface.
func (n *Network) dropConfiguration(ifIndex int, address string) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	if address == "" {
		log.Warn().Int("ifindex", ifIndex).Msg("Cannot drop configuration for empty address")
		return
	}

	linkName, exists := n.LinksByIndex[ifIndex]
	if !exists {
		log.Warn().Int("ifindex", ifIndex).Str("address", address).Msg("Link not found for dropping configuration")
		return
	}

	log.Debug().
		Str("address", address).
		Str("link", linkName).
		Int("ifindex", ifIndex).
		Msg("Dropping configuration")

	// Remove 'from' routing rule.
	if rule, ok := n.RoutingRulesByAddressFrom[address]; ok {
		if err := rule.RoutingPolicyRuleRemove(); err != nil {
			log.Error().
				Str("address", address).
				Str("link", linkName).
				Int("ifindex", ifIndex).
				Err(err).
				Msg("Failed to remove 'from' routing rule")
		}
		delete(n.RoutingRulesByAddressFrom, address)
	}

	// Remove 'to' routing rule.
	if rule, ok := n.RoutingRulesByAddressTo[address]; ok {
		if err := rule.RoutingPolicyRuleRemove(); err != nil {
			log.Error().
				Str("address", address).
				Str("link", linkName).
				Int("ifindex", ifIndex).
				Err(err).
				Msg("Failed to remove 'to' routing rule")
		}
		delete(n.RoutingRulesByAddressTo, address)
	}

	// Remove route if no rules remain for the table.
	if rt, ok := n.RoutesByIndex[ifIndex]; ok && n.IsRulesByTableEmpty(rt.Table) {
		log.Debug().
			Str("gw", rt.Gw).
			Str("link", linkName).
			Int("ifindex", ifIndex).
			Int("table", rt.Table).
			Msg("Dropping route as no rules remain")

		if err := rt.RouteRemove(); err != nil {
			log.Error().
				Str("gw", rt.Gw).
				Str("link", linkName).
				Int("ifindex", ifIndex).
				Int("table", rt.Table).
				Err(err).
				Msg("Failed to remove route")
		}
		delete(n.RoutesByIndex, ifIndex)
	}
}
