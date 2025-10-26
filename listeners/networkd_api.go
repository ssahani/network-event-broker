// SPDX-License-Identifier: Apache-2.0

package listeners

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vmware/network-event-broker/pkg/configfile"
)

// Constants for file paths and state keys.
const (
	linksStatePath   = "/run/systemd/netif/links"
	networkStatePath = "/run/systemd/netif/state"

	keyAdminState       = "ADMIN_STATE"
	keyCarrierState     = "CARRIER_STATE"
	keyOnlineState      = "ONLINE_STATE"
	keyActivationPolicy = "ACTIVATION_POLICY"
	keyNetworkFile      = "NETWORK_FILE"
	keyOperationalState = "OPER_STATE"
	keyAddressState     = "ADDRESS_STATE"
	keyIPv4AddressState = "IPV4_ADDRESS_STATE"
	keyIPv6AddressState = "IPV6_ADDRESS_STATE"
	keyDNS              = "DNS"
	keyNTP              = "NTP"
	keyDomains          = "DOMAINS"
	keyRouteDomains     = "ROUTE_DOMAINS"
)

// parseLinkString reads a specific key from the link state file for a given interface index.
func parseLinkString(ifindex int, key string) (string, error) {
	if ifindex < 0 {
		return "", fmt.Errorf("invalid interface index: %d", ifindex)
	}

	path := filepath.Join(linksStatePath, strconv.Itoa(ifindex))
	value, err := configfile.ParseKeyFromSectionString(path, "", key)
	if err != nil {
		log.Error().Int("ifindex", ifindex).Str("key", key).Err(err).Msg("Failed to parse link state")
		return "", fmt.Errorf("failed to parse %s for ifindex %d: %w", key, ifindex, err)
	}

	log.Debug().Int("ifindex", ifindex).Str("key", key).Str("value", value).Msg("Parsed link state")
	return strings.TrimSpace(value), nil
}

// parseNetworkState reads a specific key from the network state file.
func parseNetworkState(key string) (string, error) {
	value, err := configfile.ParseKeyFromSectionString(networkStatePath, "", key)
	if err != nil {
		log.Error().Str("key", key).Err(err).Msg("Failed to parse network state")
		return "", fmt.Errorf("failed to parse %s: %w", key, err)
	}

	log.Debug().Str("key", key).Str("value", value).Msg("Parsed network state")
	return strings.TrimSpace(value), nil
}

// parseSpaceSeparatedList parses a space-separated string into a list, handling empty or invalid cases.
func parseSpaceSeparatedList(s string, key string) ([]string, error) {
	if s == "" {
		log.Debug().Str("key", key).Msg("Empty value, returning empty list")
		return nil, nil
	}

	list := strings.Fields(s) // Use Fields to handle multiple spaces or tabs
	if len(list) == 0 {
		log.Debug().Str("key", key).Msg("No valid entries after splitting")
		return nil, nil
	}

	return list, nil
}

// ParseLinkSetupState returns the setup state for a given interface.
func ParseLinkSetupState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyAdminState)
}

// ParseLinkCarrierState returns the carrier state for a given interface.
func ParseLinkCarrierState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyCarrierState)
}

// ParseLinkOnlineState returns the online state for a given interface.
func ParseLinkOnlineState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyOnlineState)
}

// ParseLinkActivationPolicy returns the activation policy for a given interface.
func ParseLinkActivationPolicy(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyActivationPolicy)
}

// ParseLinkNetworkFile returns the network file path for a given interface.
func ParseLinkNetworkFile(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyNetworkFile)
}

// ParseLinkOperationalState returns the operational state for a given interface.
func ParseLinkOperationalState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyOperationalState)
}

// ParseLinkAddressState returns the address state for a given interface.
func ParseLinkAddressState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyAddressState)
}

// ParseLinkIPv4AddressState returns the IPv4 address state for a given interface.
func ParseLinkIPv4AddressState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyIPv4AddressState)
}

// ParseLinkIPv6AddressState returns the IPv6 address state for a given interface.
func ParseLinkIPv6AddressState(ifindex int) (string, error) {
	return parseLinkString(ifindex, keyIPv6AddressState)
}

// ParseLinkDNS returns the DNS servers for a given interface.
func ParseLinkDNS(ifindex int) ([]string, error) {
	s, err := parseLinkString(ifindex, keyDNS)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyDNS)
}

// ParseLinkNTP returns the NTP servers for a given interface.
func ParseLinkNTP(ifindex int) ([]string, error) {
	s, err := parseLinkString(ifindex, keyNTP)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyNTP)
}

// ParseLinkDomains returns the DNS domains for a given interface.
func ParseLinkDomains(ifindex int) ([]string, error) {
	s, err := parseLinkString(ifindex, keyDomains)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyDomains)
}

// ParseNetworkOperationalState returns the network operational state.
func ParseNetworkOperationalState() (string, error) {
	return parseNetworkState(keyOperationalState)
}

// ParseNetworkCarrierState returns the network carrier state.
func ParseNetworkCarrierState() (string, error) {
	return parseNetworkState(keyCarrierState)
}

// ParseNetworkAddressState returns the network address state.
func ParseNetworkAddressState() (string, error) {
	return parseNetworkState(keyAddressState)
}

// ParseNetworkIPv4AddressState returns the network IPv4 address state.
func ParseNetworkIPv4AddressState() (string, error) {
	return parseNetworkState(keyIPv4AddressState)
}

// ParseNetworkIPv6AddressState() returns the network IPv6 address state.
func ParseNetworkIPv6AddressState() (string, error) {
	return parseNetworkState(keyIPv6AddressState)
}

// ParseNetworkOnlineState returns the network online state.
func ParseNetworkOnlineState() (string, error) {
	return parseNetworkState(keyOnlineState)
}

// ParseNetworkDNS returns the network DNS servers.
func ParseNetworkDNS() ([]string, error) {
	s, err := parseNetworkState(keyDNS)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyDNS)
}

// ParseNetworkNTP returns the network NTP servers.
func ParseNetworkNTP() ([]string, error) {
	s, err := parseNetworkState(keyNTP)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyNTP)
}

// ParseNetworkDomains returns the network DNS domains.
func ParseNetworkDomains() ([]string, error) {
	s, err := parseNetworkState(keyDomains)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyDomains)
}

// ParseNetworkRouteDomains returns the network route domains.
func ParseNetworkRouteDomains() ([]string, error) {
	s, err := parseNetworkState(keyRouteDomains)
	if err != nil {
		return nil, err
	}
	return parseSpaceSeparatedList(s, keyRouteDomains)
}
