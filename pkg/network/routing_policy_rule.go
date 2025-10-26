// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RoutingRule represents a routing policy rule for source or destination routing.
type RoutingRule struct {
	From  string `json:"From"`  // Source IP address.
	To    string `json:"To"`    // Destination IP address.
	Table int    `json:"Table"` // Routing table ID.
}

// RoutingPolicyRuleAdd adds a routing policy rule to the system.
func (rule *RoutingRule) RoutingPolicyRuleAdd() error {
	if rule == nil {
		log.Error().Msg("Routing rule cannot be nil")
		return fmt.Errorf("routing rule cannot be nil")
	}
	if rule.Table < 0 {
		log.Error().Int("table", rule.Table).Msg("Invalid routing table")
		return fmt.Errorf("invalid routing table: %d", rule.Table)
	}
	if rule.From == "" && rule.To == "" {
		log.Error().Int("table", rule.Table).Msg("Both From and To IP addresses are empty")
		return fmt.Errorf("both From and To IP addresses are empty")
	}

	// Validate IP addresses.
	if rule.From != "" {
		if ip := net.ParseIP(rule.From); ip == nil {
			log.Error().Str("from", rule.From).Int("table", rule.Table).Msg("Invalid source IP address")
			return fmt.Errorf("invalid source IP address: %s", rule.From)
		}
	}
	if rule.To != "" {
		if ip := net.ParseIP(rule.To); ip == nil {
			log.Error().Str("to", rule.To).Int("table", rule.Table).Msg("Invalid destination IP address")
			return fmt.Errorf("invalid destination IP address: %s", rule.To)
		}
	}

	// Skip rule addition if only one or two interfaces exist (including loopback).
	links, err := netlink.LinkList()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list network links")
		return fmt.Errorf("failed to list network links: %w", err)
	}
	if len(links) <= 2 {
		log.Debug().Int("link_count", len(links)).Int("table", rule.Table).Msg("Skipping routing rule addition due to low link count")
		return nil
	}

	// Check for existing rules to avoid duplicates.
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		log.Error().Err(err).Int("table", rule.Table).Msg("Failed to list IPv4 routing rules")
		return fmt.Errorf("failed to list IPv4 routing rules: %w", err)
	}

	r := netlink.NewRule()
	r.Table = rule.Table
	r.Family = unix.AF_INET // Explicitly set IPv4 family.

	if rule.From != "" {
		r.Src = &net.IPNet{IP: net.ParseIP(rule.From), Mask: net.CIDRMask(32, 32)}
	}
	if rule.To != "" {
		r.Dst = &net.IPNet{IP: net.ParseIP(rule.To), Mask: net.CIDRMask(32, 32)}
	}

	if ruleExists(rules, *r) {
		log.Debug().
			Str("from", rule.From).
			Str("to", rule.To).
			Int("table", rule.Table).
			Msg("Routing rule already exists, skipping")
		return nil
	}

	if err := netlink.RuleAdd(r); err != nil {
		log.Error().
			Str("from", rule.From).
			Str("to", rule.To).
			Int("table", rule.Table).
			Err(err).
			Msg("Failed to add routing rule")
		return fmt.Errorf("failed to add routing rule (from %s, to %s, table %d): %w", rule.From, rule.To, rule.Table, err)
	}

	log.Debug().
		Str("from", rule.From).
		Str("to", rule.To).
		Int("table", rule.Table).
		Msg("Successfully added routing rule")
	return nil
}

// RoutingPolicyRuleRemove removes a routing policy rule from the system.
func (rule *RoutingRule) RoutingPolicyRuleRemove() error {
	if rule == nil {
		log.Error().Msg("Routing rule cannot be nil")
		return fmt.Errorf("routing rule cannot be nil")
	}
	if rule.Table < 0 {
		log.Error().Int("table", rule.Table).Msg("Invalid routing table")
		return fmt.Errorf("invalid routing table: %d", rule.Table)
	}

	r := netlink.NewRule()
	r.Table = rule.Table
	r.Family = unix.AF_INET // Explicitly set IPv4 family.

	if rule.From != "" {
		if ip := net.ParseIP(rule.From); ip == nil {
			log.Error().Str("from", rule.From).Int("table", rule.Table).Msg("Invalid source IP address")
			return fmt.Errorf("invalid source IP address: %s", rule.From)
		}
		r.Src = &net.IPNet{IP: net.ParseIP(rule.From), Mask: net.CIDRMask(32, 32)}
	}
	if rule.To != "" {
		if ip := net.ParseIP(rule.To); ip == nil {
			log.Error().Str("to", rule.To).Int("table", rule.Table).Msg("Invalid destination IP address")
			return fmt.Errorf("invalid destination IP address: %s", rule.To)
		}
		r.Dst = &net.IPNet{IP: net.ParseIP(rule.To), Mask: net.CIDRMask(32, 32)}
	}

	if err := netlink.RuleDel(r); err != nil {
		log.Error().
			Str("from", rule.From).
			Str("to", rule.To).
			Int("table", rule.Table).
			Err(err).
			Msg("Failed to remove routing rule")
		return fmt.Errorf("failed to remove routing rule (from %s, to %s, table %d): %w", rule.From, rule.To, rule.Table, err)
	}

	log.Debug().
		Str("from", rule.From).
		Str("to", rule.To).
		Int("table", rule.Table).
		Msg("Successfully removed routing rule")
	return nil
}

// ruleExists checks if a routing rule already exists in the provided list.
func ruleExists(rules []netlink.Rule, rule netlink.Rule) bool {
	for _, existing := range rules {
		if ruleEquals(existing, rule) {
			return true
		}
	}
	return false
}

// ruleEquals compares two routing rules for equality.
func ruleEquals(a, b netlink.Rule) bool {
	// Ensure family matches (IPv4 in this case).
	if a.Family != b.Family {
		return false
	}

	// Compare table, source, destination, and interface names.
	return a.Table == b.Table &&
		((a.Src == nil && b.Src == nil) || (a.Src != nil && b.Src != nil && a.Src.String() == b.Src.String())) &&
		((a.Dst == nil && b.Dst == nil) || (a.Dst != nil && b.Dst != nil && a.Dst.String() == b.Dst.String())) &&
		a.OifName == b.OifName &&
		a.IifName == b.IifName
}
