// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 VMware, Inc.

package listeners

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"

	"github.com/vmware/network-event-broker/pkg/bus"
	"github.com/vmware/network-event-broker/pkg/conf"
	"github.com/vmware/network-event-broker/pkg/network"
	"github.com/vmware/network-event-broker/pkg/parser"
	"github.com/vmware/network-event-broker/pkg/system"
)

// setDNSServer configures DNS servers for a network interface.
func setDNSServer(dnsServers []net.IP, index int) error {
	if len(dnsServers) == 0 {
		log.Debug().Int("ifindex", index).Msg("No DNS servers to configure")
		return nil
	}

	linkDNS := make([]bus.DnsServer, 0, len(dnsServers))
	for _, ip := range dnsServers {
		if ip == nil {
			log.Warn().Int("ifindex", index).Msg("Skipping invalid DNS IP")
			continue
		}
		family := unix.AF_INET
		addr := ip.To4()
		if addr == nil {
			family = unix.AF_INET6
			addr = ip.To16()
		}
		if addr == nil {
			log.Warn().Int("ifindex", index).Str("ip", ip.String()).Msg("Skipping invalid DNS IP")
			continue
		}
		linkDNS = append(linkDNS, bus.DnsServer{
			Family:  family,
			Address: addr,
		})
	}

	if len(linkDNS) == 0 {
		log.Warn().Int("ifindex", index).Msg("No valid DNS servers after filtering")
		return nil
	}

	if err := bus.SetResolveDNS(linkDNS, index); err != nil {
		log.Warn().Int("ifindex", index).Err(err).Msg("Failed to set DNS servers")
		return fmt.Errorf("failed to set DNS servers for ifindex %d: %w", index, err)
	}

	log.Debug().Int("ifindex", index).Int("count", len(linkDNS)).Msg("Successfully set DNS servers")
	return nil
}

// setDNSDomain configures DNS domains for a network interface.
func setDNSDomain(dnsDomains []string, index int) error {
	if len(dnsDomains) == 0 {
		log.Debug().Int("ifindex", index).Msg("No DNS domains to configure")
		return nil
	}

	linkDomains := make([]bus.Domain, 0, len(dnsDomains))
	for _, domain := range dnsDomains {
		if domain == "" {
			log.Warn().Int("ifindex", index).Msg("Skipping empty DNS domain")
			continue
		}
		linkDomains = append(linkDomains, bus.Domain{
			Domain:  domain,
			Routing: true, // Renamed from Set to Routing for clarity (consistent with bus package).
		})
	}

	if len(linkDomains) == 0 {
		log.Warn().Int("ifindex", index).Msg("No valid DNS domains after filtering")
		return nil
	}

	if err := bus.SetResolveDomain(linkDomains, index); err != nil {
		log.Warn().Int("ifindex", index).Err(err).Msg("Failed to set DNS domains")
		return fmt.Errorf("failed to set DNS domains for ifindex %d: %w", index, err)
	}

	log.Debug().Int("ifindex", index).Int("count", len(linkDomains)).Msg("Successfully set DNS domains")
	return nil
}

// executeDHClientLinkStateScripts runs scripts in the routable.d directory for a DHCP lease.
func executeDHClientLinkStateScripts(n *network.Network, link, strIndex, dns, domain, domainSearch, lease string, cfg *conf.Config) error {
	if link == "" || strIndex == "" || cfg == nil {
		return fmt.Errorf("invalid input: link=%q, strIndex=%q, cfg=%v", link, strIndex, cfg)
	}

	scriptDir := filepath.Join(conf.ConfPath, "routable.d")
	scripts, err := system.ReadAllScriptInConfDir(scriptDir)
	if err != nil {
		log.Error().Err(err).Str("dir", scriptDir).Msg("Failed to read script directory")
		return fmt.Errorf("failed to read script directory %s: %w", scriptDir, err)
	}

	if len(scripts) == 0 {
		log.Debug().Str("dir", scriptDir).Msg("No scripts found in directory")
		return nil
	}

	// Prepare environment variables.
	env := append(os.Environ(),
		"LINK="+link,
		"LINKINDEX="+strIndex,
		"DNS="+dns,
		"DOMAIN="+domain,
		"DHCP_LEASE="+lease,
	)
	if domainSearch != "" {
		env = append(env, "DOMAINSEARCH="+domainSearch)
	}

	// Add JSON data if enabled.
	if cfg.Network.EmitJSON {
		linkData, err := acquireLink(link)
		if err == nil {
			linkData.DNS = strings.Split(dns, ",")
			linkData.Domains = strings.Split(domain, ",")
			linkData.DomainSearch = strings.Split(domainSearch, ",")
			if jsonBytes, err := json.Marshal(linkData); err == nil {
				jsonStr := "JSON=" + string(jsonBytes)
				env = append(env, jsonStr)
				log.Debug().Str("link", link).Str("json", jsonStr).Msg("Generated JSON data")
			} else {
				log.Warn().Str("link", link).Err(err).Msg("Failed to marshal link data")
			}
		} else {
			log.Warn().Str("link", link).Err(err).Msg("Failed to acquire link data for JSON")
		}
	}

	// Execute scripts with timeout.
	for _, script := range scripts {
		scriptPath := filepath.Join(scriptDir, script)
		log.Debug().Str("script", scriptPath).Str("link", link).Msg("Executing script")

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

	return nil
}

// TaskDHClient processes DHCP client leases and applies configurations.
func TaskDHClient(n *network.Network, cfg *conf.Config) error {
	if n == nil || cfg == nil {
		return fmt.Errorf("network or config cannot be nil")
	}

	leases, err := parser.ParseDHClientLease()
	if err != nil {
		log.Warn().Str("file", conf.DHClientLeaseFile).Err(err).Msg("Failed to parse DHClient lease file")
		return nil // Continue processing to avoid blocking other tasks.
	}

	for link, lease := range leases {
		index, ok := n.LinksByName[link]
		if !ok {
			log.Debug().Str("link", link).Msg("Link not found in network links")
			continue
		}

		if cfg.Network.Links != "" && !strings.Contains(cfg.Network.Links, link) {
			log.Debug().Str("link", link).Msg("Link not in configured links")
			continue
		}

		strIndex := strconv.Itoa(index)
		dns := strings.Join(lease.Dns, ",")
		domain := strings.Join(lease.Domain, ",")
		domainSearch := strings.Join(lease.DomainSearch, ",")
		dhcpLease := fmt.Sprintf("ADDRESS=%s,DNS=%s,ROUTER=%s,SUBNETMASK=%s,DOMAIN=%s",
			lease.Address, dns, lease.Routers, lease.SubnetMask, domain)

		log.Debug().Str("link", link).Int("ifindex", index).Msg("Processing DHCP lease")

		if err := executeDHClientLinkStateScripts(n, link, strIndex, dns, domain, domainSearch, dhcpLease, cfg); err != nil {
			log.Warn().Str("link", link).Int("ifindex", index).Err(err).Msg("Failed to execute link state scripts")
		}

		if cfg.Network.UseHostname && lease.Hostname != "" {
			if err := bus.SetHostname(lease.Hostname); err != nil {
				log.Warn().Str("hostname", lease.Hostname).Int("ifindex", index).Err(err).Msg("Failed to set hostname")
			} else {
				log.Debug().Str("hostname", lease.Hostname).Int("ifindex", index).Msg("Successfully set hostname")
			}
		}

		if cfg.Network.UseDNS && len(lease.Dns) > 0 {
			dnsServers := make([]net.IP, 0, len(lease.Dns))
			for _, d := range lease.Dns {
				if ip, err := parser.ParseIP(strings.TrimSpace(d)); err == nil && ip != nil {
					dnsServers = append(dnsServers, ip)
				} else {
					log.Warn().Str("dns", d).Int("ifindex", index).Err(err).Msg("Invalid DNS IP")
				}
			}
			if err := setDNSServer(dnsServers, index); err != nil {
				log.Warn().Int("ifindex", index).Err(err).Msg("Failed to configure DNS servers")
			}
		}

		if cfg.Network.UseDomain && len(lease.Domain) > 0 {
			if err := setDNSDomain(lease.Domain, index); err != nil {
				log.Warn().Int("ifindex", index).Err(err).Msg("Failed to configure DNS domains")
			}
		}
	}

	return nil
}

// WatchDHClient monitors the DHClient lease file for changes and processes updates.
func WatchDHClient(n *network.Network, cfg *conf.Config, finished chan bool) {
	if n == nil || cfg == nil {
		log.Fatal().Msg("Network or config cannot be nil")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create file watcher")
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close file watcher")
		}
		finished <- true
	}()

	log.Info().Str("file", conf.DHClientLeaseFile).Msg("Listening to DHClient lease file events")

	// Process leases initially in case they already exist.
	if err := TaskDHClient(n, cfg); err != nil {
		log.Warn().Err(err).Msg("Initial DHClient lease processing failed")
	}

	if err := watcher.Add(conf.DHClientLeaseFile); err != nil {
		log.Error().Err(err).Str("file", conf.DHClientLeaseFile).Msg("Failed to watch DHClient lease file")
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Warn().Msg("File watcher channel closed")
				return
			}
			log.Debug().Str("file", event.Name).Str("op", event.Op.String()).Msg("Received file event")
			if err := TaskDHClient(n, cfg); err != nil {
				log.Warn().Err(err).Msg("Failed to process DHClient lease event")
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				log.Warn().Msg("File watcher error channel closed")
				return
			}
			log.Error().Err(err).Msg("File watcher error")
		}
	}
}
