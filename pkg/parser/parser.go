// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package parser

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/vmware/network-event-broker/pkg/conf"
)

// Lease represents a DHCP client lease configuration.
type Lease struct {
	Interface    string   `json:"Interface"`    // Network interface name.
	Address      string   `json:"Address"`      // Fixed IP address.
	ServerName   string   `json:"ServerName"`   // DHCP server name.
	SubnetMask   string   `json:"SubnetMask"`   // Subnet mask.
	Routers      string   `json:"Routers"`      // Router/gateway IP.
	LeaseTime    string   `json:"LeaseTime"`    // Lease duration.
	Server       string   `json:"Server"`       // DHCP server identifier.
	Hostname     string   `json:"Hostname"`     // Hostname provided by DHCP.
	Dns          []string `json:"Dns"`          // DNS server IPs.
	DomainSearch []string `json:"DomainSearch"` // Domain search list.
	Domain       []string `json:"Domain"`       // Domain names.
}

// ParseIP validates and parses an IP address string.
func ParseIP(ip string) (net.IP, error) {
	if ip = strings.TrimSpace(ip); ip == "" {
		log.Warn().Msg("Invalid empty IP address")
		return nil, fmt.Errorf("invalid empty IP address")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Warn().Str("ip", ip).Msg("Failed to parse IP address")
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	log.Debug().Str("ip", ip).Msg("Successfully parsed IP address")
	return parsedIP, nil
}

// IP4or6 determines whether an IP address is IPv4, IPv6, or invalid.
func IP4or6(ip string) string {
	if ip = strings.TrimSpace(ip); ip == "" {
		log.Warn().Msg("Empty IP address provided")
		return "unknown"
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Warn().Str("ip", ip).Msg("Invalid IP address")
		return "unknown"
	}

	if parsedIP.To4() != nil {
		log.Debug().Str("ip", ip).Msg("Identified as IPv4")
		return "IPv4"
	}
	if parsedIP.To16() != nil {
		log.Debug().Str("ip", ip).Msg("Identified as IPv6")
		return "IPv6"
	}

	log.Warn().Str("ip", ip).Msg("Unknown IP address type")
	return "unknown"
}

// ParseDHClientLease parses the DHCP client lease file into a map of leases by interface.
func ParseDHClientLease() (map[string]*Lease, error) {
	if conf.DHClientLeaseFile == "" {
		log.Error().Msg("DHClient lease file path is empty")
		return nil, fmt.Errorf("DHClient lease file path is empty")
	}

	file, err := os.Open(conf.DHClientLeaseFile)
	if err != nil {
		log.Error().Str("file", conf.DHClientLeaseFile).Err(err).Msg("Failed to open DHClient lease file")
		return nil, fmt.Errorf("failed to open DHClient lease file %s: %w", conf.DHClientLeaseFile, err)
	}
	defer file.Close()

	leases := make(map[string]*Lease)
	var lease *Lease
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, " {"):
			lease = &Lease{}
			log.Debug().Str("file", conf.DHClientLeaseFile).Int("line", lineNumber).Msg("Starting new lease block")
		case strings.HasSuffix(line, "}") && lease != nil:
			if lease.Interface == "" {
				log.Warn().Str("file", conf.DHClientLeaseFile).Int("line", lineNumber).Msg("Lease block missing interface")
				continue
			}
			leases[lease.Interface] = lease
			log.Debug().Str("interface", lease.Interface).Int("line", lineNumber).Msg("Added lease to map")
			lease = nil
		case lease != nil:
			if err := parseLeaseLine(line, lease, lineNumber); err != nil {
				log.Warn().Str("file", conf.DHClientLeaseFile).Int("line", lineNumber).Err(err).Msg("Failed to parse lease line")
				continue
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Str("file", conf.DHClientLeaseFile).Err(err).Msg("Error reading DHClient lease file")
		return nil, fmt.Errorf("error reading DHClient lease file %s: %w", conf.DHClientLeaseFile, err)
	}

	if len(leases) == 0 {
		log.Debug().Str("file", conf.DHClientLeaseFile).Msg("No leases found in file")
	} else {
		log.Debug().Str("file", conf.DHClientLeaseFile).Int("count", len(leases)).Msg("Successfully parsed leases")
	}

	return leases, nil
}

// parseLeaseLine parses a single line in a lease block and updates the Lease struct.
func parseLeaseLine(line string, lease *Lease, lineNumber int) error {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("invalid line format")
	}

	switch {
	case strings.Contains(line, "interface"):
		lease.Interface = strings.Trim(strings.TrimSuffix(fields[1], ";"), "\"")
		log.Debug().Str("interface", lease.Interface).Int("line", lineNumber).Msg("Parsed interface")
	case strings.Contains(line, "fixed-address"):
		lease.Address = strings.TrimSuffix(fields[1], ";")
		log.Debug().Str("address", lease.Address).Int("line", lineNumber).Msg("Parsed fixed-address")
	case strings.Contains(line, "subnet-mask"):
		lease.SubnetMask = strings.TrimSuffix(fields[2], ";")
		log.Debug().Str("subnet_mask", lease.SubnetMask).Int("line", lineNumber).Msg("Parsed subnet-mask")
	case strings.Contains(line, "routers"):
		lease.Routers = strings.TrimSuffix(fields[2], ";")
		log.Debug().Str("routers", lease.Routers).Int("line", lineNumber).Msg("Parsed routers")
	case strings.Contains(line, "dhcp-server-identifier"):
		lease.Server = strings.TrimSuffix(fields[2], ";")
		log.Debug().Str("server", lease.Server).Int("line", lineNumber).Msg("Parsed dhcp-server-identifier")
	case strings.Contains(line, "domain-name-servers"):
		dnsList := strings.TrimSuffix(fields[2], ";")
		lease.Dns = strings.Split(dnsList, ",")
		for i, dns := range lease.Dns {
			lease.Dns[i] = strings.TrimSpace(dns)
			if lease.Dns[i] == "" {
				log.Warn().Int("line", lineNumber).Msg("Empty DNS server in domain-name-servers")
			}
		}
		log.Debug().Strs("dns", lease.Dns).Int("line", lineNumber).Msg("Parsed domain-name-servers")
	case strings.Contains(line, "domain-name"):
		s := strings.TrimPrefix(line, "option domain-name")
		s = strings.Trim(strings.TrimSuffix(s, ";"), "\"")
		domains := strings.Fields(s)
		for _, d := range domains {
			if d = strings.TrimSpace(d); d != "" {
				lease.Domain = append(lease.Domain, d)
			}
		}
		if len(lease.Domain) == 0 {
			log.Warn().Int("line", lineNumber).Msg("No valid domains in domain-name")
		} else {
			log.Debug().Strs("domain", lease.Domain).Int("line", lineNumber).Msg("Parsed domain-name")
		}
	case strings.Contains(line, "host-name"):
		lease.Hostname = strings.Trim(strings.TrimSuffix(fields[1], ";"), "\"")
		log.Debug().Str("hostname", lease.Hostname).Int("line", lineNumber).Msg("Parsed host-name")
	case strings.Contains(line, "domain-search"):
		s := strings.TrimPrefix(line, "option domain-search")
		s = strings.Trim(strings.TrimSuffix(s, ";"), "\"")
		domains := strings.Fields(s)
		for _, d := range domains {
			if d = strings.TrimSpace(d); d != "" {
				lease.DomainSearch = append(lease.DomainSearch, d)
			}
		}
		if len(lease.DomainSearch) == 0 {
			log.Warn().Int("line", lineNumber).Msg("No valid domains in domain-search")
		} else {
			log.Debug().Strs("domain_search", lease.DomainSearch).Int("line", lineNumber).Msg("Parsed domain-search")
		}
	default:
		log.Debug().Str("line", line).Int("line", lineNumber).Msg("Skipped unrecognized lease line")
	}

	return nil
}
