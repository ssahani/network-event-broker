// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 VMware, Inc.

package listeners

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jaypipes/ghw"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"

	"github.com/vmware/network-event-broker/pkg/configfile"
	"github.com/vmware/network-event-broker/pkg/parser"
)

// Constants for default timeouts and paths.
const (
	sysClassNetPath = "/sys/class/net"
)

// Route represents a network route configuration.
type Route struct {
	Scope int      `json:"Scope"`
	Dst   struct { // Anonymous struct for destination IP and mask.
		IP   string `json:"IP"`
		Mask int    `json:"Mask"`
	} `json:"Dst"`
	Src       string   `json:"Src"`
	Gw        string   `json:"Gw"`
	MultiPath string   `json:"MultiPath"`
	Protocol  int      `json:"Protocol"`
	Priority  int      `json:"Priority"`
	Table     int      `json:"Table"`
	Type      int      `json:"Type"`
	Tos       int      `json:"Tos"`
	Flags     []string `json:"Flags"`
	MPLSDst   string   `json:"MPLSDst"`
	NewDst    string   `json:"NewDst"`
	Encap     string   `json:"Encap"`
	Mtu       int      `json:"MTU"`
	AdvMSS    int      `json:"AdvMSS"`
	Hoplimit  int      `json:"Hoplimit"`
}

// Address represents a network interface address.
type Address struct {
	IP           string `json:"IP"`
	Family       string `json:"Family"`
	Mask         int    `json:"Mask"`
	Label        string `json:"Label"`
	Flags        int    `json:"Flags"`
	Scope        int    `json:"Scope"`
	Peer         string `json:"Peer"`
	Broadcast    string `json:"Broadcast"`
	PreferredLft int    `json:"PreferredLft"` // Fixed typo in JSON tag.
	ValidLft     int    `json:"ValidLft"`
}

// LinkDescribe describes a network interface with its state and configuration.
type LinkDescribe struct {
	Index            int                     `json:"Index"`
	Mtu              int                     `json:"MTU"`
	TxQLen           int                     `json:"TxQLen"`
	Name             string                  `json:"Name"`
	AlternativeNames string                  `json:"AlternativeNames"`
	HardwareAddr     string                  `json:"HardwareAddr"`
	Flags            string                  `json:"Flags"`
	RawFlags         uint32                  `json:"RawFlags"`
	ParentIndex      int                     `json:"ParentIndex"`
	MasterIndex      int                     `json:"MasterIndex"`
	Namespace        string                  `json:"Namespace"`
	Alias            string                  `json:"Alias"`
	Statistics       *netlink.LinkStatistics `json:"Statistics"`
	Promisc          int                     `json:"Promisc"`
	Xdp              struct {
		Fd       int  `json:"Fd"`
		Attached bool `json:"Attached"`
		Flags    int  `json:"Flags"`
		ProgID   int  `json:"ProgId"`
	} `json:"Xdp"`
	EncapType        string    `json:"EncapType"`
	Protinfo         string    `json:"Protinfo"`
	OperState        string    `json:"OperState"`
	NetNsID          int       `json:"NetNsID"`
	NumTxQueues      int       `json:"NumTxQueues"`
	NumRxQueues      int       `json:"NumRxQueues"`
	GSOMaxSize       uint32    `json:"GSOMaxSize"`
	GSOMaxSegs       uint32    `json:"GSOMaxSegs"`
	Group            uint32    `json:"Group"`
	Slave            string    `json:"Slave"`
	KernelOperState  string    `json:"KernelOperState"`
	AddressState     string    `json:"AddressState"`
	CarrierState     string    `json:"CarrierState"`
	Driver           string    `json:"Driver"`
	IPv4AddressState string    `json:"IPv4AddressState"`
	IPv6AddressState string    `json:"IPv6AddressState"`
	LinkFile         string    `json:"LinkFile"`
	Model            string    `json:"Model"`
	OnlineState      string    `json:"OnlineState"`
	OperationalState string    `json:"OperationalState"`
	Path             string    `json:"Path"`
	SetupState       string    `json:"SetupState"`
	Type             string    `json:"Type"`
	Vendor           string    `json:"Vendor"`
	ProductID        string    `json:"ProductID"`
	Manufacturer     string    `json:"Manufacturer"`
	NetworkFile      string    `json:"NetworkFile,omitempty"`
	DNS              []string  `json:"DNS"`
	Domains          []string  `json:"Domains"`
	DomainSearch     []string  `json:"DomainSearch"`
	NTP              []string  `json:"NTP"`
	Addresses        []Address `json:"Addresses"` // Fixed JSON tag typo.
	Routes           []Route   `json:"Routes"`
}

// LinksDescribe holds a collection of LinkDescribe objects.
type LinksDescribe struct {
	Interfaces []LinkDescribe `json:"Interfaces"`
}

// fillOneRoute populates a Route struct from a netlink.Route.
func fillOneRoute(rt *netlink.Route) Route {
	if rt == nil {
		return Route{}
	}

	route := Route{
		Scope:     int(rt.Scope),
		Protocol:  rt.Protocol,
		Priority:  rt.Priority,
		Table:     rt.Table,
		Type:      rt.Type,
		Tos:       rt.Tos,
		Mtu:       rt.MTU,
		AdvMSS:    rt.AdvMSS,
		Hoplimit:  rt.Hoplimit,
		MultiPath: rt.MultiPath.String(),
		MPLSDst:   rt.MPLSDst.String(),
		NewDst:    rt.NewDst.String(),
		Encap:     rt.Encap.String(),
	}

	if rt.Gw != nil {
		route.Gw = rt.Gw.String()
	}
	if rt.Src != nil {
		route.Src = rt.Src.String()
	}
	if rt.Dst != nil {
		route.Dst.IP = rt.Dst.IP.String()
		route.Dst.Mask, _ = rt.Dst.Mask.Size()
	}
	if rt.Flags != 0 {
		route.Flags = rt.ListFlags()
	}

	return route
}

// fillOneAddress populates an Address struct from a netlink.Addr.
func fillOneAddress(addr *netlink.Addr) Address {
	if addr == nil {
		return Address{}
	}

	a := Address{
		IP:           addr.IP.String(),
		Label:        addr.Label,
		Scope:        addr.Scope,
		Flags:        addr.Flags,
		PreferredLft: addr.PreferedLft, // Fixed typo in field name.
		ValidLft:     addr.ValidLft,
		Family:       parser.IP4or6(addr.IP.String()),
	}

	if mask, _ := addr.Mask.Size(); mask > 0 {
		a.Mask = mask
	}
	if addr.Peer != nil {
		a.Peer = addr.Peer.String()
	}
	if addr.Broadcast != nil {
		a.Broadcast = addr.Broadcast.String()
	}

	return a
}

// fillOneLink populates a LinkDescribe struct from a netlink.Link.
func fillOneLink(link netlink.Link) *LinkDescribe {
	if link == nil || link.Attrs() == nil {
		log.Warn().Msg("Nil link or link attributes, returning empty LinkDescribe")
		return &LinkDescribe{}
	}

	attrs := link.Attrs()
	l := &LinkDescribe{
		Type:            attrs.EncapType,
		KernelOperState: attrs.OperState.String(),
		Index:           attrs.Index,
		Mtu:             attrs.MTU,
		TxQLen:          attrs.TxQLen,
		Name:            attrs.Name,
		HardwareAddr:    attrs.HardwareAddr.String(),
		RawFlags:        attrs.RawFlags,
		ParentIndex:     attrs.ParentIndex,
		MasterIndex:     attrs.MasterIndex,
		Alias:           attrs.Alias,
		EncapType:       attrs.EncapType,
		OperState:       attrs.OperState.String(),
		NetNsID:         attrs.NetNsID,
		NumTxQueues:     attrs.NumTxQueues,
		NumRxQueues:     attrs.NumRxQueues,
		GSOMaxSize:      attrs.GSOMaxSize,
		GSOMaxSegs:      attrs.GSOMaxSegs,
		Group:           attrs.Group,
		Statistics:      attrs.Statistics,
		Promisc:         attrs.Promisc,
		Flags:           attrs.Flags.String(),
	}

	// Fetch link states, log errors but continue to avoid partial data loss.
	if state, err := ParseLinkAddressState(attrs.Index); err == nil {
		l.AddressState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse AddressState")
	}
	if state, err := ParseLinkIPv4AddressState(attrs.Index); err == nil {
		l.IPv4AddressState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse IPv4AddressState")
	}
	if state, err := ParseLinkIPv6AddressState(attrs.Index); err == nil {
		l.IPv6AddressState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse IPv6AddressState")
	}
	if state, err := ParseLinkCarrierState(attrs.Index); err == nil {
		l.CarrierState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse CarrierState")
	}
	if state, err := ParseLinkOnlineState(attrs.Index); err == nil {
		l.OnlineState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse OnlineState")
	}
	if state, err := ParseLinkOperationalState(attrs.Index); err == nil {
		l.OperationalState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse OperationalState")
	}
	if state, err := ParseLinkSetupState(attrs.Index); err == nil {
		l.SetupState = state
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse SetupState")
	}
	if file, err := ParseLinkNetworkFile(attrs.Index); err == nil {
		l.NetworkFile = file
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse NetworkFile")
	}
	if dns, err := ParseLinkDNS(attrs.Index); err == nil {
		l.DNS = dns
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse DNS")
	}
	if domains, err := ParseLinkDomains(attrs.Index); err == nil {
		l.Domains = domains
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse Domains")
	}
	if ntp, err := ParseLinkNTP(attrs.Index); err == nil {
		l.NTP = ntp
	} else {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to parse NTP")
	}

	// Fetch addresses.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to list addresses")
	} else {
		for _, a := range addrs {
			l.Addresses = append(l.Addresses, fillOneAddress(&a))
		}
	}

	// Fetch routes for this link.
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.Warn().Int("ifindex", attrs.Index).Err(err).Msg("Failed to list routes")
	} else {
		for _, rt := range routes {
			l.Routes = append(l.Routes, fillOneRoute(&rt))
		}
	}

	// Fetch PCI and driver information.
	ueventPath := filepath.Join(sysClassNetPath, attrs.Name, "device/uevent")
	if pciSlot, err := configfile.ParseKeyFromSectionString(ueventPath, "", "PCI_SLOT_NAME"); err == nil {
		if pci, err := ghw.PCI(); err == nil {
			if dev := pci.GetDevice(pciSlot); dev != nil {
				l.Model = dev.Product.Name
				l.Vendor = dev.Vendor.Name
				l.Path = "pci-" + dev.Address
				l.Driver = dev.Driver
				l.ProductID = dev.Product.ID
			} else {
				log.Warn().Str("pci_slot", pciSlot).Msg("PCI device not found")
			}
		} else {
			log.Warn().Str("pci_slot", pciSlot).Err(err).Msg("Failed to initialize PCI info")
		}
	} else {
		log.Debug().Str("path", ueventPath).Err(err).Msg("Failed to parse PCI_SLOT_NAME")
	}

	if driver, err := configfile.ParseKeyFromSectionString(ueventPath, "", "DRIVER"); err == nil {
		l.Driver = driver
	} else {
		log.Debug().Str("path", ueventPath).Err(err).Msg("Failed to parse DRIVER")
	}

	return l
}

// buildLinkMessageFallback retrieves link information using netlink as a fallback.
func buildLinkMessageFallback(link string) (*LinkDescribe, error) {
	l, err := netlink.LinkByName(link)
	if err != nil {
		log.Error().Str("link", link).Err(err).Msg("Failed to get link by name")
		return nil, fmt.Errorf("failed to get link %q: %w", link, err)
	}

	log.Debug().Str("link", link).Msg("Using netlink fallback for link description")
	return fillOneLink(l), nil
}

// acquireLink retrieves link information via DBus or falls back to netlink.
func acquireLink(link string) (*LinkDescribe, error) {
	if link == "" {
		return nil, errors.New("link name cannot be empty")
	}

	c, err := NewSDConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to establish system bus connection")
		return buildLinkMessageFallback(link)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	links, err := c.DBusLinkDescribe(ctx)
	if err != nil {
		log.Warn().Err(err).Str("link", link).Msg("Failed to describe link via DBus, using fallback")
		return buildLinkMessageFallback(link)
	}

	for _, l := range links.Interfaces {
		if l.Name == link {
			log.Debug().Str("link", link).Msg("Found link via DBus")
			return &l, nil
		}
	}

	log.Warn().Str("link", link).Msg("Link not found via DBus")
	return nil, fmt.Errorf("link %q not found", link)
}
