// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"fmt"
	"os"
	"strconv"

	"github.com/godbus/dbus/v5"
	"github.com/sirupsen/logrus"
)

// Constants for DBus interfaces and methods.
const (
	dbusProperties = "org.freedesktop.DBus.Properties"

	resolveInterface      = "org.freedesktop.resolve1"
	resolveObjectPath     = "/org/freedesktop/resolve1"
	resolveSetLinkDNS     = resolveInterface + ".Manager.SetLinkDNS"
	resolveSetLinkDomains = resolveInterface + ".Manager.SetLinkDomains"
	resolveRevertLink     = resolveInterface + ".Manager.RevertLink"

	hostnameInterface   = "org.freedesktop.hostname1"
	hostnameObjectPath  = "/org/freedesktop/hostname1"
	hostnameSetHostname = hostnameInterface + ".SetStaticHostname"
)

// DnsServer represents a DNS server configuration.
type DnsServer struct {
	Family  int32
	Address []byte
}

// Domain represents a DNS domain configuration.
type Domain struct {
	Domain  string
	Routing bool // Renamed 'Set' to 'Routing' for clarity.
}

// SystemBusPrivateConn establishes a private connection to the system DBus.
func SystemBusPrivateConn() (*dbus.Conn, error) {
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("failed to create private system bus connection: %w", err)
	}

	// Authenticate using external authentication.
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to authenticate on system bus: %w", err)
	}

	// Send Hello message to complete connection setup.
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send Hello message: %w", err)
	}

	return conn, nil
}

// SetResolveDNS configures DNS servers for a network interface.
func SetResolveDNS(dns []DnsServer, index int) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system bus: %w", err)
	}
	defer conn.Close()

	logrus.Debugf("Setting DNS servers for interface index=%d", index)

	obj := conn.Object(resolveInterface, resolveObjectPath)
	if err := obj.Call(resolveSetLinkDNS, 0, index, dns).Err; err != nil {
		return fmt.Errorf("failed to set DNS servers for index=%d: %w", index, err)
	}

	logrus.Debugf("Successfully set DNS servers for interface index=%d", index)
	return nil
}

// SetResolveDomain configures DNS domains for a network interface.
func SetResolveDomain(domains []Domain, index int) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system bus: %w", err)
	}
	defer conn.Close()

	logrus.Debugf("Setting DNS domains for interface index=%d", index)

	obj := conn.Object(resolveInterface, resolveObjectPath)
	if err := obj.Call(resolveSetLinkDomains, 0, index, domains).Err; err != nil {
		return fmt.Errorf("failed to set DNS domains for index=%d: %w", index, err)
	}

	logrus.Debugf("Successfully set DNS domains for interface index=%d", index)
	return nil
}

// RevertDNSLink reverts DNS settings for a network interface.
func RevertDNSLink(index int) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system bus: %w", err)
	}
	defer conn.Close()

	logrus.Debugf("Reverting DNS settings for interface index=%d", index)

	obj := conn.Object(resolveInterface, resolveObjectPath)
	if err := obj.Call(resolveRevertLink, 0, index).Err; err != nil {
		return fmt.Errorf("failed to revert DNS settings for index=%d: %w", index, err)
	}

	logrus.Debugf("Successfully reverted DNS settings for interface index=%d", index)
	return nil
}

// SetHostname sets the static hostname via DBus.
func SetHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system bus: %w", err)
	}
	defer conn.Close()

	logrus.Debugf("Setting hostname to %q", hostname)

	obj := conn.Object(hostnameInterface, hostnameObjectPath)
	if err := obj.Call(hostnameSetHostname, 0, hostname, true).Err; err != nil {
		return fmt.Errorf("failed to set hostname %q: %w", hostname, err)
	}

	logrus.Debug("Successfully set hostname")
	return nil
}
