/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

package network

import (
	"github.com/network-event-broker/pkg/log"
	"github.com/vishvananda/netlink"
)

// Links we want to configure
type Network struct {
	LinksByName  map[string]int
	LinksByIndex map[int]string
}

func AcquireLinks() (*Network, error) {
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	n := Network{
		LinksByName:  make(map[string]int),
		LinksByIndex: make(map[int]string),
	}

	log.Debugf("Acquiring link information")

	for _, link := range linkList {
		if link.Attrs().Name == "lo" {
			continue
		}

		n.LinksByName[link.Attrs().Name] = link.Attrs().Index
		n.LinksByIndex[link.Attrs().Index] = link.Attrs().Name

		log.Debugf("Acquired link='%v' ifindex='%v' from netlink message", link.Attrs().Name, link.Attrs().Index)
	}

	return &n, nil
}
