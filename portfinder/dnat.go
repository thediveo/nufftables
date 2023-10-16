// Copyright 2022 Harald Albrecht.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy
// of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package portfinder

import (
	"bytes"
	"net"

	"github.com/google/nftables/xt"
	"github.com/thediveo/nufftables"
	"github.com/thediveo/nufftables/dsl"
)

// dnatWithIPsAndPorts are the flags that need to be set in order for the
// xt.NatRange(2) data structures to contain an IP range as well as a transport
// layer port range.
const dnatWithIPsAndPorts = uint(xt.NatRangeMapIPs | xt.NatRangeProtoSpecified)

// A real IPv4 unspecified address ... which isn't an IPv4-mapped IPv6
// unspecified address! $HEAVENS! Why did the Go team mess up this so terribly?!
var ipv4zero = net.ParseIP("0.0.0.0").To4()

// ForwardedPort returns the port range forwarding if contained in the passed
// [nufftables.Rule], otherwise nil.
//
// ForwardedPort ensures that the returned IP addresses are always in their
// canonical IPv4 format, and never in form of IPv4-mapped addresses.
func ForwardedPort(rule nufftables.Rule) *ForwardedPortRange {
	// Pick up the match and target DNAT expressions and make sure that both are
	// present and that the DNAT information contains both IP and port
	// information. An optional original destination IP address match might be
	// present to narrow down the port forwarding.
	exprs, origIP := dsl.OptionalCompareIP(rule.Expressions())
	exprs, proto, minPort, maxPort := dsl.MatchPortRange(exprs)
	exprs, dnat := dsl.TargetDNAT(exprs)
	if exprs == nil || dnat.Flags&dnatWithIPsAndPorts != dnatWithIPsAndPorts ||
		minPort == 0 || dnat.MinPort == 0 {
		return nil
	}
	// In case we didn't find any original (host) destination IP address we
	// return the unspecified IP address instead of nil. However, we ensure that
	// we always return "canonical" IPv4 and not IPv4-mapped IPv6 addresses as
	// this can terribly mess up API users further down the road.
	if origIP == nil {
		if dnat.MinIP.To4() == nil {
			origIP = net.IPv6zero
		} else {
			origIP = ipv4zero // DON'T use the FUBAR'd net.IPv4zero
		}
	}
	return &ForwardedPortRange{
		Protocol:       proto, // "tcp" or "udp"
		IP:             origIP,
		PortMin:        minPort,
		PortMax:        maxPort,
		ForwardIP:      dnat.MinIP,
		ForwardPortMin: dnat.MinPort,
	}
}

// ForwardedPortOrder returns true if the forwarded port range a comes before b.
// The sorting order of two forwarded port ranges a and b is defined as follows:
//   - IPv4 addresses come before IPv6 addresse (or, in other words: IPv4
//     addresses are less than IPv6 addresses *snicker*).
//   - by the original (host) IP address,
//   - by the original beginning of the port range,
//   - finally by the IP address forwarding to.
func ForwardedPortOrder(a, b *ForwardedPortRange) int {
	// sorts IPv4 before IPv6
	av4 := len(a.IP) == net.IPv4len
	bv4 := len(b.IP) == net.IPv4len
	if av4 != bv4 {
		if av4 {
			return -1
		}
		return 1
	}
	// sorts within IP family by original destination address
	if c := bytes.Compare(a.IP, b.IP); c != 0 {
		return c
	}
	// sorts by original min port
	if c := int(a.PortMin) - int(b.PortMin); c != 0 {
		return c
	}
	return bytes.Compare(a.ForwardIP, b.ForwardIP)
}
