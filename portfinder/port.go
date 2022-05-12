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
	"fmt"
	"net"
	"strconv"
)

// ForwardedPortRange describes a port or port range in a network namespace
// (such as the "host") to be forwarded to a potentially shifted range of ports
// on one or more new destination IP(s). Multiple forwarded destination IPs can
// used in case of load-balancing between multiple instances of the same
// service.
type ForwardedPortRange struct {
	Protocol       string // such as "tcp" and "udp".
	IP             net.IP // the original destination IP address to forward from, if any.
	PortMin        uint16 // original destination port...
	PortMax        uint16 // ...or port range.
	ForwardIP      net.IP // new destionation IP address to forward to.
	ForwardPortMin uint16 // the new (min) destination port to forward to.
}

// String returns the port forwarding information in plain textual format, such
// as for simple logging, et cetera. In case of a single forwarded port only,
// the port range automatically will be collapsed into a single port only.
func (f ForwardedPortRange) String() string {
	portRange := strconv.FormatUint(uint64(f.PortMin), 10)
	if f.PortMax != f.PortMin {
		portRange += "-" + strconv.FormatUint(uint64(f.PortMax), 10)
	}
	return fmt.Sprintf("forwarding %s from %s:%s to %s:%d",
		f.Protocol,
		f.ipString(f.IP), portRange,
		f.ipString(f.ForwardIP), f.ForwardPortMin)
}

// ipString returns the IP address in its textual form so that it can be
// combined with port numbers without any ambiguities. For IPv6 addresses this
// is the "[]" format expressed in [RFC 3986] and also [RFC 5952].
//
// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986
// [RFC 5952]: https://www.rfc-editor.org/rfc/rfc5952#section-6
func (f ForwardedPortRange) ipString(ip net.IP) string {
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return "[" + ip.String() + "]"
}
