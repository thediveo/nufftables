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

package dsl

import (
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/thediveo/nufftables"
)

// MatchPortRange returns the (non-inverted) port range and transport protocol
// from a matching [expr.Match] expression, as well as the remaining
// expressions. Protocol names returned are either "tcp" or "udp". If no
// suitable Match expression was found, then the remaining expressions are
// returned as nil, together with an empty protocol name.
func MatchPortRange(exprs nufftables.Expressions) (e nufftables.Expressions, protocol string, minport, maxport uint16) {
	exprs, match := nufftables.OfTypeFunc(exprs, isTCPUDPPortRange)
	if exprs == nil {
		return nil, "", 0, 0
	}
	// The port(s) to forward to are specified in the extension payload and this
	// payload type depends upon the protocol (TCP or UDP).
	switch info := match.Info.(type) {
	case *xt.Tcp:
		return exprs, match.Name, info.DstPorts[0], info.DstPorts[1]
	case *xt.Udp:
		return exprs, match.Name, info.DstPorts[0], info.DstPorts[1]
	default:
	}
	return nil, "", 0, 0
}

// isTCPUDPPortRange returns true if the passed Match expression contains port
// range information suitable for the TCP or UDP protocol and the port range
// isn't inverted.
func isTCPUDPPortRange(match *expr.Match) bool {
	switch info := match.Info.(type) {
	case *xt.Tcp:
		return info.InvFlags == 0
	case *xt.Udp:
		return info.InvFlags == 0
	}
	return false
}
