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

package nufftables

import (
	"fmt"

	"github.com/google/nftables"
)

// TableFamily wraps [nftables.TableFamily] in order to implement the
// [fmt.Stringer] interface.
type TableFamily nftables.TableFamily

// Reexported netfilter table family constants, for convenience.
const (
	TableFamilyUnspecified TableFamily = TableFamily(nftables.TableFamilyUnspecified)
	TableFamilyARP         TableFamily = TableFamily(nftables.TableFamilyARP)
	TableFamilyBridge      TableFamily = TableFamily(nftables.TableFamilyBridge)
	TableFamilyINet        TableFamily = TableFamily(nftables.TableFamilyINet)
	TableFamilyIPv4        TableFamily = TableFamily(nftables.TableFamilyIPv4)
	TableFamilyIPv6        TableFamily = TableFamily(nftables.TableFamilyIPv6)
	TableFamilyNetdev      TableFamily = TableFamily(nftables.TableFamilyNetdev)
)

// String returns the table family name (identifier) for the given TableFamily
// value, such as "inet", "ip" (for IPv4), "ipv6", et cetera.
func (tf TableFamily) String() string {
	switch tf {
	case TableFamily(nftables.TableFamilyINet):
		return "inet"
	case TableFamily(nftables.TableFamilyIPv4):
		return "ip"
	case TableFamily(nftables.TableFamilyIPv6):
		return "ipv6"
	case TableFamily(nftables.TableFamilyARP):
		return "arp"
	case TableFamily(nftables.TableFamilyBridge):
		return "bridge"
	case TableFamily(nftables.TableFamilyNetdev):
		return "netdev"
	default:
		return fmt.Sprintf("TableFamily(%d)", tf)
	}
}
