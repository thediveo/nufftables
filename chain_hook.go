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
	"golang.org/x/sys/unix"
)

// ChainHook wraps [nftables.ChainHook] to support clear-text string
// representations of chain hook values.
type ChainHook nftables.ChainHook

// Name returns the name of a chain hook, based on the (table's) address family
// the hook is used in.
//
// The following chain hook names are currently defined:
//   - PREROUTING, or INGRESS (netdev table family only)
//   - INPUT
//   - FORWARD
//   - OUTPUT
//   - POSTROUTING
func (h ChainHook) Name(fam TableFamily) string {
	switch h {
	case ChainHook(unix.NF_INET_PRE_ROUTING):
		switch fam {
		case TableFamily(nftables.TableFamilyNetdev):
			return "INGRESS"
		default:
			return "PREROUTING"
		}
	case ChainHook(unix.NF_INET_LOCAL_IN):
		return "INPUT"
	case ChainHook(unix.NF_INET_FORWARD):
		return "FORWARD"
	case ChainHook(unix.NF_INET_LOCAL_OUT):
		return "OUTPUT"
	case ChainHook(unix.NF_INET_POST_ROUTING):
		return "POSTROUTING"
	default:
		return fmt.Sprintf("ChainHook(%d)", h)
	}
}
