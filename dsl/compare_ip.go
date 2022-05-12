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
	"net"

	"github.com/google/nftables/expr"
	"github.com/thediveo/nufftables"
)

// OptionalCompareIP returns the next IP address compare expression, if any, or
// nil. It either returns the remaining expressions or the original expressions
// if no IP compare expression could be found. IP here refers to both IPv4 and
// IPv6.
func OptionalCompareIP(exprs nufftables.Expressions) (nufftables.Expressions, net.IP) {
	remexprs, cmp := nufftables.OptionalOfTypeFunc(exprs, isCompareIPExpression)
	if cmp == nil {
		return exprs, nil
	}
	// IP address in cmp.Data is in network order, so we can directly use it
	// with the net.IP type.
	return remexprs, net.IP(cmp.Data)
}

// isCompareIPExpression is static to avoid creating tons of temporary func
// objects jamming the garbage collector.
func isCompareIPExpression(cmp *expr.Cmp) bool {
	return cmp.Op == expr.CmpOpEq && (len(cmp.Data) == 4 || len(cmp.Data) == 16)
}
