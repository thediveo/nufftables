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

// TargetDNAT returns the [xt.NatRange2] information from the first matching
// Target DNAT expression, together with the remaining expressions after the
// Target DNAT expression. If no match is found, then nil is returned for the
// remaining expressions.
func TargetDNAT(exprs nufftables.Expressions) (nufftables.Expressions, *xt.NatRange2) {
	remexprs, target := nufftables.OfTypeFunc(exprs, isTargetDNATExpression)
	if remexprs == nil {
		return nil, nil
	}
	natrange2, ok := target.Info.(*xt.NatRange2)
	if !ok {
		// maybe there's another one after this one...?
		return TargetDNAT(remexprs)
	}
	return remexprs, natrange2
}

// isTargetDNATExpression returns true if the given Target expression is a DNAT
// target expression, otherwise false.
func isTargetDNATExpression(target *expr.Target) bool {
	return target.Name == "DNAT"
}
