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
	"github.com/google/nftables/expr"
)

// Expressions represents a slice of a rule's [expr.Any] expressions.
type Expressions []expr.Any

// OfType returns the first expression of the specified type, together with the
// remaining expressions after the matching expression. The type parameter must
// be a pointer to a concrete expression type, such as [*expr.Match], et cetera.
// If no match could be found, then a nil expressions list is returned together
// with a zero matching expression (~nil).
func OfType[E expr.Any](exprs Expressions) (Expressions, E) {
	for idx, elem := range exprs {
		if e, ok := elem.(E); ok {
			return exprs[idx+1:], e
		}
	}
	var nill E
	return nil, nill
}

// OfTypeFunc returns the first expression of the specified type and
// additionally satisfying f(exprs[i]). If no match could be found, then a nil
// expressions list is returned together with a zero matching expression (~nil).
func OfTypeFunc[E expr.Any](exprs Expressions, f func(e E) bool) (Expressions, E) {
	for idx, elem := range exprs {
		if e, ok := elem.(E); ok && f(e) {
			return exprs[idx+1:], e
		}
	}
	var nill E
	return nil, nill
}

// OptionalOfType returns the first expression of the specified type if found,
// otherwise a zero matching expression (~nil). If a match was found, then the
// remaining expressions are returned, otherwise the original expressions.
func OptionalOfType[E expr.Any](exprs Expressions) (Expressions, E) {
	remexprs, e := OfType[E](exprs)
	if remexprs == nil {
		return exprs, e
	}
	return remexprs, e
}

// OptionalOfTypeFunc returns the first expression of the specified type and
// satisfying f(exprs[i]), otherwise a zero matching expression (~nil). If a
// match was found, then the remaining expressions are returned, otherwise the
// original expressions.
func OptionalOfTypeFunc[E expr.Any](exprs Expressions, f func(e E) bool) (Expressions, E) {
	remexprs, e := OfTypeFunc(exprs, f)
	if remexprs == nil {
		return exprs, e
	}
	return remexprs, e
}
