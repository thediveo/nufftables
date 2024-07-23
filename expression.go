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

// Expressions represents a slice of expr.Any expressions for a single Rule.
type Expressions []expr.Any

// asIs returns its passed expression ”as-is”, acting as the neutral one-to-one
// “transformation” function that returns its passed expression together with
// “ok”/true.
func asIs[E expr.Any](e E) (E, bool) { return e, true }

// satisfying returns a transformation function that in turn returns its passed
// value “e” together with “ok”/true) only if the specified function “fn”
// returns true for the given value “e”. It basically acts as a conditional
// (gated) “neutral” transformation.
func satisfying[E expr.Any](fn func(e E) bool) func(e E) (E, bool) {
	return func(e E) (E, bool) {
		ok := fn(e)
		if !ok {
			var zero E
			return zero, false
		}
		return e, true
	}
}

// OfType returns the first expression (if any) of the specified type E,
// together with the remaining expressions after the match. The type parameter E
// must be a pointer to a concrete nftables expression type, such as
// [*expr.Match], et cetera. If no expression with a matching type could be
// found, then a nil expressions list is returned, together with a zero matching
// expression (~nil).
func OfType[E expr.Any](exprs Expressions) (Expressions, E) {
	return OfTypeTransformed(exprs, asIs[E])
}

// OptionalOfType returns the first expression (if any) of the specified type E,
// together with the remaining expressions after the match; otherwise, it
// returns a zero matching expression of type E (~nil), together with the
// original expressions.
//
// This form allows chaining in optional expressions without further separate
// found/not-found case handling, giving a somewhat “fluent” expression hunting
// experience.
func OptionalOfType[E expr.Any](exprs Expressions) (Expressions, E) {
	return OptionalOfTypeTransformed(exprs, asIs[E])
}

// OfTypeFunc returns the first expression (if any) of the specified type E and
// additionally satisfying fn(E). If no expression with a matching type and
// satisfied fn(E) could be found, then a nil expressions list is returned,
// together with a zero matching expression of type E (~nil).
func OfTypeFunc[E expr.Any](exprs Expressions, fn func(e E) bool) (Expressions, E) {
	return OfTypeTransformed(exprs, satisfying(fn))
}

// OptionalOfTypeFunc returns the first expression (if any) of the specified
// type E and additionally satisfying fn(E), together with the remaining
// expressions after the match; otherwise, it returns a zero matching expression
// of type E (~nil) together with the original expressions.
//
// This form allows chaining in optional expressions without further separate
// found/not-found case handling, giving a somewhat “fluent” expression hunting
// experience.
func OptionalOfTypeFunc[E expr.Any](exprs Expressions, fn func(e E) bool) (Expressions, E) {
	return OptionalOfTypeTransformed(exprs, satisfying(fn))
}

// PrefixedOfTypeFunc returns the first expression (if any) of the specified
// type E also satisfying fn(E) that additionally has a prefix expression of
// type P satisfying prefn(P). If no such twin-match could be found, then a nil
// expressions list is returned together with a zero expression of type E
// (~nil).
func PrefixedOfTypeFunc[P, E expr.Any](exprs Expressions, prefn func(p P) bool, fn func(e E) bool) (Expressions, E) {
	return PrefixedOfTypeTransformed(exprs, prefn, satisfying(fn))
}

// OptionalPrefixedOfTypeFunc returns the first expression (if any) of the
// specified type E also satisfying fn(E) that additionally has a prefix
// expression of type P satisfying prefn(P). If no such twin-match could be
// found, then the original expressions together with a zero expression of type
// E is returned instead.
func OptionalPrefixedOfTypeFunc[P, E expr.Any](exprs Expressions, prefn func(p P) bool, fn func(e E) bool) (Expressions, E) {
	return OptionalPrefixedOfTypeTransformed(exprs, prefn, satisfying(fn))
}

// OfTypeTransformed returns the transformed result of type R of the first
// expression matching the specified type E and additionally satisfying the
// transformator fn(E); otherwise, it returns a zero result expression of type
// R, as well as a nil expressions list.
//
// The passed fn should return the transformed expression of type R as well as
// true upon accepting a match; otherwise, it should return false, so that
// OfTypeTransformed tries to find the next potential match of type E.
func OfTypeTransformed[E expr.Any, R any](exprs Expressions, fn func(e E) (R, bool)) (Expressions, R) {
	for idx, elem := range exprs {
		e, ok := elem.(E)
		if !ok {
			continue
		}
		r, ok := fn(e)
		if !ok {
			continue
		}
		return exprs[idx+1:], r
	}
	var zero R
	return nil, zero
}

// OptionalOfTypeTransformed returns the transformed result of type R of the
// first expression matching the specified type E and additionally satisfying
// the transformator fn(E); otherwise, it returns a zero result expression of
// type R, as well as the original expressions list.
//
// The passed fn should return the transformed expression of type R as well as
// true upon accepting a match; otherwise, it should return false, so that
// OfTypeTransformed tries to find the next potential match of type E.
func OptionalOfTypeTransformed[E expr.Any, R any](exprs Expressions, fn func(e E) (R, bool)) (Expressions, R) {
	remexprs, r := OfTypeTransformed(exprs, fn)
	if remexprs == nil {
		return exprs, r
	}
	return remexprs, r
}

// PrefixedOfTypeTransformed returns the transformed result of type R of the
// first expression matching the specified type E also satisfying fn(E) that
// additionally has a prefix expression of type P satisfying prefn(P). If no
// such twin-match could be found, then a nil expressions list is returned
// together with a zero expression of type E (~nil).
func PrefixedOfTypeTransformed[P, E expr.Any, R any](exprs Expressions, prefn func(p P) bool, fn func(e E) (R, bool)) (Expressions, R) {
	for idx, elem := range exprs {
		p, ok := elem.(P)
		if !ok || !prefn(p) {
			continue
		}
		if idx >= len(exprs)-1 {
			continue
		}
		e, ok := exprs[idx+1].(E)
		if !ok {
			continue
		}
		r, ok := fn(e)
		if !ok {
			continue
		}
		return exprs[idx+2:], r
	}
	var zero R
	return nil, zero
}

// OptionalPrefixedOfTypeTransformed returns the transformed result of type R of
// the first expression matching the specified type E also satisfying fn(E) that
// additionally has a prefix expression of type P satisfying prefn(P);
// otherwise, it returns a zero result expression of type R, as well as the
// original expressions list.
//
// The passed fn should return the transformed expression of type R as well as
// true upon accepting a match; otherwise, it should return false, so that
// OfTypeTransformed tries to find the next potential match of type E.
func OptionalPrefixedOfTypeTransformed[P, E expr.Any, R any](exprs Expressions, precfn func(p P) bool, fn func(e E) (R, bool)) (Expressions, R) {
	remexprs, r := PrefixedOfTypeTransformed(exprs, precfn, fn)
	if remexprs == nil {
		return exprs, r
	}
	return remexprs, r
}
