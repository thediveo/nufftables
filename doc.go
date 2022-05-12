/*
Package nufftables is a thin wrapper around Google's nftables to ease reasoning
over the current state of tables, chains, rules, and expressions. If you just
want to setup and remove netfilter chains and rules, then [google/nftables]
should be sufficient most of the time.

# Information Model

nufftables' information model is basically that of netfilter and Google's
nftables information model in particular, but with the hierarchy added in
explicitly.

  - [Table] wraps [nftables.Table] and references all [Chain] objects belonging
    to this table by name.
  - [Chain] wraps [nftables.Chain] and contains all [Rule] objects for a
    particular chain, sorted by their [nftables.Rule.Position]. It also
    references its containing table.
  - [Rule] wraps [nftables.Rule] with its [Expressions]. Rules reference the
    [Chain] they are contained in.

# Reasoning About Expressions

To simplify “fishing” for expressions in rules, nufftables defines a set of
convenience functions:

  - [OfType] and [OfTypeFunc] for finding and returning the next expression of a
    specific type.
  - [OptionalOfType] and [OptionalOfTypeFunc] work like OfType and OfTypeFunc
    but don't consider failures to find matching expression types to be a
    failure.

For instance,

	remexprs, cmp := nufftables.OptionalOfTypeFunc(
	  rule.Expressions(),
	  func(cmp *expr.Cmp) bool {
	    return cmp.Op == expr.CmpOpEq && len(cmp.Data) == 4
	  })

returns the first [expr.Cmp] expression, if any, that is compares with a given
IPv4 address for equality ([expr.CmpOpEq]). The (optional) search returns either
the remaining expressions after a match, or the original slice of expressions in
case of no match.

In contrast,

	exprs, match := nufftables.OfTypeFunc(
	  exprs, func(match *expr.Match) bool {...})

either returns the first match of an [expr.Match] expression together with the
remaining expressions, or simply a nil match with nil expressions.

These basic building blocks allow to assemble a DSL for netfilter table
expression reasoning, and to finally build high-level functions on top of this
all. Please see the [github.com/thediveo/nufftables/dsl] and
[github.com/thediveo/nufftables/portfinder] packages for more details.

[google/nftables]: https://github.com/google/nftables
*/
package nufftables
