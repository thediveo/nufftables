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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("expression matching", func() {

	Context("internal convenience transformations", func() {

		It("transforms an expression as-is", func() {
			origExpr := &expr.Cmp{Op: expr.CmpOpGt}
			e, ok := asIs(origExpr)
			Expect(ok).To(BeTrue())
			Expect(e).To(BeAssignableToTypeOf(origExpr))
			Expect(e).To(HaveField("Op", expr.CmpOpGt))
		})

		It("transforms an approved an expression as-is", func() {
			approver := satisfying(func(e *expr.Cmp) bool {
				return e.Op == expr.CmpOpGt
			})

			e, ok := approver(&expr.Cmp{Op: expr.CmpOpEq})
			Expect(ok).To(BeFalse())
			Expect(e).To(BeNil())

			e, ok = approver(&expr.Cmp{Op: expr.CmpOpGt})
			Expect(ok).To(BeTrue())
			Expect(e.Op).To(Equal(expr.CmpOpGt))
		})

	})

	Context("OfType/OptionalOfType", func() {

		It("matches a specific expression type and returns it, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			exprs, cmp := OfType[*expr.Cmp](origexprs)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(HaveField("Op", expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))
		})

		It("matches an optional specific expression type and returns it, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			exprs, cmp := OptionalOfType[*expr.Cmp](origexprs)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(HaveField("Op", expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))
		})

		It("returns no expressions when no type match is found", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Counter{},
			}
			exprs, cmp := OfType[*expr.Cmp](origexprs)
			Expect(exprs).To(BeNil())
			Expect(cmp).To(BeNil())
		})

		It("returns all original expressions for lack of optional type match", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Counter{},
			}
			exprs, cmp := OptionalOfType[*expr.Cmp](origexprs)
			Expect(exprs).To(Equal(origexprs))
			Expect(cmp).To(BeNil())
		})

	})

	Context("OfTypeFunc/OptionalOfTypeFunc", func() {

		It("matches a specific expression type and constraint, and then returns it, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpEq,
				},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			f := func(cmp *expr.Cmp) bool {
				return cmp.Op == expr.CmpOpGt
			}
			exprs, cmp := OfTypeFunc(origexprs, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(HaveField("Op", expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))
		})

		It("matches an optional specific expression type and constraint, and then returns it, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			f := func(cmp *expr.Cmp) bool {
				return cmp.Op == expr.CmpOpGt
			}
			exprs, cmp := OptionalOfTypeFunc(origexprs, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(HaveField("Op", expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))
		})

		It("returns no expressions when no match is found", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpEq,
				},
				&expr.Counter{},
			}
			exprs, cmp := OfTypeFunc(
				origexprs,
				func(cmp *expr.Cmp) bool {
					return cmp.Op == expr.CmpOpGt
				})
			Expect(exprs).To(BeNil())
			Expect(cmp).To(BeNil())
		})

		It("returns all expressions for optional (non-) match", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{Op: expr.CmpOpGte},
				&expr.Counter{},
			}
			exprs, cmp := OptionalOfTypeFunc(origexprs,
				func(cmp *expr.Cmp) bool { return false })
			Expect(exprs).To(Equal(origexprs))
			Expect(cmp).To(BeNil())
		})

	})

	Context("PrefixedOfTypeFunc/OptionalPrefixedOfTypeFunc", func() {

		It("matches a twin expression with func constraint", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 666,
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
				},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 42,
				},
				&expr.Counter{},
			}
			p := func(payl *expr.Payload) bool {
				return payl.Base == expr.PayloadBaseNetworkHeader
			}
			f := func(cmp *expr.Cmp) bool {
				return cmp.Op == expr.CmpOpGt
			}
			exprs, cmp := PrefixedOfTypeFunc(origexprs, p, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(And(
				HaveField("Op", expr.CmpOpGt),
				HaveField("Register", uint32(42))))
			Expect(exprs).To(HaveLen(1))
		})

		It("matches an optional twin expression with func constraint", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 666,
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
				},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 42,
				},
				&expr.Counter{},
			}
			p := func(payl *expr.Payload) bool {
				return payl.Base == expr.PayloadBaseNetworkHeader
			}
			f := func(cmp *expr.Cmp) bool {
				return cmp.Op == expr.CmpOpGt
			}
			exprs, cmp := OptionalPrefixedOfTypeFunc(origexprs, p, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp).To(And(
				HaveField("Op", expr.CmpOpGt),
				HaveField("Register", uint32(42))))
			Expect(exprs).To(HaveLen(1))
		})

		It("returns original expressions for missing optional match with prefix and func constraint", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 666,
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
				},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 42,
				},
				&expr.Counter{},
			}
			p := func(payl *expr.Payload) bool {
				return payl.Base == expr.PayloadBaseNetworkHeader
			}
			f := func(cmp *expr.Cmp) bool {
				return cmp.Op == expr.CmpOpGt && cmp.Register == 666
			}
			exprs, cmp := OptionalPrefixedOfTypeFunc(origexprs, p, f)
			Expect(exprs).To(Equal(origexprs))
			Expect(cmp).To(BeNil())
		})

	})

	Context("OfTypeTransformed", func() {

		It("matches a specific expression type and constraint, and then return its transformation, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			f := func(cmp *expr.Cmp) (expr.CmpOp, bool) {
				return cmp.Op, true
			}
			exprs, op := OfTypeTransformed(origexprs, f)
			Expect(exprs).NotTo(BeNil())
			Expect(op).To(Equal(expr.CmpOpGt))
		})

		It("matches a specific expression type and constraint, and then return its transformation, together with the remaining expressions", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Cmp{},
				&expr.Cmp{
					Op: expr.CmpOpGt,
				},
				&expr.Counter{},
			}
			f := func(cmp *expr.Cmp) (expr.CmpOp, bool) {
				if cmp.Op == 0 {
					return 0, false
				}
				return cmp.Op, true
			}
			exprs, op := OfTypeTransformed(origexprs, f)
			Expect(exprs).NotTo(BeNil())
			Expect(op).To(Equal(expr.CmpOpGt))
			Expect(exprs[0]).To(BeIdenticalTo(origexprs[3]))
		})

		It("returns nil when no match", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
			}
			f := func(cmp *expr.Cmp) (expr.CmpOp, bool) {
				return cmp.Op, true
			}
			exprs, op := OfTypeTransformed(origexprs, f)
			Expect(exprs).To(BeNil())
			Expect(op).To(BeZero())
		})

	})

	Context("pair of specific expressions with func constraint", func() {

		It("handles precursor-only expression correctly", func() {
			origexprs := Expressions{
				&expr.Cmp{},
				&expr.Bitwise{},
			}
			exprs, e := PrefixedOfTypeFunc(origexprs,
				func(b *expr.Bitwise) bool { return true },
				func(c *expr.Cmp) bool { return true })
			Expect(exprs).To(BeNil())
			Expect(e).To(BeNil())
		})

		It("handles precursor-only expression correctly", func() {
			origexprs := Expressions{
				&expr.Payload{OperationType: expr.PayloadLoad, Base: expr.PayloadBaseTransportHeader},
				&expr.Cmp{Op: expr.CmpOpLt},
				&expr.Payload{OperationType: expr.PayloadLoad, Base: expr.PayloadBaseTransportHeader},
				&expr.Cmp{Op: expr.CmpOpEq},
			}
			exprs, e := PrefixedOfTypeFunc(origexprs,
				func(p *expr.Payload) bool { return p.Base == expr.PayloadBaseTransportHeader },
				func(c *expr.Cmp) bool { return c.Op == expr.CmpOpEq })
			Expect(exprs).NotTo(BeNil())
			Expect(exprs).To(BeEmpty())
			Expect(e).To(BeIdenticalTo(origexprs[3]))
		})

	})

})
