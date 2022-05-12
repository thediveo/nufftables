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

	Context("type match only", func() {

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
			Expect(cmp.Op).To(Equal(expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))

			exprs, cmp = OptionalOfType[*expr.Cmp](origexprs)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp.Op).To(Equal(expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))
		})

		It("returns no expressions when no match is found", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Counter{},
			}
			exprs, cmp := OfType[*expr.Cmp](origexprs)
			Expect(exprs).To(BeNil())
			Expect(cmp).To(BeNil())
		})

		It("returns all expressions for optional (non-) match", func() {
			origexprs := Expressions{
				&expr.Bitwise{},
				&expr.Counter{},
			}
			exprs, cmp := OptionalOfType[*expr.Cmp](origexprs)
			Expect(exprs).To(Equal(origexprs))
			Expect(cmp).To(BeNil())
		})

	})

	Context("type match with additional func constraint", func() {

		It("matches a specific expression type and constraint, and then returns it, together with the remaining expressions", func() {
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
			exprs, cmp := OfTypeFunc(origexprs, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp.Op).To(Equal(expr.CmpOpGt))
			Expect(exprs).To(HaveLen(1))

			exprs, cmp = OptionalOfTypeFunc(origexprs, f)
			Expect(cmp).NotTo(BeNil())
			Expect(cmp.Op).To(Equal(expr.CmpOpGt))
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

})
