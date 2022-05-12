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
	"github.com/thediveo/nufftables"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("expression comparing with an IP address", func() {

	Context("filter", func() {

		DescribeTable("rejects unwanted compare expressions",
			func(cmp *expr.Cmp) {
				Expect(isCompareIPExpression(cmp)).To(BeFalse())
			},
			Entry(nil, &expr.Cmp{
				Op: expr.CmpOpGt,
			}),
			Entry(nil, &expr.Cmp{
				Op:   expr.CmpOpEq,
				Data: nil,
			}),
			Entry(nil, &expr.Cmp{
				Op:   expr.CmpOpEq,
				Data: []byte{42},
			}),
		)

		DescribeTable("accepts comparing with IPv4 and IPv6 address",
			func(addr string) {
				Expect(isCompareIPExpression(&expr.Cmp{
					Op:   expr.CmpOpEq,
					Data: ip(addr),
				})).To(BeTrue())
			},
			Entry(nil, "1.2.3.4"),
			Entry(nil, "::1"),
		)

	})

	It("returns address compare information together with the remaining expressions", func() {
		origexprs := nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Cmp{
				Op:   expr.CmpOpEq,
				Data: ip("1.2.3.4"),
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, cmpip := OptionalCompareIP(origexprs)
		Expect(cmpip).To(Equal(ip("1.2.3.4")))
		Expect(exprs).To(HaveLen(1)) // one remaining
	})

	It("returns the original expressions when no address compare can be found", func() {
		origexprs := nufftables.Expressions{
			&expr.Range{},   // arbitrary
			&expr.Cmp{},     // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, cmp := OptionalCompareIP(origexprs)
		Expect(exprs).To(HaveLen(len(origexprs)))
		Expect(cmp).To(BeNil())
	})

})
