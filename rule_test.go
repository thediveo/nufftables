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
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("rules", func() {

	It("returns the expressions of a rule", func() {
		rule := Rule{
			Rule: &nftables.Rule{
				Exprs: []expr.Any{
					&expr.Bitwise{},
				},
			},
		}
		exprs := rule.Expressions()
		Expect(exprs).To(HaveLen(1))
	})

})
