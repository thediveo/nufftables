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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("expression matching a port range", func() {

	It("accepts a tcp or udp match with a port range", func() {
		origexprs := nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Match{
				Name: "tcp",
				Info: &xt.Tcp{
					DstPorts: [2]uint16{42, 666},
					InvFlags: 0,
				},
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, protocol, minport, maxport := MatchPortRange(origexprs)
		Expect(exprs).To(HaveLen(1))
		Expect(protocol).To(Equal("tcp"))
		Expect(minport).To((Equal(uint16(42))))
		Expect(maxport).To((Equal(uint16(666))))

		origexprs = nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Match{
				Name: "udp",
				Info: &xt.Udp{
					DstPorts: [2]uint16{42, 666},
					InvFlags: 0,
				},
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, protocol, minport, maxport = MatchPortRange(origexprs)
		Expect(exprs).To(HaveLen(1))
		Expect(protocol).To(Equal("udp"))
		Expect(minport).To((Equal(uint16(42))))
		Expect(maxport).To((Equal(uint16(666))))
	})

	It("rejects a match with inverted port range", func() {
		origexprs := nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Match{
				Info: &xt.Tcp{
					DstPorts: [2]uint16{42, 666},
					InvFlags: xt.TcpInvDestPorts,
				},
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, protocol, minport, maxport := MatchPortRange(origexprs)
		Expect(exprs).To(BeNil())
		Expect(protocol).To(BeEmpty())
		Expect(minport).To((BeZero()))
		Expect(maxport).To((BeZero()))

		origexprs = nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Match{
				Info: &xt.Udp{
					DstPorts: [2]uint16{42, 666},
					InvFlags: xt.UdpInvDestPorts,
				},
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, protocol, minport, maxport = MatchPortRange(origexprs)
		Expect(exprs).To(BeNil())
	})

	It("rejects a match expression with unwanted information", func() {
		origexprs := nufftables.Expressions{
			&expr.Range{}, // arbitrary
			&expr.Match{
				Info: &xt.NatRange{},
			}, // doesn't match
			&expr.Bitwise{}, // arbitrary
		}
		exprs, protocol, minport, maxport := MatchPortRange(origexprs)
		Expect(exprs).To(BeNil())
		Expect(protocol).To(BeEmpty())
		Expect(minport).To((BeZero()))
		Expect(maxport).To((BeZero()))
	})

})
