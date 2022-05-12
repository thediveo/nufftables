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

package portfinder

import (
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/thediveo/nufftables"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func ip(s string) net.IP {
	i := net.ParseIP(s)
	Expect(i).NotTo(BeNil())
	if v4 := i.To4(); v4 != nil {
		return v4
	}
	return i
}

var _ = Describe("forwarded ports", func() {

	Context("sorting", func() {

		DescribeTable("IPv4 before IPv6",
			func(a, b string, less bool) {

				Expect(ForwardedPortLess(
					&ForwardedPortRange{IP: ip(a)},
					&ForwardedPortRange{IP: ip(b)},
				)).To(Equal(less))
			},
			Entry(nil, "10.0.0.0", "fe80::1", true),
			Entry(nil, "::1", "0.0.0.1", false),
		)

		DescribeTable("by original destination address",
			func(a, b string, less bool) {

				Expect(ForwardedPortLess(
					&ForwardedPortRange{IP: ip(a)},
					&ForwardedPortRange{IP: ip(b)},
				)).To(Equal(less))
			},
			Entry(nil, "10.0.0.0", "192.168.0.1", true),
			Entry(nil, "fe80::1", "::", false),
		)

		DescribeTable("by original port",
			func(a, b int, less bool) {

				Expect(ForwardedPortLess(
					&ForwardedPortRange{IP: ip("::1"), PortMin: uint16(a)},
					&ForwardedPortRange{IP: ip("::1"), PortMin: uint16(b)},
				)).To(Equal(less))
			},
			Entry(nil, 42, 66, true),
			Entry(nil, 420, 66, false),
		)

		DescribeTable("by new destination address",
			func(a, b string, less bool) {

				Expect(ForwardedPortLess(
					&ForwardedPortRange{IP: ip("::1"), PortMin: 42, ForwardIP: ip(a)},
					&ForwardedPortRange{IP: ip("::1"), PortMin: 42, ForwardIP: ip(b)},
				)).To(Equal(less))
			},
			Entry(nil, "::1", "fe80::1", true),
			Entry(nil, "::1", "::1", false),
			Entry(nil, "fe80::1", "::1", false),
		)

	})

	Context("expression", func() {

		m := &expr.Match{
			Name: "tcp",
			Info: &xt.Tcp{
				DstPorts: [2]uint16{123, 124},
			},
		}

		dnat4 := &expr.Target{
			Name: "DNAT",
			Info: &xt.NatRange2{
				NatRange: xt.NatRange{
					MinIP:   ip("1.2.3.4"),
					MaxIP:   ip("1.2.3.5"),
					MinPort: 666,
					MaxPort: 667,
					Flags:   dnatWithIPsAndPorts,
				},
			},
		}

		dnat6 := &expr.Target{
			Name: "DNAT",
			Info: &xt.NatRange2{
				NatRange: xt.NatRange{
					MinIP:   ip("fe80::1"),
					MaxIP:   ip("fe80::2"),
					MinPort: 666,
					MaxPort: 667,
					Flags:   dnatWithIPsAndPorts,
				},
			},
		}

		It("finds a forwarded port for the unspecified address", func() {
			r := nufftables.Rule{
				Rule: &nftables.Rule{
					Exprs: []expr.Any{m, dnat4},
				},
			}
			Expect(ForwardedPort(r)).To(HaveValue(Equal(ForwardedPortRange{
				Protocol:       m.Name,
				IP:             ip("0.0.0.0"),
				PortMin:        m.Info.(*xt.Tcp).DstPorts[0],
				PortMax:        m.Info.(*xt.Tcp).DstPorts[1],
				ForwardIP:      dnat4.Info.(*xt.NatRange2).MinIP,
				ForwardPortMin: dnat4.Info.(*xt.NatRange2).MinPort,
			})))

			r = nufftables.Rule{
				Rule: &nftables.Rule{
					Exprs: []expr.Any{m, dnat6},
				},
			}
			Expect(ForwardedPort(r)).To(HaveValue(Equal(ForwardedPortRange{
				Protocol:       m.Name,
				IP:             ip("::"),
				PortMin:        m.Info.(*xt.Tcp).DstPorts[0],
				PortMax:        m.Info.(*xt.Tcp).DstPorts[1],
				ForwardIP:      dnat6.Info.(*xt.NatRange2).MinIP,
				ForwardPortMin: dnat6.Info.(*xt.NatRange2).MinPort,
			})))
		})

		It("skips where no port is forwarded", func() {
			r := nufftables.Rule{Rule: &nftables.Rule{
				Exprs: []expr.Any{dnat4},
			}}
			Expect(ForwardedPort(r)).To(BeNil())
		})

	})

})
