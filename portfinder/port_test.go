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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("chain hooks", func() {

	DescribeTable("renders IP textual representations suitable to be used with port numbers",
		func(ip net.IP, expected string) {
			var f ForwardedPortRange
			Expect(f.ipString(ip)).To(Equal(expected))
		},
		Entry(nil, net.ParseIP("1.2.3.4"), "1.2.3.4"),
		Entry(nil, net.ParseIP("fe80::1"), "[fe80::1]"),
	)

	It("stringifies a forwarded port range", func() {
		fwpr := ForwardedPortRange{
			Protocol:       "xdp",
			IP:             net.ParseIP("1.2.3.4"),
			PortMin:        42,
			PortMax:        666,
			ForwardIP:      net.ParseIP("8.8.8.8"),
			ForwardPortMin: 777,
		}
		Expect(fwpr.String()).To(Equal("forwarding xdp from 1.2.3.4:42-666 to 8.8.8.8:777"))
	})

	It("stringifies a single forwarded port", func() {
		fwpr := ForwardedPortRange{
			Protocol:       "xdp",
			IP:             net.ParseIP("1.2.3.4"),
			PortMin:        42,
			PortMax:        42,
			ForwardIP:      net.ParseIP("8.8.8.8"),
			ForwardPortMin: 777,
		}
		Expect(fwpr.String()).To(Equal("forwarding xdp from 1.2.3.4:42 to 8.8.8.8:777"))
	})

})
