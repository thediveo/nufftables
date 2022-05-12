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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("table families", func() {

	DescribeTable("names table families",
		func(tf nftables.TableFamily, expected string) {
			Expect(TableFamily(tf).String()).To(Equal(expected))
		},
		Entry(nil, nftables.TableFamilyARP, "arp"),
		Entry(nil, nftables.TableFamilyBridge, "bridge"),
		Entry(nil, nftables.TableFamilyINet, "inet"),
		Entry(nil, nftables.TableFamilyIPv4, "ip"),
		Entry(nil, nftables.TableFamilyIPv6, "ipv6"),
		Entry(nil, nftables.TableFamilyNetdev, "netdev"),
		Entry(nil, nftables.TableFamilyUnspecified, "TableFamily(0)"),
	)

})
