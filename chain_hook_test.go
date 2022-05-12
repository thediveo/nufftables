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

var _ = Describe("chain hooks", func() {

	var nameless = nftables.ChainHookRef(42 * 42)

	DescribeTable("names chain hooks",
		func(ch *nftables.ChainHook, tf nftables.TableFamily, expected string) {
			Expect(ChainHook(*ch).Name(TableFamily(tf))).To(Equal(expected))
		},
		Entry("ChainHookPrerouting", nftables.ChainHookPrerouting, nftables.TableFamilyINet, "PREROUTING"),
		Entry("ChainHookInput", nftables.ChainHookInput, nftables.TableFamilyINet, "INPUT"),
		Entry("ChainHookForward", nftables.ChainHookForward, nftables.TableFamilyINet, "FORWARD"),
		Entry("ChainHookOutput", nftables.ChainHookOutput, nftables.TableFamilyINet, "OUTPUT"),
		Entry("ChainHookPostrouting", nftables.ChainHookPostrouting, nftables.TableFamilyINet, "POSTROUTING"),
		Entry("ChainHookIngress", nftables.ChainHookIngress, nftables.TableFamilyNetdev, "INGRESS"),
		Entry("name-less", nameless, nftables.TableFamilyINet, "ChainHook(1764)"),
	)

})
