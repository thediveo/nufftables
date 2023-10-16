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
	"os"

	"github.com/google/nftables"
	"golang.org/x/exp/maps"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("'nuff tables", func() {

	var conn *nftables.Conn

	BeforeEach(func() {
		if os.Getuid() != 0 {
			Skip("needs root")
		}
		var err error
		conn, err = nftables.New(nftables.AsLasting())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			conn.CloseLasting()
		})
	})

	It("gets all tables", func() {
		tables, err := GetAllTables(conn)
		Expect(err).NotTo(HaveOccurred())
		Expect(tables).NotTo(BeEmpty())
		for _, fam := range []TableFamily{TableFamilyIPv4} {
			for _, tablename := range []string{"filter", "nat"} {
				Expect(tables.Table(tablename, fam)).NotTo(
					BeNil(), "missing table %q of %q", tablename, fam)
			}
		}
		Expect(tables.TableChain("nat", TableFamilyIPv4, "POSTROUTING")).NotTo(BeNil())
		Expect(tables.TableChain("nat", TableFamilyIPv4, "XXX")).To(BeNil())
		Expect(tables.TableChain("xxx", TableFamilyIPv4, "XXX")).To(BeNil())
	})

	It("get the tables of a specific family", func() {
		tables, err := GetFamilyTables(conn, TableFamilyIPv4)
		Expect(err).NotTo(HaveOccurred())
		Expect(maps.Keys(tables)).To(
			HaveEach(HaveField("Family", TableFamilyIPv4)))
		Expect(tables.Table("nat", TableFamilyIPv6)).To(BeNil())
	})

})
