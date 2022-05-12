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

/*
portfinder lists forwarded ports found in "nat" netfilter tables for the IPv4
and IPv6 families. Forwarded ports are detected only in form of rules with port
range and target DNAT expressions, as well as an optional IP address compare
expression.
*/
package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"github.com/thediveo/nufftables"
	"github.com/thediveo/nufftables/portfinder"
	"golang.org/x/exp/slices"
)

// TableFamilies maps netfilter table families (or more precise: the IP protocol
// families) to their textual representations.
var TableFamilies = map[nufftables.TableFamily][]string{
	nufftables.TableFamilyIPv4: {"IPv4", "v4"},
	nufftables.TableFamilyIPv6: {"IPv6", "v6"},
}

// dumpTableFamilies receives the table families to scan for "nat" table port
// forwarding expressions.
var dumpTableFamilies = []nufftables.TableFamily{
	nufftables.TableFamilyIPv4, nufftables.TableFamilyIPv6,
}

func dumpForwardedPorts(cmd *cobra.Command, _ []string) error {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return fmt.Errorf("cannot contact netfilter, reason: %w", err)
	}
	defer func() { _ = conn.CloseLasting() }()

	fps := []*portfinder.ForwardedPortRange{}
	for _, fam := range dumpTableFamilies {
		iptables, err := nufftables.GetFamilyTables(conn, fam)
		if err != nil {
			panic(err)
		}
		table := iptables.Table("nat", fam)
		if table == nil {
			continue
		}
		for _, chain := range table.ChainsByName {
			for _, rule := range chain.Rules {
				fp := portfinder.ForwardedPort(rule)
				if fp == nil {
					continue
				}
				fps = append(fps, fp)
			}
		}
	}

	slices.SortFunc(fps, portfinder.ForwardedPortLess)

	for _, fp := range fps {
		fmt.Printf("%s\n", fp.String())
	}
	return nil
}

func newRootCmd() (rootCmd *cobra.Command) {
	rootCmd = &cobra.Command{
		Use:     "forwardedports",
		Short:   "forwardedports lists forwarded ports from the \"nat\" netfilter tables",
		Version: "omicron",
		Args:    cobra.NoArgs,
		RunE:    dumpForwardedPorts,
	}
	// Sets up the flags.
	rootCmd.PersistentFlags().VarP(
		enumflag.NewSlice(&dumpTableFamilies, "TableFamily",
			TableFamilies, enumflag.EnumCaseInsensitive),
		"family", "f", "table family, any combination of 'v4' and 'v6'")
	rootCmd.PersistentFlags().Lookup("family").DefValue = "v4,v6"
	return
}

func main() {
	// This is cobra boilerplate documentation, except for the missing call to
	// fmt.Println(err) which in the original boilerplate is just plain wrong:
	// it renders the error message twice, see also:
	// https://github.com/spf13/cobra/issues/304
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
