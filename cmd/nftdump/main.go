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
nftdump dumps netfilter tables with their chains, rules, and down to the level
of expressions. The netfilter dump can be reduced to specific table families and
table names only.
*/
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/nftables"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"github.com/thediveo/nufftables"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var (
	exprForm = spew.ConfigState{
		Indent:            "  ",
		SortKeys:          true,
		DisableCapacities: true,
	}
)

// TableFamilies maps netfilter table families (or more precise: the IP protocol
// families) to their textual representations.
var TableFamilies = map[nufftables.TableFamily][]string{
	nufftables.TableFamilyUnspecified: {"all"},
	nufftables.TableFamilyARP:         {"arp"},
	nufftables.TableFamilyBridge:      {"bridge"},
	nufftables.TableFamilyINet:        {"inet"},
	nufftables.TableFamilyIPv4:        {"IPv4", "v4"},
	nufftables.TableFamilyIPv6:        {"IPv6", "v6"},
	nufftables.TableFamilyNetdev:      {"netdev"},
}

// dumpTableFamilies receives the table families to scan for "nat" table port
// forwarding expressions.
var dumpTableFamilies = []nufftables.TableFamily{
	nufftables.TableFamilyIPv4, nufftables.TableFamilyIPv6,
}

// indentLines returns the the specified multi-line string with every of its
// line indented by indent spaces.
func indentLines(s string, indent uint) string {
	lines := strings.Split(s, "\n")
	var buff strings.Builder
	indentation := strings.Repeat(" ", int(indent))
	for lno, line := range lines {
		if lno > 0 {
			buff.WriteRune('\n')
		}
		buff.WriteString(indentation)
		buff.WriteString(line)
	}
	return buff.String()
}

func dumpTables(cmd *cobra.Command, _ []string) error {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return fmt.Errorf("cannot contact netfilter, reason: %w", err)
	}
	defer func() { _ = conn.CloseLasting() }()

	tables := nufftables.TableMap{}
	if slices.Contains(dumpTableFamilies, nufftables.TableFamilyUnspecified) {
		tables, err = nufftables.GetAllTables(conn)
		if err != nil {
			return fmt.Errorf("cannot query netfilter tables, reason: %w", err)
		}
	} else {
		for _, fam := range dumpTableFamilies {
			famTables, err := nufftables.GetFamilyTables(conn, fam)
			if err != nil {
				return fmt.Errorf("cannot query netfilter tables, reason: %w", err)
			}
			maps.Copy(tables, famTables)
		}
	}

	includes := func(string) bool { return true }
	if tablenames, _ := cmd.PersistentFlags().GetStringSlice("table"); len(tablenames) != 0 {
		includes = func(tablename string) bool { return slices.Contains(tablenames, tablename) }
	}
	for _, table := range tables {
		if !includes(table.Name) {
			continue
		}
		fmt.Printf("TABLE %q FAMILY %s\n",
			table.Name, nufftables.TableFamily(table.Family))
		for _, chain := range table.ChainsByName {
			s := fmt.Sprintf("  CHAIN %q TYPE %q",
				chain.Name, chain.Type)
			if chain.Hooknum != nil {
				s += fmt.Sprintf(" HOOK %q",
					nufftables.ChainHook(*chain.Hooknum).Name(nufftables.TableFamily(table.Family)))
			}
			fmt.Println(s)
			for _, rule := range chain.Rules {
				fmt.Printf("    RULE HANDLE %d POS %d \n", rule.Handle, rule.Position)
				for _, expr := range rule.Exprs {
					fmt.Println(indentLines(strings.TrimRight(fmt.Sprintf("EXPR %s", exprForm.Sdump(expr)), "\n"), 6))
				}
			}
		}
	}
	return nil
}

func newRootCmd() (rootCmd *cobra.Command) {
	rootCmd = &cobra.Command{
		Use:     "nftdump",
		Short:   "nftdump dumps netfilter tables",
		Version: "omicron",
		Args:    cobra.NoArgs,
		RunE:    dumpTables,
	}
	// Sets up the flags.
	rootCmd.PersistentFlags().VarP(
		enumflag.NewSlice(&dumpTableFamilies, "TableFamily",
			TableFamilies, enumflag.EnumCaseInsensitive),
		"family", "f", "table family, 'all' or any combination of 'arp', 'bridge', 'inet', 'v4', 'v6' and 'netdev'")
	rootCmd.PersistentFlags().Lookup("family").DefValue = "v4,v6"
	rootCmd.PersistentFlags().StringSliceP("table", "t", []string{},
		"list of table names to restrict dump to")
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
