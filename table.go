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
	"golang.org/x/exp/slices"
)

// Table is a [nftables.Table] together with all its named [Chain] objects.
type Table struct {
	*nftables.Table
	ChainsByName map[string]*Chain
}

// TableMap indexes table names (that are always "namespaced" in a particular
// address family) to their corresponding [Table] objects. The Table objects
// then contain their [Chain] objects, and the chain objects in turn Rule
// objects. It's turtles all the way down.
type TableMap map[TableKey]*Table

// TableKey represents an index key into a [TableMap]. Every [Table] is always
// namespaced to a [nftables.TableFamily], such as [nftables.TableFamilyINet]
// (both IPv4 and IPv6), [nftables.TableFamilyIPv4], [nftables.TableFamilyIPv6],
// et cetera.
type TableKey struct {
	Name   string
	Family TableFamily
}

// Table returns the named table of the specified family if available, otherwise
// nil.
func (t TableMap) Table(name string, family TableFamily) *Table {
	return t[TableKey{Name: name, Family: family}]
}

// TableChain returns the specified named chain in the specified table and
// family, otherwise nil.
func (t TableMap) TableChain(tablename string, family TableFamily, chainname string) *Chain {
	table := t.Table(tablename, family)
	if table == nil {
		return nil
	}
	return table.ChainsByName[chainname]
}

// GetAllTables returns the available netfilter tables as a [TableMap] using the
// specified conn for retrieval. The [Table] objects in the returned TableMap
// are populated with their named [Chain] objects, and these in turn contain
// their [Rule] objects including expressions.
func GetAllTables(conn *nftables.Conn) (TableMap, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	// Build a map of netfilter tables, where we index the individual tables by
	// their names together with their respective netfilter family.
	tm := TableMap{}
	for _, table := range tables {
		tm[TableKey{Name: table.Name, Family: TableFamily(table.Family)}] = &Table{
			Table:        table,
			ChainsByName: map[string]*Chain{},
		}
	}
	// Please note that nftables only supports listing *all* chains; the
	// particular table object a certain chain belongs to is only partially
	// filled in, with only the table name and address being valid.
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	for _, chain := range chains {
		_ = tm.addChain(conn, chain) // ignore chains that have gone missing.
	}
	return tm, nil
}

// GetFamilyTables returns the netfiler tables for the specified netfilter
// family only, together with all their chains and rules.
func GetFamilyTables(conn *nftables.Conn, family TableFamily) (TableMap, error) {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamily(family))
	if err != nil {
		return nil, err
	}
	tm := TableMap{}
	for _, chain := range chains {
		_ = tm.addChain(conn, chain) // ignore chains that have gone missing.
	}
	return tm, nil
}

// addChain adds the given [nftables.Chain] to this TableMap and then fetches
// all rules belonging to this chain. The [Rule] objects are sorted by their
// position.
func (t TableMap) addChain(conn *nftables.Conn, chain *nftables.Chain) error {
	key := TableKey{Name: chain.Table.Name, Family: TableFamily(chain.Table.Family)}
	table, ok := t[key]
	if !ok {
		table = &Table{
			Table:        chain.Table,
			ChainsByName: map[string]*Chain{},
		}
		t[key] = table
	}
	c := &Chain{
		Chain: chain,
		Table: table,
	}
	table.ChainsByName[chain.Name] = c
	rules, err := conn.GetRules(chain.Table, chain)
	if err != nil {
		return err // things might have changed since the discovery...
	}
	for _, rule := range rules {
		c.Rules = append(c.Rules, Rule{
			Rule:  rule,
			Chain: c, // the chain this rule belongs to.
		})
	}
	slices.SortFunc(c.Rules, orderRulesByPosition)
	return nil
}

// orderRulesByPosition compares two [Rule] objects a and b and returns true if
// Rule a is in an earlier position than Rule b, where Position is an explicit
// attribute of rules.
func orderRulesByPosition(a, b Rule) bool {
	return a.Position < b.Position
}
