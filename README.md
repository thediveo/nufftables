# 'nuff tables!

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/thediveo/nufftables)
[![GitHub](https://img.shields.io/github/license/thediveo/nufftables)](https://img.shields.io/github/license/thediveo/nufftables)
![build and test](https://github.com/thediveo/nufftables/actions/workflows/buildandtest.yaml/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/thediveo/nufftables)](https://goreportcard.com/report/github.com/thediveo/nufftables)
![Coverage](https://img.shields.io/badge/Coverage-92.9%25-brightgreen)

The `nufftables` go module is a thin wrapper around Google's
[`nftables`](https://github.com/google/nftables) to ease reasoning over the
current state of tables, chains, rules, and expressions. If you just want to
setup and remove netfilter chains and rules, then `@google/nftables` should
already be sufficient most of the time.

## CLI Tool Examples

- `cmd/nftdump` is a simple CLI tool that fetches all netfilter tables (in the
  host network namespace) and then dumps the corresponding objects to stdout.

- `cmd/portfinder` is another simple CLI tool that fetches the IPv4 and IPv6
  netfilter tables and scans them for certain port forwarding expressions,
  dumping the forwarded port information found to stdout. Only port forwarding
  expressions using port range and target DNAT expressions (with an optional IP
  address compare) will be detected.

## Example Usage

A simplified example, without proper error handling, that reasons about
netfilter port match expressions:

```go
import (
    "github.com/google/nftables"
    "github.com/google/nftables/expr"
    "github.com/thediveo/nufftables"
)

func main() {
    conn, _ := nftables.New(nftables.AsLasting())
    defer conn.CloseLasting()

    tables := nufftables.GetFamilyTables(conn, nufftables.TableFamilyIPv4)
    for _, chain := range tables.Table("nat", nufftables.TableFamilyIPv4) {
        for _, rule := range chain.Rules {
            if _, match := nufftables.OfType[*expr.Match](rule.Expressions()); match != nil {
                fmt.Printf("port match expression: %#v\n", match)
            }
        }
    }
}
```

## DevContainer

> [!CAUTION]
>
> Do **not** use VSCode's "~~Dev Containers: Clone Repository in Container
> Volume~~" command, as it is utterly broken by design, ignoring
> `.devcontainer/devcontainer.json`.

1. `git clone https://github.com/thediveo/nufftables`
2. in VSCode: Ctrl+Shift+P, "Dev Containers: Open Workspace in Container..."
3. select `nufftables.code-workspace` and off you go...

## Supported Go Versions

`nufftables` supports versions of Go that are noted by the [Go release
policy](https://golang.org/doc/devel/release.html#policy), that is, major
versions _N_ and _N_-1 (where _N_ is the current major version).

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Copyright and License

Copyright 2022-26 Harald Albrecht, licensed under the Apache License, Version
2.0.
