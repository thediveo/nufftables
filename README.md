# 'nuff tables!

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/thediveo/nufftables)
[![GitHub](https://img.shields.io/github/license/thediveo/nufftables)](https://img.shields.io/github/license/thediveo/nufftables)
![build and test](https://github.com/thediveo/nufftables/workflows/build%20and%20test/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/thediveo/nufftables)](https://goreportcard.com/report/github.com/thediveo/nufftables)
![Coverage](https://img.shields.io/badge/Coverage-88.8%25-brightgreen)

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

## Note

`nufftables` supports versions of Go that are noted by the Go release policy,
that is, major versions _N_ and _N_-1 (where _N_ is the current major version).

## VSCode Tasks

The included `nufftables.code-workspace` defines the following tasks:

- **View Go module documentation** task: installs `pkgsite`, if not done already
  so, then starts `pkgsite` and opens VSCode's integrated ("simple") browser to
  show the go-plugger/v2 documentation.

#### Aux Tasks

- _pksite service_: auxilliary task to run `pkgsite` as a background service
  using `scripts/pkgsite.sh`. The script leverages browser-sync and nodemon to
  hot reload the Go module documentation on changes; many thanks to @mdaverde's
  [_Build your Golang package docs
  locally_](https://mdaverde.com/posts/golang-local-docs) for paving the way.
  `scripts/pkgsite.sh` adds automatic installation of `pkgsite`, as well as the
  `browser-sync` and `nodemon` npm packages for the local user.
- _view pkgsite_: auxilliary task to open the VSCode-integrated "simple" browser
  and pass it the local URL to open in order to show the module documentation
  rendered by `pkgsite`. This requires a detour via a task input with ID
  "_pkgsite_".

## Make Targets

- `make`: lists all targets.
- `make coverage`: runs all tests with coverage and then **updates the coverage
  badge in `README.md`**.
- `make pkgsite`: installs [`x/pkgsite`](golang.org/x/pkgsite/cmd/pkgsite), as
  well as the [`browser-sync`](https://www.npmjs.com/package/browser-sync) and
  [`nodemon`](https://www.npmjs.com/package/nodemon) npm packages first, if not
  already done so. Then runs the `pkgsite` and hot reloads it whenever the
  documentation changes.
- `make report`: installs
  [`@gojp/goreportcard`](https://github.com/gojp/goreportcard) if not yet done
  so and then runs it on the code base.
- `make test`: runs **all** tests, once as root and then as the invoking user.

## Copyright and License

Copyright 2022-23 Harald Albrecht, licensed under the Apache License, Version
2.0.
