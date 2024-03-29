<h1 align="center">
    <br>
    <img src="assets/goad_logo.png" width="200px" alt="GoAD">
    <br>
    Go Active Directory
</h1>

<h4 align="center">A learning project for Active Directory to perform many kinds of attacks.</h4>

<p align="center">
    <img src="https://img.shields.io/github/go-mod/go-version/5amu/goad">
    <img src="https://github.com/5amu/goad/actions/workflows/build-test.yml/badge.svg">
    <img src="https://github.com/5amu/goad/actions/workflows/lint-test.yml/badge.svg">
    <img src="https://github.com/5amu/goad/actions/workflows/release.yml/badge.svg">
    <a href="https://goreportcard.com/report/github.com/5amu/goad"><img src="https://goreportcard.com/badge/5amu/goad"></a>
    <a href="https://pkg.go.dev/github.com/5amu/goad"><img src="https://pkg.go.dev/badge/github.com/5amu/goad.svg"></a>
</p>

---

GoAD is a learning project of mine that aims to be used like [netexec](https://github.com/Pennyw0rth/NetExec), but entirely in Go. It is still in heavy development but can be used to perform many classic attacks on an active directory infrastructure. If you need a solution that is reliable and tested don't use it, but if you like to thinker you'll be home!

## Install

Quick way to install the tool:

```bash
go install -v "github.com/5amu/goad/cmd/goad@latest"
```

You can download a precompiled binary from the release section.

## Usage

It's still in heavy development and arguments might change in the future, so refer to the help switch:

```bash
# List subcommands
goad -h

# See options for subcommands
goad ldap -h

# To use it with a proxy (eg:socks5)
export ALL_PROXY="socks5://127.0.0.1:1080"
goad smb 10.0.0.0/24 # every command will work without any other config
```
