# SafeClone

SafeClone is a CLI security tool that scans GitHub repositories for threats — hardcoded secrets, vulnerable dependencies, and dangerous install scripts — before you clone them locally. Instead of blindly running `git clone`, SafeClone spins up a sandboxed scan on a remote server, shows you a full security report, and only clones if you choose to proceed.

## Install

**macOS / Linux (Homebrew)**
```bash
brew install altship-hq/safeclone/safeclone
```

**Windows (Scoop)**
```bash
scoop bucket add altship-hq https://github.com/altship-hq/scoop-safeclone
scoop install safeclone
```

**Direct download**

Download the latest binary for your platform from [GitHub Releases](https://github.com/altship-hq/safeclone/releases).

## Usage

```bash
# Scan and clone
safeclone https://github.com/some/repo

# Clone into a specific directory
safeclone https://github.com/some/repo --dir myproject

# Skip confirmation prompt
safeclone https://github.com/some/repo --force
```

## What we scan for

**Secrets** — runs [TruffleHog](https://github.com/trufflesecurity/trufflehog) against the cloned repository filesystem to detect hardcoded API keys, tokens, and credentials. Only verified, active secrets are reported.

**Vulnerable dependencies** — checks packages against the [OSV.dev](https://osv.dev) database with exact version pinning. Covers 10 ecosystems:

| Ecosystem | File |
|---|---|
| npm | `package.json` |
| PyPI | `requirements.txt` |
| Go | `go.mod` |
| Cargo | `Cargo.toml` |
| Maven | `pom.xml` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.json` |
| NuGet | `packages.config` / `*.csproj` |
| Pub | `pubspec.yaml` |
| Hex | `mix.exs` |

**Dangerous scripts** — inspects install-time hooks (`preinstall`, `postinstall` in `package.json`, `setup.py`) for patterns like remote downloads, `eval`, `base64`, and environment variable exfiltration.

## Self-hosting

```bash
# Requirements: Go 1.22+, Redis, Docker

# Clone and build
git clone https://github.com/altship-hq/safeclone
cd safeclone
make build-server

# Build the scanner Docker image
make docker

# Configure environment
cp .env.example .env

# Run (requires Redis on REDIS_ADDR)
./dist/safeclone-server-linux-amd64
```

Point the CLI at your instance:

```bash
export SAFECLONE_API=http://your-server:3001
safeclone https://github.com/some/repo
```
