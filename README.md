# SafeClone

SafeClone is a CLI security tool that scans GitHub repositories for threats — hardcoded secrets, vulnerable dependencies, and dangerous install scripts — before you clone them locally. Instead of blindly running `git clone`, SafeClone spins up a sandboxed scan on a remote server, shows you a full security report, and only clones if you choose to proceed.

## Install

```bash
curl -sSL https://safeclone.dev/install.sh | sh
```

## Usage

```bash
# Scan and clone
safeclone https://github.com/some/repo

# Clone into a specific directory
safeclone https://github.com/some/repo --dir myproject

# Skip confirmation prompt
safeclone https://github.com/some/repo --force
```

## How the scanners work

**Secrets scanner** — runs [TruffleHog](https://github.com/trufflesecurity/trufflehog) against the cloned repository filesystem to detect hardcoded API keys, tokens, and credentials.

**Dependencies scanner** — reads `package.json` (npm) and `requirements.txt` (PyPI), then queries the [OSV.dev](https://osv.dev) batch API for known CVEs against each package.

**Scripts scanner** — inspects install-time hook fields (`preinstall`, `install`, `postinstall` in `package.json`, plus `setup.py`, `setup.cfg`, `install.sh`, `Makefile`) for dangerous patterns such as remote downloads, dynamic code execution, and obfuscated content.

## Self-hosting

```bash
# Requirements: Go 1.22+, Redis, Docker

# Clone this repo and build
git clone https://github.com/user/safeclone
cd safeclone
make build-server

# Build the scanner Docker image
make docker

# Copy .env.example and set your values
cp .env.example .env

# Run server (requires Redis on REDIS_ADDR)
./dist/safeclone-server-linux-amd64
```

Point the CLI at your instance:

```bash
export SAFECLONE_API=http://your-server:3001
safeclone https://github.com/some/repo
```
