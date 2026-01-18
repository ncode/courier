# Courier

[![Go](https://github.com/ncode/courier/actions/workflows/go.yml/badge.svg)](https://github.com/ncode/courier/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ncode/courier)](https://goreportcard.com/report/github.com/ncode/courier)
[![codecov](https://codecov.io/gh/ncode/courier/graph/badge.svg?token=AW3IMI6P6W)](https://codecov.io/gh/ncode/courier)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Courier synchronizes HashiCorp Vault data (KV and policies) from a primary Vault to one or more destinations. It listens to Vault audit logs, deduplicates updates per path, and applies them to downstream Vaults through an in-process worker queue.

## How it works
- **Audit server (UDP):** receives Vault audit events (socket audit device).
- **Dispatcher:** deduplicates updates per path/type and feeds a worker queue.
- **Sync handler:** reads the updated secret from the source Vault and writes/deletes it on every configured destination.

## Quick start (local)
```bash
git clone https://github.com/ncode/courier.git
cd courier
go build -o courier .
./courier --help
```

### Run the dev sandbox (3 Vault dev nodes)
This spins up a source Vault plus two destinations and a Courier instance wired for fan-out.
```bash
GOOS=linux GOARCH=amd64 go build -o configs/docker/courier .
docker compose -f configs/docker/docker-compose.dev.yml up -d --build
```
Services:
- Source Vault: http://127.0.0.1:8200 (token `root`)
- Dest 1: http://127.0.0.1:8201 (token `root`)
- Dest 2: http://127.0.0.1:8202 (token `root`)
- Courier audit server listens on UDP 1269
- Audit device on source is auto-configured via `courier setup`

Verify propagation:
```bash
# write on source
docker exec -e VAULT_ADDR=http://vault-source:8200 -e VAULT_TOKEN=root vault-source \
  vault kv put secret/data/demo foo=bar

# read on destinations
docker exec -e VAULT_ADDR=http://vault-dest-1:8200 -e VAULT_TOKEN=root vault-dest-1 \
  vault kv get -format=json secret/data/demo
docker exec -e VAULT_ADDR=http://vault-dest-2:8200 -e VAULT_TOKEN=root vault-dest-2 \
  vault kv get -format=json secret/data/demo
```
Tear down:
```bash
docker compose -f configs/docker/docker-compose.dev.yml down
```

## Configuration (CLI flags/env)
- `--vault.source.address` / `--vault.source.token`: source Vault to read from.
- `--vault.audit_address`: UDP address Courier listens on (configure Vault audit device to send here).
- `--vault.destinations.addresses`: comma-separated destination Vault addresses.
- `--vault.destinations.tokens`: comma-separated tokens (one per destination, or a single token reused).
- Worker tuning: `--worker.concurrency`, `--worker.queue_size`.

Example (manual run):
```bash
./courier auditServer \
  --vault.source.address http://127.0.0.1:8200 \
  --vault.source.token root \
  --vault.audit_address 0.0.0.0:1269 \
  --vault.destinations.addresses http://127.0.0.1:8201,http://127.0.0.1:8202 \
  --vault.destinations.tokens root,root
```
Then enable a socket audit device on the source Vault pointing to the audit address.

## Testing
```bash
go test ./...
```

## Status / Roadmap
- **Works today:** audit-driven KV fan-out from one source to multiple destinations; per-path deduplication; in-process worker queue; dev docker-compose sandbox with three Vault dev nodes and auto-configured audit device.
- **Near-term TODOs:** retries/backoff for destination failures; fuller policy sync coverage; richer logging/metrics; TLS/auth hardening for audit traffic; better config validation and error surfacing.
- **Future ideas:** persistence/queue durability, throttling/limiting, extensible handlers for non-KV resources, packaging/distribution improvements.

## License
Apache 2.0
