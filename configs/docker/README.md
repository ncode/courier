# Local dev sandbox (3 Vault dev nodes + Courier)

## Prerequisites
- Docker and Docker Compose v2
- Built Courier image tag `courier:dev` (compose will build from repo root via `configs/docker/Dockerfile`, expecting a `courier` binary in `configs/docker/` after `go build -o configs/docker/courier .`)

## Run the stack
```bash
go build -o configs/docker/courier .
docker compose -f configs/docker/docker-compose.dev.yml up --build
```

Services:
- `vault-source` (http://127.0.0.1:8200, token `root`)
- `vault-dest-1` (http://127.0.0.1:8201, token `root`)
- `vault-dest-2` (http://127.0.0.1:8202, token `root`)
- `courier-audit` (listens on UDP 1269)
- `courier-setup` (runs once to configure the audit device on `vault-source`)

## Verify propagation
1) Write a KV secret on the source:
```bash
docker exec -e VAULT_ADDR=http://vault-source:8200 -e VAULT_TOKEN=root vault-source \
  vault kv put secret/data/demo foo=bar
```
2) Read from each destination:
```bash
docker exec -e VAULT_ADDR=http://vault-dest-1:8200 -e VAULT_TOKEN=root vault-dest-1 \
  vault kv get -format=json secret/data/demo

docker exec -e VAULT_ADDR=http://vault-dest-2:8200 -e VAULT_TOKEN=root vault-dest-2 \
  vault kv get -format=json secret/data/demo
```

Courier should consume audit events from `vault-source` and fan-out the change to both destinations without manual copying.
