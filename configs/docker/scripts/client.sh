#!/bin/sh

sleep 5

set -x

vault kv put secret/myapp/config api_key=12345 environment=production
vault kv put secret/myapp/database '{ "username": "dbuser", "password": "supersecret", "host": "db.example.com", "port": 5432 }'
vault kv get secret/myapp/config
vault kv get -field=api_key secret/myapp/config
vault kv get -format=json secret/myapp/database

vault policy list
vault policy read app-policy
vault policy read -format=json dev-policy

vault token create -policy=app-policy
vault token create -policy=app-policy -policy=dev-policy

vault kv list secret/myapp/
vault kv delete secret/myapp/config


