# Courier

[![Go](https://github.com/ncode/courier/actions/workflows/go.yml/badge.svg)](https://github.com/ncode/courier/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ncode/courier)](https://goreportcard.com/report/github.com/ncode/courier)
[![codecov](https://codecov.io/gh/ncode/courier/graph/badge.svg?token=AW3IMI6P6W)](https://codecov.io/gh/ncode/courier)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Courier is a utility designed to synchronize key-value (KV) pairs, policies, and general settings across multiple HashiCorp Vault clusters. Inspired by [jonasvinther/medusa](https://github.com/jonasvinther/medusa) and [pbchekin/vault-sync](https://github.com/pbchekin/vault-sync), Courier aims to provide a robust and easy-to-use solution for managing Vault configurations across various environments.

## Installation

You can install Courier by building it from source:

```bash
git clone https://github.com/ncode/courier.git
cd courier
go build -o courier
````


