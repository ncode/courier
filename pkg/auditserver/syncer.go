package auditserver

import (
	"fmt"
	"log/slog"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/ncode/courier/pkg/vault"
)

type DestinationConfig struct {
	Address string
	Token   string
}

type logicalClient interface {
	Read(path string) (*vaultapi.Secret, error)
	Write(path string, data map[string]interface{}) (*vaultapi.Secret, error)
	Delete(path string) (*vaultapi.Secret, error)
}

type clientWithAddress struct {
	address string
	client  logicalClient
}

// VaultSyncer applies audit-derived updates to a set of destination Vaults.
type VaultSyncer struct {
	logger       *slog.Logger
	source       logicalClient
	destinations []clientWithAddress
}

func NewVaultSyncer(logger *slog.Logger, source *vault.VaultClient, destinations []DestinationConfig) (*VaultSyncer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if source == nil {
		return nil, fmt.Errorf("source vault client is required")
	}
	destClients := make([]clientWithAddress, 0, len(destinations))
	for _, dest := range destinations {
		client, err := vault.NewVaultClient(dest.Address, vault.TokenAuth{Token: dest.Token})
		if err != nil {
			return nil, fmt.Errorf("failed to create destination client for %s: %w", dest.Address, err)
		}
		destClients = append(destClients, clientWithAddress{address: dest.Address, client: client.Logical()})
	}

	return &VaultSyncer{
		logger:       logger,
		source:       source.Logical(),
		destinations: destClients,
	}, nil
}

func (s *VaultSyncer) Handle(event UpdateEvent) error {
	switch event.Operation {
	case "delete":
		return s.delete(event)
	default:
		return s.write(event)
	}
}

func (s *VaultSyncer) write(event UpdateEvent) error {
	secret, err := s.source.Read(event.Path)
	if err != nil {
		return fmt.Errorf("failed to read source secret: %w", err)
	}
	if secret == nil {
		return fmt.Errorf("source secret not found at %s", event.Path)
	}

	payload, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		// Fallback for non-KV-v2 or unexpected shape
		if data, ok := secret.Data["data"]; ok {
			if m, ok := data.(map[string]interface{}); ok {
				payload = m
			}
		}
		if payload == nil {
			payload = make(map[string]interface{})
			for k, v := range secret.Data {
				if k != "metadata" {
					payload[k] = v
				}
			}
		}
	}

	body := map[string]interface{}{"data": payload}
	var firstErr error
	for _, dest := range s.destinations {
		if _, err := dest.client.Write(event.Path, body); err != nil {
			s.logger.Error("Failed to write to destination", "destination", dest.address, "path", event.Path, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (s *VaultSyncer) delete(event UpdateEvent) error {
	var firstErr error
	for _, dest := range s.destinations {
		if _, err := dest.client.Delete(event.Path); err != nil {
			s.logger.Error("Failed to delete from destination", "destination", dest.address, "path", event.Path, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
