package vault

import (
	"fmt"
	"log/slog"
	"os"

	vault "github.com/hashicorp/vault/api"
)

var logger *slog.Logger

func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type VaultClient struct {
	*vault.Client
}

type AuthMethod interface {
	Authenticate(*vault.Client) error
	ConfigureTLS(*vault.Config) error
}

type TokenAuth struct {
	Token string
}

type AppRoleAuth struct {
	RoleID   string
	SecretID string
}

type CertAuth struct {
	CertFile string
	KeyFile  string
}

func (t TokenAuth) Authenticate(client *vault.Client) error {
	client.SetToken(t.Token)
	return nil
}

func (t TokenAuth) ConfigureTLS(*vault.Config) error {
	return nil
}

func (a AppRoleAuth) Authenticate(client *vault.Client) error {
	data := map[string]interface{}{
		"role_id":   a.RoleID,
		"secret_id": a.SecretID,
	}
	secret, err := client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("failed to authenticate with AppRole: %w", err)
	}
	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func (a AppRoleAuth) ConfigureTLS(*vault.Config) error {
	return nil
}

func (c CertAuth) Authenticate(client *vault.Client) error {
	secret, err := client.Logical().Write("auth/cert/login", nil)
	if err != nil {
		return fmt.Errorf("failed to authenticate with certificate: %w", err)
	}
	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func (c CertAuth) ConfigureTLS(config *vault.Config) error {
	err := config.ConfigureTLS(&vault.TLSConfig{
		ClientCert: c.CertFile,
		ClientKey:  c.KeyFile,
	})
	if err != nil {
		return fmt.Errorf("failed to configure TLS: %w", err)
	}
	return nil
}

func NewVaultClient(address string, authMethod AuthMethod) (*VaultClient, error) {
	config := vault.DefaultConfig()
	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	err = authMethod.Authenticate(client)
	if err != nil {
		return nil, err
	}

	return &VaultClient{client}, nil
}

func (vc *VaultClient) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := vc.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found")
	}
	return secret.Data, nil
}

func (vc *VaultClient) WriteSecret(path string, data map[string]interface{}) error {
	_, err := vc.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}
	return nil
}

func (vc *VaultClient) DeleteSecret(path string) error {
	_, err := vc.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

func (vc *VaultClient) EnableAuditDevice(name, type_, description string, options map[string]string) error {
	auditDevices, err := vc.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := auditDevices[name+"/"]; exists {
		logger.Info("Audit device already exists", "name", name)
		return nil
	}

	err = vc.Sys().EnableAuditWithOptions(name, &vault.EnableAuditOptions{
		Type:        type_,
		Description: description,
		Options:     options,
	})
	if err != nil {
		return fmt.Errorf("failed to enable audit device: %w", err)
	}

	logger.Info("Enabled audit device", "name", name)
	return nil
}
