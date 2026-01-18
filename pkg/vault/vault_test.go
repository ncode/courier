package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCertAuth struct {
	CertAuth
	mockConfigureTLS func(*vault.Config) error
}

// ConfigureTLS overrides the original method with our mock
func (m *mockCertAuth) ConfigureTLS(config *vault.Config) error {
	return m.mockConfigureTLS(config)
}

type roundTripperFunc func(*http.Request) *http.Response

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := f(req)
	if resp == nil {
		return nil, fmt.Errorf("no response provided for %s", req.URL.Path)
	}
	resp.Request = req
	if resp.Body == nil {
		resp.Body = io.NopCloser(bytes.NewBuffer(nil))
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	return resp, nil
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func newTestVaultClient(t *testing.T, transport http.RoundTripper) *vault.Client {
	t.Helper()
	cfg := vault.DefaultConfig()
	cfg.Address = "http://vault.test"
	cfg.HttpClient = &http.Client{Transport: transport}
	client, err := vault.NewClient(cfg)
	require.NoError(t, err)
	client.SetToken("test-token")
	return client
}

func TestNewVaultClient(t *testing.T) {
	tests := []struct {
		name       string
		authMethod AuthMethod
		transport  http.RoundTripper
		address    string
		wantErr    bool
	}{
		{
			name:       "TokenAuth_Success",
			authMethod: TokenAuth{Token: "test-token"},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "test-token", r.Header.Get("X-Vault-Token"))
				assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
				return response(http.StatusOK, `{"data": {"id": "test-token"}}`)
			}),
		},
		{
			name: "AppRoleAuth_Success",
			authMethod: AppRoleAuth{
				RoleID:   "test-role-id",
				SecretID: "test-secret-id",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "/v1/auth/approle/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var payload map[string]interface{}
				json.NewDecoder(r.Body).Decode(&payload)
				assert.Equal(t, "test-role-id", payload["role_id"])
				assert.Equal(t, "test-secret-id", payload["secret_id"])
				return response(http.StatusOK, `{"auth": {"client_token": "test-client-token"}}`)
			}),
		},
		{
			name: "CertAuth_Success",
			authMethod: &mockCertAuth{
				CertAuth: CertAuth{
					CertFile: "test-cert.pem",
					KeyFile:  "test-key.pem",
				},
				mockConfigureTLS: func(config *vault.Config) error {
					return nil
				},
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "/v1/auth/cert/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				return response(http.StatusOK, `{"auth": {"client_token": "test-client-token"}}`)
			}),
		},
		{
			name: "JWTAuth_Success",
			authMethod: JWTAuth{
				Role: "test-role",
				JWT:  "test-jwt",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "/v1/auth/jwt/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var payload map[string]interface{}
				json.NewDecoder(r.Body).Decode(&payload)
				assert.Equal(t, "test-role", payload["role"])
				assert.Equal(t, "test-jwt", payload["jwt"])
				return response(http.StatusOK, `{"auth": {"client_token": "test-client-token"}}`)
			}),
		},
		{
			name: "K8sAuth_Success",
			authMethod: K8sAuth{
				Role: "test-role",
				JWT:  "test-jwt",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "/v1/auth/kubernetes/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var payload map[string]interface{}
				json.NewDecoder(r.Body).Decode(&payload)
				assert.Equal(t, "test-role", payload["role"])
				assert.Equal(t, "test-jwt", payload["jwt"])
				return response(http.StatusOK, `{"auth": {"client_token": "test-client-token"}}`)
			}),
		},
		{
			name:       "TokenAuth_Failure",
			authMethod: TokenAuth{Token: "invalid-token"},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
				return response(http.StatusForbidden, `{"errors": ["invalid token"]}`)
			}),
			wantErr: true,
		},
		{
			name: "AppRoleAuth_Failure",
			authMethod: AppRoleAuth{
				RoleID:   "invalid-role-id",
				SecretID: "invalid-secret-id",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusBadRequest, `{"errors": ["invalid AppRole credentials"]}`)
			}),
			wantErr: true,
		},
		{
			name: "CertAuth_Failure",
			authMethod: &mockCertAuth{
				CertAuth: CertAuth{
					CertFile: "invalid-cert.pem",
					KeyFile:  "invalid-key.pem",
				},
				mockConfigureTLS: func(config *vault.Config) error {
					return nil
				},
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusUnauthorized, `{"errors": ["invalid certificate"]}`)
			}),
			wantErr: true,
		},
		{
			name: "JWTAuth_Failure",
			authMethod: JWTAuth{
				Role: "invalid-role",
				JWT:  "invalid-jwt",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusUnauthorized, `{"errors": ["invalid JWT"]}`)
			}),
			wantErr: true,
		},
		{
			name: "K8sAuth_Failure",
			authMethod: K8sAuth{
				Role: "invalid-role",
				JWT:  "invalid-jwt",
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusUnauthorized, `{"errors": ["invalid Kubernetes credentials"]}`)
			}),
			wantErr: true,
		},
		{
			name:       "Fail to create Vault client",
			authMethod: TokenAuth{Token: "test-token"},
			address:    "://bad-address",
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusOK, `{}`)
			}),
			wantErr: true,
		},
		{
			name: "Fail to configure TLS",
			authMethod: &mockCertAuth{
				CertAuth: CertAuth{
					CertFile: "test-cert.pem",
					KeyFile:  "test-key.pem",
				},
				mockConfigureTLS: func(config *vault.Config) error {
					return errors.New("TLS config failed")
				},
			},
			transport: roundTripperFunc(func(r *http.Request) *http.Response {
				return response(http.StatusOK, `{}`)
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.transport
			if transport == nil {
				transport = roundTripperFunc(func(r *http.Request) *http.Response {
					return response(http.StatusOK, `{}`)
				})
			}
			addr := tt.address
			if addr == "" {
				addr = "http://vault.test"
			}

			client, err := NewVaultClient(addr, tt.authMethod, WithHTTPClient(&http.Client{Transport: transport}))
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestVaultClient_Operations(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		path        string
		input       map[string]interface{}
		handler     func(t *testing.T, r *http.Request) *http.Response
		expectedErr bool
		checkResult func(t *testing.T, result interface{})
		checkError  func(t *testing.T, err error)
	}{
		{
			name:      "ReadSecret_Success",
			operation: "Read",
			path:      "secret/data/test",
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				return response(http.StatusOK, `{"data": {"data": {"foo": "bar"}}}`)
			},
			expectedErr: false,
			checkResult: func(t *testing.T, result interface{}) {
				data, ok := result.(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "bar", data["data"].(map[string]interface{})["foo"])
			},
		},
		{
			name:      "ReadSecret_NotFound",
			operation: "Read",
			path:      "secret/data/nonexistent",
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/nonexistent", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				return response(http.StatusNotFound, `{"errors": ["not found"]}`)
			},
			expectedErr: true,
		},
		{
			name:      "ReadSecret_Error",
			operation: "Read",
			path:      "secret/data/error",
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/error", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				return response(http.StatusInternalServerError, `{"errors": ["internal server error"]}`)
			},
			expectedErr: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to read secret")
				var vaultErr *vault.ResponseError
				assert.True(t, errors.As(err, &vaultErr), "error should be or wrap a vault.ResponseError")
				assert.Equal(t, []string{"internal server error"}, vaultErr.Errors)
			},
		},
		{
			name:      "WriteSecret_Success",
			operation: "Write",
			path:      "secret/data/test",
			input:     map[string]interface{}{"foo": "bar"},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var payload map[string]interface{}
				json.NewDecoder(r.Body).Decode(&payload)
				assert.Equal(t, map[string]interface{}{"foo": "bar"}, payload)
				return response(http.StatusNoContent, `{}`)
			},
			expectedErr: false,
		},
		{
			name:      "WriteSecret_Failure",
			operation: "Write",
			path:      "secret/data/test",
			input:     map[string]interface{}{"foo": "bar"},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				return response(http.StatusBadRequest, `{"errors": ["permission denied"]}`)
			},
			expectedErr: true,
		},
		{
			name:      "DeleteSecret_Success",
			operation: "Delete",
			path:      "secret/data/test",
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				return response(http.StatusNoContent, `{}`)
			},
			expectedErr: false,
		},
		{
			name:      "DeleteSecret_Failure",
			operation: "Delete",
			path:      "secret/data/test",
			handler: func(t *testing.T, r *http.Request) *http.Response {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				return response(http.StatusBadRequest, `{"errors": ["permission denied"]}`)
			},
			expectedErr: true,
		},
		{
			name:      "EnableAuditDevice_Success",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				switch r.URL.Path {
				case "/v1/sys/audit":
					assert.Equal(t, http.MethodGet, r.Method)
					return response(http.StatusOK, `{"data":{}}`)
				case "/v1/sys/audit/test-audit":
					assert.Equal(t, http.MethodPut, r.Method)
					var payload map[string]interface{}
					json.NewDecoder(r.Body).Decode(&payload)
					assert.Equal(t, "file", payload["type"])
					assert.Equal(t, "Test audit device", payload["description"])
					assert.Equal(t, map[string]interface{}{"file_path": "/tmp/audit.log"}, payload["options"])
					return response(http.StatusNoContent, `{}`)
				default:
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
				return response(http.StatusInternalServerError, `{}`)
			},
			expectedErr: false,
		},
		{
			name:      "EnableAuditDevice_Failure",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				switch r.URL.Path {
				case "/v1/sys/audit":
					assert.Equal(t, http.MethodGet, r.Method)
					return response(http.StatusOK, `{"test-audit/": {"type": "file"}}`)
				case "/v1/sys/audit/test-audit":
					t.Fatalf("Unexpected request to enable existing audit device")
				default:
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
				return response(http.StatusInternalServerError, `{}`)
			},
			expectedErr: true,
		},
		{
			name:      "EnableAuditDevice_ListFailure",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				if r.URL.Path == "/v1/sys/audit" && r.Method == http.MethodGet {
					return response(http.StatusInternalServerError, `{"errors": ["internal server error"]}`)
				} else {
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
				return response(http.StatusInternalServerError, `{}`)
			},
			expectedErr: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to list audit devices")
				var vaultErr *vault.ResponseError
				assert.True(t, errors.As(err, &vaultErr), "error should be or wrap a vault.ResponseError")
				assert.Equal(t, []string{"internal server error"}, vaultErr.Errors)
			},
		},
		{
			name:      "EnableAuditDevice_EnableFailure",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			handler: func(t *testing.T, r *http.Request) *http.Response {
				switch r.URL.Path {
				case "/v1/sys/audit":
					if r.Method == http.MethodGet {
						return response(http.StatusOK, `{"data":{}}`)
					} else {
						t.Fatalf("Unexpected request to %s", r.URL.Path)
					}
				case "/v1/sys/audit/test-audit":
					if r.Method == http.MethodPut {
						return response(http.StatusInternalServerError, `{"errors": ["failed to enable audit device"]}`)
					} else {
						t.Fatalf("Unexpected request to %s", r.URL.Path)
					}
				default:
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
				return response(http.StatusInternalServerError, `{}`)
			},
			expectedErr: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to enable audit device")
				var vaultErr *vault.ResponseError
				assert.True(t, errors.As(err, &vaultErr), "error should be or wrap a vault.ResponseError")
				assert.Equal(t, []string{"failed to enable audit device"}, vaultErr.Errors)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestVaultClient(t, roundTripperFunc(func(r *http.Request) *http.Response {
				return tt.handler(t, r)
			}))
			vaultClient := &VaultClient{client}

			var err error
			var result interface{}

			switch tt.operation {
			case "Read":
				result, err = vaultClient.ReadSecret(tt.path)
			case "Write":
				err = vaultClient.WriteSecret(tt.path, tt.input)
			case "Delete":
				err = vaultClient.DeleteSecret(tt.path)
			case "EnableAudit":
				err = vaultClient.EnableAuditDevice(tt.path, tt.input["type"].(string), tt.input["description"].(string), tt.input["options"].(map[string]string))
			}

			if tt.expectedErr {
				assert.Error(t, err)
				if tt.checkError != nil {
					tt.checkError(t, err)
				}
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}
		})
	}
}

func generateCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func TestCertAuth_ConfigureTLS(t *testing.T) {
	tempDir := t.TempDir()
	validCert := filepath.Join(tempDir, "valid-cert.pem")
	validKey := filepath.Join(tempDir, "valid-key.pem")
	invalidCert := filepath.Join(tempDir, "invalid-cert.pem")
	invalidKey := filepath.Join(tempDir, "invalid-key.pem")

	err := generateCert(validCert, validKey)
	assert.NoError(t, err)

	err = os.WriteFile(invalidCert, []byte("invalid cert"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(invalidKey, []byte("invalid key"), 0644)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		expectError bool
	}{
		{
			name:        "Valid Certificate and Key",
			certFile:    validCert,
			keyFile:     validKey,
			expectError: false,
		},
		{
			name:        "Invalid Certificate",
			certFile:    invalidCert,
			keyFile:     validKey,
			expectError: true,
		},
		{
			name:        "Invalid Key",
			certFile:    validCert,
			keyFile:     invalidKey,
			expectError: true,
		},
		{
			name:        "Missing Certificate",
			certFile:    filepath.Join(tempDir, "nonexistent-cert.pem"),
			keyFile:     validKey,
			expectError: true,
		},
		{
			name:        "Missing Key",
			certFile:    validCert,
			keyFile:     filepath.Join(tempDir, "nonexistent-key.pem"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certAuth := CertAuth{
				CertFile: tt.certFile,
				KeyFile:  tt.keyFile,
			}

			config := vault.DefaultConfig()
			err := certAuth.ConfigureTLS(config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to configure TLS")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Mock AuthMethod for testing
type mockAuthMethod struct {
	configureTLSFunc func(*vault.Config) error
	authenticateFunc func(*vault.Client) error
}

func (m *mockAuthMethod) ConfigureTLS(config *vault.Config) error {
	return m.configureTLSFunc(config)
}

func (m *mockAuthMethod) Authenticate(client *vault.Client) error {
	return m.authenticateFunc(client)
}
