package vault

import (
	"net/http"
	"net/http/httptest"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

// TestNewVaultClient is a unit test function that tests the creation of a new Vault client.
// It iterates over a list of test cases, each representing a different authentication method,
// and verifies that the client is created correctly based on the provided authentication method.
// The function sets up a mock HTTP server and makes requests to it using the specified authentication method.
// It checks whether the client is created successfully or if an error occurs, based on the expected outcome.
// This test function is used to ensure the proper functioning of the NewVaultClient function.
func TestNewVaultClient(t *testing.T) {
	// Test cases for different authentication methods
	tests := []struct {
		name       string
		authMethod AuthMethod
		setupMock  func(*httptest.Server)
		wantErr    bool
	}{
		{
			name:       "TokenAuth",
			authMethod: TokenAuth{Token: "test-token"},
			setupMock:  func(s *httptest.Server) {},
			wantErr:    false,
		},
		// Add more test cases for AppRoleAuth and CertAuth
	}

	// Iterate over the test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Call the setupMock function for additional setup
			tt.setupMock(server)

			// Create a new Vault client
			client, err := NewVaultClient(server.URL, tt.authMethod)

			// Check if the expected error occurred or if the client was created successfully
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

// TestVaultClient_Operations is a test function that tests various operations of the VaultClient.
// It runs a series of test cases to verify the behavior of the Read, Write, Delete, and EnableAuditDevice methods.
// Each test case defines a specific operation, path, input, and expected result.
// The setupMock function is used to mock the HTTP server responses for each test case.
// The function uses the httptest package to create a temporary HTTP server for testing.
// It creates a new VaultClient instance with the server's URL and performs the specified operation.
// The function asserts the expected error or success using the assert package.
func TestVaultClient_Operations(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		path        string
		input       map[string]interface{}
		setupMock   func(w http.ResponseWriter, r *http.Request)
		expectedErr bool
	}{
		{
			name:      "ReadSecret_Success",
			operation: "Read",
			path:      "secret/data/test",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data": {"foo": "bar"}}`))
			},
			expectedErr: false,
		},
		{
			name:      "WriteSecret_Success",
			operation: "Write",
			path:      "secret/data/test",
			input:     map[string]interface{}{"foo": "bar"},
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(http.StatusNoContent)
			},
			expectedErr: false,
		},
		{
			name:      "DeleteSecret_Success",
			operation: "Delete",
			path:      "secret/data/test",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusNoContent)
			},
			expectedErr: false,
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
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/audit":
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{}`))
				case "/v1/sys/audit/test-audit":
					assert.Equal(t, http.MethodPut, r.Method)
					w.WriteHeader(http.StatusNoContent)
				}
			},
			expectedErr: false,
		},
		// Add more test cases here, including error cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.setupMock))
			defer server.Close()

			client, _ := vault.NewClient(&vault.Config{Address: server.URL})
			vaultClient := &VaultClient{client}

			var err error
			switch tt.operation {
			case "Read":
				_, err = vaultClient.ReadSecret(tt.path)
			case "Write":
				err = vaultClient.WriteSecret(tt.path, tt.input)
			case "Delete":
				err = vaultClient.DeleteSecret(tt.path)
			case "EnableAudit":
				err = vaultClient.EnableAuditDevice(tt.path, tt.input["type"].(string), tt.input["description"].(string), tt.input["options"].(map[string]string))
			}

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
