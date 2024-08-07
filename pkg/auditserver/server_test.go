package auditserver

import (
	"bytes"
	"encoding/json"
	"github.com/panjf2000/gnet"
	"github.com/redis/go-redis/v9"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
)

// mockConn is a mock implementation of gnet.Conn
type mockConn struct{}

func (m *mockConn) Read() []byte                        { return nil }
func (m *mockConn) ReadN(n int) (int, []byte)           { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Close() error                        { return nil }
func (m *mockConn) LocalAddr() net.Addr                 { return nil }
func (m *mockConn) RemoteAddr() net.Addr                { return nil }
func (m *mockConn) Context() interface{}                { return nil }
func (m *mockConn) SetContext(ctx interface{})          {}
func (m *mockConn) Wake() error                         { return nil }
func (m *mockConn) ResetBuffer()                        {}
func (m *mockConn) ReadBytes() []byte                   { return nil }
func (m *mockConn) ShiftN(n int) (size int)             { return 0 }
func (m *mockConn) InboundBuffer() *bytes.Buffer        { return nil }
func (m *mockConn) OutboundBuffer() *bytes.Buffer       { return nil }
func (m *mockConn) AsyncWrite(buf []byte) (err error)   { return nil }
func (m *mockConn) AsyncWritev(bs [][]byte) (err error) { return nil }
func (m *mockConn) SendTo(buf []byte) (err error)       { return nil }
func (m *mockConn) WriteFrame(buf []byte) (err error)   { return nil }
func (m *mockConn) BufferLength() int                   { return 0 }
func (m *mockConn) Peek(n int) (buf []byte, err error)  { return nil, nil }
func (m *mockConn) Next(n int) (buf []byte, err error)  { return nil, nil }

func TestAuditServer_React(t *testing.T) {
	tests := []struct {
		name           string
		input          AuditLog
		expectedAction gnet.Action
		expectedLog    bool
	}{
		{
			name: "Valid KV update operation",
			input: AuditLog{
				Type: "audit",
				Time: "2023-07-31T12:34:56Z",
				Auth: Auth{
					PolicyResults: struct {
						Allowed bool `json:"allowed"`
					}{Allowed: true},
				},
				Request: Request{
					Operation: "update",
					MountType: "kv",
					Path:      "/secret/data/test",
				},
				Response: Response{
					MountType: "kv",
				},
				RemoteAddr: "192.168.1.1",
			},
			expectedAction: gnet.None,
			expectedLog:    true,
		},
		{
			name: "Valid KV create operation",
			input: AuditLog{
				Type: "audit",
				Time: "2023-07-31T12:34:56Z",
				Auth: Auth{
					PolicyResults: struct {
						Allowed bool `json:"allowed"`
					}{Allowed: true},
				},
				Request: Request{
					Operation: "create",
					MountType: "kv",
					Path:      "/secret/data/test",
				},
				Response: Response{
					MountType: "kv",
				},
				RemoteAddr: "192.168.1.1",
			},
			expectedAction: gnet.None,
			expectedLog:    true,
		},
		{
			name: "Valid KV delete operation",
			input: AuditLog{
				Type: "audit",
				Time: "2023-07-31T12:34:56Z",
				Auth: Auth{
					PolicyResults: struct {
						Allowed bool `json:"allowed"`
					}{Allowed: true},
				},
				Request: Request{
					Operation: "delete",
					MountType: "kv",
					Path:      "/secret/data/test",
				},
				Response: Response{
					MountType: "kv",
				},
				RemoteAddr: "192.168.1.1",
			},
			expectedAction: gnet.None,
			expectedLog:    true,
		},
		{
			name: "Non-KV operation",
			input: AuditLog{
				Type: "audit",
				Time: "2023-07-31T12:34:56Z",
				Auth: Auth{
					PolicyResults: struct {
						Allowed bool `json:"allowed"`
					}{Allowed: true},
				},
				Request: Request{
					Operation: "update",
					MountType: "transit",
					Path:      "/transit/keys/test",
				},
				Response: Response{
					MountType: "transit",
				},
				RemoteAddr: "192.168.1.1",
			},
			expectedAction: gnet.Close,
			expectedLog:    false,
		},
		{
			name: "Disallowed operation",
			input: AuditLog{
				Type: "audit",
				Time: "2023-07-31T12:34:56Z",
				Auth: Auth{
					PolicyResults: struct {
						Allowed bool `json:"allowed"`
					}{Allowed: false},
				},
				Request: Request{
					Operation: "update",
					MountType: "kv",
					Path:      "/secret/data/test",
				},
				Response: Response{
					MountType: "kv",
				},
				RemoteAddr: "192.168.1.1",
			},
			expectedAction: gnet.Close,
			expectedLog:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}))

			server := New(logger, nil)

			inputJSON, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			_, action := server.React(inputJSON, &mockConn{})

			t.Logf("Test case: %s", tt.name)
			t.Logf("Input: %s", string(inputJSON))
			t.Logf("Action: %v", action)
			t.Logf("Log buffer: %s", logBuffer.String())

			if action != tt.expectedAction {
				t.Errorf("Expected action %v, but got %v", tt.expectedAction, action)
			}

			if tt.expectedLog {
				if logBuffer.Len() == 0 {
					t.Errorf("Expected log output, but got none")
				} else {
					var logEntry map[string]interface{}
					err := json.Unmarshal(logBuffer.Bytes(), &logEntry)
					if err != nil {
						t.Fatalf("Failed to parse log output: %v", err)
					}

					expectedFields := []string{"operation", "path"}
					for _, field := range expectedFields {
						if _, ok := logEntry[field]; !ok {
							t.Errorf("Expected '%s' field in log, but it was missing", field)
						}
					}
				}
			} else if logBuffer.Len() > 0 {
				t.Errorf("Expected no log output, but got: %s", logBuffer.String())
			}
		})
	}
}

func TestNew(t *testing.T) {
	// Test with nil logger and nil publisher
	server := New(nil, nil)
	if server.logger == nil {
		t.Errorf("Expected non-nil logger when initialized with nil")
	}
	if server.publisher != nil {
		t.Errorf("Expected nil publisher when initialized with nil")
	}

	// Test with custom logger and publisher
	customLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	customPublisher := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	server = New(customLogger, customPublisher)
	if server.logger != customLogger {
		t.Errorf("Expected custom logger to be used")
	}
	if server.publisher != customPublisher {
		t.Errorf("Expected custom publisher to be used")
	}
}

func TestAuditServer_React_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := New(logger, nil)

	invalidJSON := []byte(`{"invalid": json}`)
	_, action := server.React(invalidJSON, &mockConn{})

	if action != gnet.Close {
		t.Errorf("Expected gnet.Close action for invalid JSON, got %v", action)
	}
}

func TestAuditServer_React_NonRelevantOperations(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := New(logger, nil)

	nonRelevantOps := []string{"read", "list", "sudo"}
	for _, op := range nonRelevantOps {
		input := AuditLog{
			Auth: Auth{
				PolicyResults: struct {
					Allowed bool `json:"allowed"`
				}{Allowed: true},
			},
			Request: Request{
				Operation: op,
				MountType: "kv",
			},
			Response: Response{
				MountType: "kv",
			},
		}

		inputJSON, _ := json.Marshal(input)
		_, action := server.React(inputJSON, &mockConn{})

		if action != gnet.Close {
			t.Errorf("Expected gnet.Close action for non-relevant operation %s, got %v", op, action)
		}
	}
}

func TestAuditServer_React_LoggingBehavior(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := New(logger, nil)

	validInput := AuditLog{
		Auth: Auth{
			PolicyResults: struct {
				Allowed bool `json:"allowed"`
			}{Allowed: true},
		},
		Request: Request{
			Operation: "update",
			MountType: "kv",
			Path:      "/secret/test",
		},
		Response: Response{
			MountType: "kv",
		},
	}

	inputJSON, _ := json.Marshal(validInput)
	server.React(inputJSON, &mockConn{})

	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "Received audit log") {
		t.Errorf("Expected log output to contain 'Received audit log', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "/secret/test") {
		t.Errorf("Expected log output to contain the path '/secret/test', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "update") {
		t.Errorf("Expected log output to contain the operation 'update', got: %s", logOutput)
	}
}

func TestAuditServer_React_JSONParseError(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelError}))
	server := New(logger, nil)

	// Create an input that will pass the initial checks but fail JSON unmarshaling
	invalidInput := []byte(`{"auth":{"policy_results":{"allowed":true}},"request":{"mount_type":"kv","operation":"update"},"response":{"mount_type":"kv"},"invalid_json":}`)

	_, action := server.React(invalidInput, &mockConn{})

	// Check that the action is gnet.Close
	if action != gnet.Close {
		t.Errorf("Expected gnet.Close action for JSON parse error, got %v", action)
	}

	// Check that an error was logged
	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "Error parsing audit log") {
		t.Errorf("Expected log output to contain 'Error parsing audit log', got: %s", logOutput)
	}

	// Parse the log output to check for the error details
	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(logOutput), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["level"] != "ERROR" {
		t.Errorf("Expected log level to be ERROR, got: %s", logEntry["level"])
	}

	errorMsg, ok := logEntry["error"].(string)
	if !ok {
		t.Errorf("Expected 'error' field in log output to be a string")
	} else if !strings.Contains(errorMsg, "invalid character") {
		t.Errorf("Expected error message to contain 'invalid character', got: %s", errorMsg)
	}
}
