package auditserver

import (
	"bytes"
	"encoding/json"
	"github.com/panjf2000/gnet"
	"log/slog"
	"net"
	"os"
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
		input          interface{}
		expectedAction gnet.Action
		expectedLog    bool
	}{
		{
			name: "Valid update operation",
			input: map[string]interface{}{
				"type":        "audit",
				"time":        "2023-07-31T12:34:56Z",
				"operation":   "update",
				"auth":        map[string]interface{}{"user": "testuser"},
				"request":     map[string]interface{}{"id": "123"},
				"response":    map[string]interface{}{"status": "success"},
				"remote_addr": "192.168.1.1",
			},
			expectedAction: gnet.None,
			expectedLog:    true,
		},
		{
			name: "Valid create operation",
			input: map[string]interface{}{
				"type":        "audit",
				"time":        "2023-07-31T12:34:56Z",
				"operation":   "create",
				"auth":        map[string]interface{}{"user": "testuser"},
				"request":     map[string]interface{}{"id": "123"},
				"response":    map[string]interface{}{"status": "success"},
				"remote_addr": "192.168.1.1",
			},
			expectedAction: gnet.None,
			expectedLog:    true,
		},
		{
			name: "Invalid operation",
			input: map[string]interface{}{
				"type":        "audit",
				"time":        "2023-07-31T12:34:56Z",
				"operation":   "delete",
				"auth":        map[string]interface{}{"user": "testuser"},
				"request":     map[string]interface{}{"id": "123"},
				"response":    map[string]interface{}{"status": "success"},
				"remote_addr": "192.168.1.1",
			},
			expectedAction: gnet.Close,
			expectedLog:    false,
		},
		{
			name:           "Invalid JSON",
			input:          []byte(`{"invalid json, "operation":"create"`),
			expectedAction: gnet.Close,
			expectedLog:    true, // We expect an error log
		},
		{
			name:           "Empty frame",
			input:          []byte{},
			expectedAction: gnet.Close,
			expectedLog:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}))

			server := New(logger)

			var inputJSON []byte
			if b, ok := tt.input.([]byte); ok {
				inputJSON = b
			} else {
				var err error
				inputJSON, err = json.Marshal(tt.input)
				if err != nil {
					t.Fatalf("Failed to marshal input: %v", err)
				}
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

					if tt.name == "Invalid JSON" {
						if _, ok := logEntry["error"]; !ok {
							t.Errorf("Expected 'error' field in log for invalid JSON, but it was missing")
						}
					} else {
						expectedFields := []string{"type", "time", "remote_addr"}
						for _, field := range expectedFields {
							if _, ok := logEntry[field]; !ok {
								t.Errorf("Expected '%s' field in log, but it was missing", field)
							}
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
	// Test with nil logger
	server := New(nil)
	if server.logger == nil {
		t.Errorf("Expected non-nil logger when initialized with nil")
	}

	// Test with custom logger
	customLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server = New(customLogger)
	if server.logger != customLogger {
		t.Errorf("Expected custom logger to be used")
	}
}
