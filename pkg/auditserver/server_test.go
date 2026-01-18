package auditserver

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// mockConn is a mock implementation of gnet.Conn for v2
type mockConn struct {
	buf *bytes.Buffer
}

func newMockConn(data []byte) *mockConn {
	return &mockConn{buf: bytes.NewBuffer(data)}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *safeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// Reader interface
func (m *mockConn) Read(p []byte) (n int, err error)         { return m.buf.Read(p) }
func (m *mockConn) WriteTo(w io.Writer) (n int64, err error) { return m.buf.WriteTo(w) }
func (m *mockConn) Next(n int) ([]byte, error) {
	if n < 0 || n > m.buf.Len() {
		n = m.buf.Len()
	}
	data := make([]byte, n)
	_, err := m.buf.Read(data)
	return data, err
}
func (m *mockConn) Peek(n int) ([]byte, error) {
	if n < 0 || n > m.buf.Len() {
		n = m.buf.Len()
	}
	return m.buf.Bytes()[:n], nil
}
func (m *mockConn) Discard(n int) (int, error) {
	if n < 0 || n > m.buf.Len() {
		n = m.buf.Len()
	}
	m.buf.Next(n)
	return n, nil
}
func (m *mockConn) InboundBuffered() int { return m.buf.Len() }

// Writer interface
func (m *mockConn) Write(p []byte) (n int, err error)                    { return len(p), nil }
func (m *mockConn) ReadFrom(r io.Reader) (n int64, err error)            { return 0, nil }
func (m *mockConn) SendTo(buf []byte, addr net.Addr) (int, error)        { return len(buf), nil }
func (m *mockConn) Writev(bs [][]byte) (int, error)                      { return 0, nil }
func (m *mockConn) Flush() error                                         { return nil }
func (m *mockConn) OutboundBuffered() int                                { return 0 }
func (m *mockConn) AsyncWrite(buf []byte, cb gnet.AsyncCallback) error   { return nil }
func (m *mockConn) AsyncWritev(bs [][]byte, cb gnet.AsyncCallback) error { return nil }

// Socket interface
func (m *mockConn) Fd() int                                                             { return 0 }
func (m *mockConn) Dup() (int, error)                                                   { return 0, nil }
func (m *mockConn) SetReadBuffer(size int) error                                        { return nil }
func (m *mockConn) SetWriteBuffer(size int) error                                       { return nil }
func (m *mockConn) SetLinger(secs int) error                                            { return nil }
func (m *mockConn) SetKeepAlivePeriod(d time.Duration) error                            { return nil }
func (m *mockConn) SetKeepAlive(enabled bool, idle, intvl time.Duration, cnt int) error { return nil }
func (m *mockConn) SetNoDelay(noDelay bool) error                                       { return nil }

// Conn interface
func (m *mockConn) Context() any                                  { return nil }
func (m *mockConn) SetContext(ctx any)                            {}
func (m *mockConn) LocalAddr() net.Addr                           { return nil }
func (m *mockConn) RemoteAddr() net.Addr                          { return nil }
func (m *mockConn) Wake(cb gnet.AsyncCallback) error              { return nil }
func (m *mockConn) CloseWithCallback(cb gnet.AsyncCallback) error { return nil }
func (m *mockConn) Close() error                                  { return nil }
func (m *mockConn) SetDeadline(t time.Time) error                 { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error             { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error            { return nil }

func TestAuditServer_OnTraffic(t *testing.T) {
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
			logBuffer := &safeBuffer{}
			logger := slog.New(slog.NewJSONHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}))

			server := New(logger, nil)

			inputJSON, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			action := server.OnTraffic(newMockConn(inputJSON))

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
					lines := bytes.Split(bytes.TrimSpace(logBuffer.Bytes()), []byte("\n"))
					if len(lines) == 0 {
						t.Fatalf("Expected log output lines, but found none")
					}
					err := json.Unmarshal(lines[0], &logEntry)
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
	// Test with nil logger and nil dispatcher
	server := New(nil, nil)
	if server.logger == nil {
		t.Errorf("Expected non-nil logger when initialized with nil")
	}

	// Test with custom logger
	customLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server = New(customLogger, nil)
	if server.logger != customLogger {
		t.Errorf("Expected custom logger to be used")
	}
}

func TestAuditServer_OnTraffic_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := New(logger, nil)

	invalidJSON := []byte(`{"invalid": json}`)
	action := server.OnTraffic(newMockConn(invalidJSON))

	if action != gnet.Close {
		t.Errorf("Expected gnet.Close action for invalid JSON, got %v", action)
	}
}

func TestAuditServer_OnTraffic_NonRelevantOperations(t *testing.T) {
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
		action := server.OnTraffic(newMockConn(inputJSON))

		if action != gnet.Close {
			t.Errorf("Expected gnet.Close action for non-relevant operation %s, got %v", op, action)
		}
	}
}

func TestAuditServer_OnTraffic_LoggingBehavior(t *testing.T) {
	logBuffer := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}))
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
	server.OnTraffic(newMockConn(inputJSON))

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

func TestAuditServer_OnTraffic_JSONParseError(t *testing.T) {
	logBuffer := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelError}))
	server := New(logger, nil)

	// Create an input that will pass the initial checks but fail JSON unmarshaling
	invalidInput := []byte(`{"auth":{"policy_results":{"allowed":true}},"request":{"mount_type":"kv","operation":"update"},"response":{"mount_type":"kv"},"invalid_json":}`)

	action := server.OnTraffic(newMockConn(invalidInput))

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

func TestAuditServer_OnTraffic_EnqueuesDispatcher(t *testing.T) {
	callCh := make(chan string, 1)

	logger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	dispatcher := NewDispatcher(logger, func(event UpdateEvent) error {
		callCh <- string(event.Kind) + ":" + event.Path + ":" + event.Operation
		return nil
	}, 1, 1)
	server := New(logger, dispatcher)

	input := AuditLog{
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

	inputJSON, _ := json.Marshal(input)
	server.OnTraffic(newMockConn(inputJSON))

	select {
	case got := <-callCh:
		if got != "kv:/secret/test:update" {
			t.Fatalf("unexpected dispatcher input: %s", got)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("dispatcher was not invoked")
	}
}
