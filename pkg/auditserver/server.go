package auditserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"

	"github.com/panjf2000/gnet/v2"
)

var (
	operationUpdate = []byte(`"operation":"update"`)
	operationCreate = []byte(`"operation":"create"`)
	operationDelete = []byte(`"operation":"delete"`)
	allowedPolicy   = []byte(`"policy_results":{"allowed":true`)
)

type Request struct {
	MountClass          string `json:"mount_class"`
	MountPoint          string `json:"mount_point"`
	MountRunningVersion string `json:"mount_running_version"`
	MountType           string `json:"mount_type"`
	Operation           string `json:"operation"`
	Path                string `json:"path"`
}

type Response struct {
	MountAccessor             string `json:"mount_accessor"`
	MountClass                string `json:"mount_class"`
	MountPoint                string `json:"mount_point"`
	MountRunningPluginVersion string `json:"mount_running_plugin_version"`
	MountType                 string `json:"mount_type"`
}

type Auth struct {
	Accessor      string `json:"accessor"`
	ClientToken   string `json:"client_token"`
	DisplayName   string `json:"display_name"`
	PolicyResults struct {
		Allowed bool `json:"allowed"`
	} `json:"policy_results"`
}

type AuditLog struct {
	Type       string   `json:"type"`
	Time       string   `json:"time"`
	Auth       Auth     `json:"auth"`
	Request    Request  `json:"request"`
	Response   Response `json:"response"`
	Error      string   `json:"error"`
	RemoteAddr string   `json:"remote_addr"`
}

type AuditServer struct {
	gnet.BuiltinEventEngine
	logger     *slog.Logger
	dispatcher *Dispatcher
}

func (as *AuditServer) OnTraffic(c gnet.Conn) gnet.Action {
	frame, _ := c.Next(-1)

	if !bytes.Contains(frame, allowedPolicy) {
		// Skip events that are not allowed
		return gnet.Close
	}

	if !bytes.Contains(frame, operationUpdate) && !bytes.Contains(frame, operationCreate) && !bytes.Contains(frame, operationDelete) {
		// Skip events that are not relevant for courier
		return gnet.Close
	}

	var auditLog AuditLog
	err := json.Unmarshal(frame, &auditLog)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return gnet.Close
	}

	if auditLog.Auth.PolicyResults.Allowed != true {
		return gnet.Close
	}

	kind, ok := resolveUpdateKind(auditLog)
	if !ok {
		return gnet.Close
	}

	logAttrs := []any{
		"kind", kind,
		"operation", auditLog.Request.Operation,
		"path", auditLog.Request.Path,
	}
	as.logger.Info("Received audit log", logAttrs...)

	if as.dispatcher != nil {
		as.dispatcher.Enqueue(UpdateEvent{
			Kind:      kind,
			Path:      auditLog.Request.Path,
			Operation: auditLog.Request.Operation,
		})
	}

	return gnet.None
}

func New(logger *slog.Logger, dispatcher *Dispatcher) *AuditServer {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if dispatcher == nil {
		dispatcher = NewDispatcher(logger, nil, 0, 0)
	}
	return &AuditServer{
		logger:     logger,
		dispatcher: dispatcher,
	}
}

func resolveUpdateKind(auditLog AuditLog) (UpdateKind, bool) {
	if auditLog.Request.MountType == "kv" || auditLog.Response.MountType == "kv" {
		return UpdateKindKV, true
	}

	if strings.HasPrefix(auditLog.Request.Path, "sys/policies") {
		return UpdateKindPolicy, true
	}

	return "", false
}
