package auditserver

import (
	"bytes"
	"encoding/json"
	"github.com/panjf2000/gnet"
	"log/slog"
	"os"
)

type AuditLog struct {
	Type       string                 `json:"type"`
	Time       string                 `json:"time"`
	Auth       map[string]interface{} `json:"auth"`
	Request    map[string]interface{} `json:"request"`
	Response   map[string]interface{} `json:"response"`
	Error      string                 `json:"error"`
	RemoteAddr string                 `json:"remote_addr"`
}

type AuditServer struct {
	*gnet.EventServer
	logger *slog.Logger
}

func (as *AuditServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	if !bytes.Contains(frame, []byte(`"operation":"update"`)) && !bytes.Contains(frame, []byte(`"operation":"create"`)) {
		// Skip events that are not relevant for courier
		return nil, gnet.Close
	}

	var auditLog AuditLog

	err := json.Unmarshal(frame, &auditLog)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return nil, gnet.Close
	}

	logAttrs := []any{
		slog.String("type", auditLog.Type),
		slog.String("time", auditLog.Time),
		slog.String("remote_addr", auditLog.RemoteAddr),
	}

	if auditLog.Auth != nil {
		authAttrs := make([]any, 0, len(auditLog.Auth)*2)
		for k, v := range auditLog.Auth {
			authAttrs = append(authAttrs, k, v)
		}
		logAttrs = append(logAttrs, slog.Group("auth", authAttrs...))
	}

	if auditLog.Request != nil {
		requestAttrs := make([]any, 0, len(auditLog.Request)*2)
		for k, v := range auditLog.Request {
			requestAttrs = append(requestAttrs, k, v)
		}
		logAttrs = append(logAttrs, slog.Group("request", requestAttrs...))
	}

	if auditLog.Response != nil {
		responseAttrs := make([]any, 0, len(auditLog.Response)*2)
		for k, v := range auditLog.Response {
			responseAttrs = append(responseAttrs, k, v)
		}
		logAttrs = append(logAttrs, slog.Group("response", responseAttrs...))
	}

	if auditLog.Error != "" {
		logAttrs = append(logAttrs, slog.String("error", auditLog.Error))
	}

	as.logger.Info("Received audit log", logAttrs...)

	return
}

func New(logger *slog.Logger) *AuditServer {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return &AuditServer{
		logger: logger,
	}
}
