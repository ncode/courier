package auditserver

import (
	vaultfilter "github.com/ncode/vault-audit-filter/pkg/auditserver"
	"log/slog"
	"os"
	"strings"

	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/viper"
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

var courierAuditRules = []vaultfilter.RuleGroupConfig{
	{
		Name: "courier-filter",
		Rules: []string{
			`Auth.PolicyResults.Allowed == true && Request.Operation in ["create", "update", "delete"]`,
		},
	},
}

type AuditServer struct {
	gnet.BuiltinEventEngine
	logger     *slog.Logger
	matcher    *vaultfilter.AuditServer
	dispatcher *Dispatcher
}

func (as *AuditServer) handleFrame(frame []byte) gnet.Action {
	result, err := as.matcher.MatchFrame(frame)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return gnet.Close
	}
	if !result.Matched {
		return gnet.Close
	}

	auditLog := toAuditLog(result.Log)
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

func toAuditLog(log vaultfilter.AuditLog) AuditLog {
	return AuditLog{
		Type: log.Type,
		Time: log.Time,
		Auth: Auth{
			Accessor:    log.Auth.Accessor,
			ClientToken: log.Auth.ClientToken,
			DisplayName: log.Auth.DisplayName,
			PolicyResults: struct {
				Allowed bool `json:"allowed"`
			}{
				Allowed: log.Auth.PolicyResults.Allowed,
			},
		},
		Request: Request{
			MountClass:          log.Request.MountClass,
			MountPoint:          log.Request.MountPoint,
			MountRunningVersion: log.Request.MountRunningVersion,
			MountType:           log.Request.MountType,
			Operation:           log.Request.Operation,
			Path:                log.Request.Path,
		},
		Response: Response{
			MountAccessor:             log.Response.MountAccessor,
			MountClass:                log.Response.MountClass,
			MountPoint:                log.Response.MountPoint,
			MountRunningPluginVersion: log.Response.MountRunningPluginVersion,
			MountType:                 log.Response.MountType,
		},
		Error:      log.Error,
		RemoteAddr: log.RemoteAddr,
	}
}

func (as *AuditServer) OnTraffic(c gnet.Conn) gnet.Action {
	frame, _ := c.Next(-1)

	if as.matcher == nil {
		as.logger.Error("Audit matcher is not initialized", "error", "nil matcher")
		return gnet.Close
	}

	return as.handleFrame(frame)
}

func New(logger *slog.Logger, dispatcher *Dispatcher) *AuditServer {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if dispatcher == nil {
		dispatcher = NewDispatcher(logger, nil, 0, 0)
	}
	viper.Set("rule_groups", courierAuditRules)
	matcher, err := vaultfilter.New(logger)
	if err != nil {
		logger.Error("Failed to initialize audit matcher", "error", err)
		matcher = nil
	}
	return &AuditServer{
		logger:     logger,
		matcher:    matcher,
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
