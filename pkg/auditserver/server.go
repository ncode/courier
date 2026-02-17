package auditserver

import (
	vaultfilter "github.com/ncode/vault-audit-filter/pkg/auditserver"
	"log/slog"
	"os"
	"strings"

	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/viper"
)

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

	event, ok := toUpdateEvent(result.Log)
	if !ok {
		return gnet.Close
	}

	logAttrs := []any{
		"kind", event.Kind,
		"operation", event.Operation,
		"path", event.Path,
		"matched_groups", result.MatchedGroups,
	}
	as.logger.Info("Received audit log", logAttrs...)

	if as.dispatcher != nil {
		as.dispatcher.Enqueue(UpdateEvent{
			Kind:      event.Kind,
			Path:      event.Path,
			Operation: event.Operation,
		})
	}

	return gnet.None
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

func resolveUpdateKind(auditLog vaultfilter.AuditLog) (UpdateKind, bool) {
	if auditLog.Request.MountType == "kv" || auditLog.Response.MountType == "kv" {
		return UpdateKindKV, true
	}

	if strings.HasPrefix(auditLog.Request.Path, "sys/policies") {
		return UpdateKindPolicy, true
	}

	return "", false
}

func toUpdateEvent(log vaultfilter.AuditLog) (UpdateEvent, bool) {
	kind, ok := resolveUpdateKind(log)
	if !ok {
		return UpdateEvent{}, false
	}

	return UpdateEvent{
		Kind:      kind,
		Path:      log.Request.Path,
		Operation: log.Request.Operation,
	}, true
}
