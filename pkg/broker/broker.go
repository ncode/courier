package broker

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/tidwall/redcon"
)

type Server struct {
	addr   string
	logger *slog.Logger
	ps     redcon.PubSub
	mu     sync.Mutex
}

func NewServer(addr string, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return &Server{
		addr:   addr,
		logger: logger,
	}, nil
}

func (s *Server) ListenAndServeTLS(tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return fmt.Errorf("TLS config is nil")
	}
	s.logger.Info("Starting TLS server", "address", s.addr)
	return redcon.ListenAndServeTLS(s.addr,
		s.handleCommand,
		s.handleAccept,
		s.handleClose,
		tlsConfig,
	)
}

func (s *Server) ListenAndServe() error {
	s.logger.Info("Starting server", "address", s.addr)
	return redcon.ListenAndServe(s.addr,
		s.handleCommand,
		s.handleAccept,
		s.handleClose,
	)
}

func (s *Server) handleCommand(conn redcon.Conn, cmd redcon.Command) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch strings.ToLower(string(cmd.Args[0])) {
	default:
		conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
	case "ping":
		conn.WriteString("PONG")
	case "quit":
		conn.WriteString("OK")
		conn.Close()
	case "publish":
		if len(cmd.Args) != 3 {
			conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
			return
		}
		channel := string(cmd.Args[1])
		message := string(cmd.Args[2])
		numSubs := s.ps.Publish(channel, message)
		conn.WriteInt(numSubs)
		s.logger.Debug("PUBLISH command", "channel", channel, "subscribers", numSubs)
	case "subscribe", "psubscribe":
		if len(cmd.Args) < 2 {
			conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
			return
		}
		command := strings.ToLower(string(cmd.Args[0]))
		for i := 1; i < len(cmd.Args); i++ {
			if command == "psubscribe" {
				s.ps.Psubscribe(conn, string(cmd.Args[i]))
			} else {
				s.ps.Subscribe(conn, string(cmd.Args[i]))
			}
		}
		s.logger.Debug(strings.ToUpper(command)+" command", "patterns", cmd.Args[1:])
	}
}

func (s *Server) handleAccept(conn redcon.Conn) bool {
	s.logger.Info("New connection accepted", "client", conn.RemoteAddr())
	return true
}

func (s *Server) handleClose(conn redcon.Conn, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil && err.Error() != "detached" {
		s.logger.Error("Connection closed with error", "client", conn.RemoteAddr(), "error", err)
	} else {
		s.logger.Info("Connection closed", "client", conn.RemoteAddr())
	}
}
