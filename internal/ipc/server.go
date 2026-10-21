package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"time"
)

type Handler func(req Request) Response

type Server struct {
	socket  string
	handler Handler
	log     *slog.Logger
	ln      net.Listener
}

func NewServer(socket string, handler Handler, log *slog.Logger) (*Server, error) {
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{socket: socket, handler: handler, log: log, ln: ln}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("ipc accept", "err", err)
			continue
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	// Bound the lifetime of a single connection. A stalled client must not
	// hold a goroutine indefinitely — unbounded handler goroutines are a
	// DoS waiting to happen even on a local socket.
	//
	// The deadline bounds reading the request and writing the response, not
	// the handler itself: some commands (cve) collect facts and read every
	// feed cache, which can exceed 10s on a large host. Handlers that do
	// real work bound themselves with a context timeout.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = json.NewEncoder(c).Encode(Response{OK: false, Error: "bad json: " + err.Error()})
		return
	}
	resp := s.handler(req)
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(c).Encode(resp)
}
