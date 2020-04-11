// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/inconshreveable/go-vhost"
	//	"github.com/mmatczuk/go-http-tunnel/id"

	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

// ServerConfig defines configuration for the Server.
type ServerConfig struct {
	// Addr is TCP address to listen for client connections. If empty ":0"
	// is used.
	Addr string
	// Address Pool enables Port AutoAssignation.
	PortRange string
	// TLSConfig specifies the tls configuration to use with tls.Listener.
	TLSConfig *tls.Config
	// Listener specifies optional listener for client connections. If nil
	// tls.Listen("tcp", Addr, TLSConfig) is used.
	Listener net.Listener
	// Logger is optional logger. If nil logging is disabled.
	Logger log.Logger
	// Addr is TCP address to listen for TLS SNI connections
	SNIAddr string
}

// Server is responsible for proxying public connections to the client over a
// tunnel connection.
type Server struct {
	*registry
	config *ServerConfig

	listener   net.Listener
	connPool   *connPool
	httpClient *http.Client
	logger     log.Logger
	vhostMuxer *vhost.TLSMuxer
	PortPool   *AddrPool
}

// NewServer creates a new Server.
func NewServer(config *ServerConfig) (*Server, error) {
	pPool := &AddrPool{}
	err := pPool.Init(config.PortRange)
	if err != nil {
		return nil, fmt.Errorf("failed to create port range pool: %s", err)
	}

	listener, err := listener(config)
	if err != nil {
		return nil, fmt.Errorf("listener failed: %s", err)
	}

	logger := config.Logger
	if logger == nil {
		logger = log.NewNopLogger()
	}

	s := &Server{
		registry: newRegistry(logger),
		PortPool: pPool,
		config:   config,
		listener: listener,
		logger:   logger,
	}

	t := &http2.Transport{}
	pool := newConnPool(t, s.disconnected)
	t.ConnPool = pool
	s.connPool = pool
	s.httpClient = &http.Client{
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if config.SNIAddr != "" {
		l, err := net.Listen("tcp", config.SNIAddr)
		if err != nil {
			return nil, err
		}
		mux, err := vhost.NewTLSMuxer(l, DefaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("SNI Muxer creation failed: %s", err)
		}
		s.vhostMuxer = mux
		go func() {
			for {
				conn, err := mux.NextError()
				vhostName := ""
				tlsConn, ok := conn.(*vhost.TLSConn)
				if ok {
					vhostName = tlsConn.Host()
				}

				switch err.(type) {
				case vhost.BadRequest:
					logger.Log(
						"level", 0,
						"action", "got a bad request!",
						"addr", conn.RemoteAddr(),
					)
				case vhost.NotFound:

					logger.Log(
						"level", 0,
						"action", "got a connection for an unknown vhost",
						"addr", vhostName,
					)
				case vhost.Closed:
					logger.Log(
						"level", 0,
						"action", "closed conn",
						"addr", vhostName,
					)
				}

				if conn != nil {
					conn.Close()
				}
			}
		}()
	}

	return s, nil
}

func listener(config *ServerConfig) (net.Listener, error) {
	if config.Listener != nil {
		return config.Listener, nil
	}

	if config.Addr == "" {
		return nil, errors.New("missing Addr")
	}
	if config.TLSConfig == nil {
		return nil, errors.New("missing TLSConfig")
	}

	return net.Listen("tcp", config.Addr)
}

// disconnected clears resources used by client, it's invoked by connection pool
// when client goes away.
func (s *Server) disconnected(identifier string) {
	s.logger.Log(
		"level", 1,
		"action", "disconnected",
		"identifier", identifier,
	)

	i := s.registry.clear(identifier)
	if i == nil {
		s.logger.Log(
			"level", 1,
			"action", "ERROR ON DISCONNECT (registry not found)",
			"identifier", identifier,
		)
		return
	}

	s.logger.Log(
		"level", 1,
		"action", "DISCONNECT",
		"identifier", identifier,
		"client-name", i.ClientName,
		"data", i,
	)

	for _, l := range i.Listeners {
		s.logger.Log(
			"level", 2,
			"action", "close listener",
			"identifier", identifier,
			"client-name", i.ClientName,
			"addr", l.Addr(),
		)
		l.Close()
		s.PortPool.Release(i.ClientName)
	}
}

// Start starts accepting connections form clients. For accepting http traffic
// from end users server must be run as handler on http server.
func (s *Server) Start() {
	addr := s.listener.Addr().String()

	s.logger.Log(
		"level", 1,
		"action", "start",
		"addr", addr,
	)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				s.logger.Log(
					"level", 1,
					"action", "control connection listener closed",
					"addr", addr,
				)
				return
			}

			s.logger.Log(
				"level", 0,
				"msg", "accept of control connection failed",
				"addr", addr,
				"err", err,
			)
			continue
		}

		if err := keepAlive(conn); err != nil {
			s.logger.Log(
				"level", 0,
				"msg", "TCP keepalive for control connection failed",
				"addr", addr,
				"err", err,
			)
		}

		go s.handleClient(tls.Server(conn, s.config.TLSConfig))
	}
}

func (s *Server) handleClient(conn net.Conn) {
	logger := log.NewContext(s.logger).With("addr", conn.RemoteAddr())

	logger.Log(
		"level", 1,
		"action", "try connect",
	)

	var (
		conid   string
		req     *http.Request
		resp    *http.Response
		tunnels TunnelExt
		err     error

		inConnPool bool
	)

	conid = conn.RemoteAddr().String()

	s.PreSubscribe(conid)

	if err = conn.SetDeadline(time.Time{}); err != nil {
		logger.Log(
			"level", 2,
			"msg", "setting infinite deadline failed",
			"err", err,
		)
		goto reject
	}

	if err := s.connPool.AddConn(conn, conid); err != nil {
		logger.Log(
			"level", 2,
			"msg", "adding connection failed",
			"err", err,
		)
		goto reject
	}
	inConnPool = true

	req, err = http.NewRequest(http.MethodConnect, s.connPool.URL(conid), nil)
	if err != nil {
		logger.Log(
			"level", 2,
			"msg", "handshake request creation failed",
			"err", err,
		)
		goto reject
	}

	{
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	resp, err = s.httpClient.Do(req)
	if err != nil {
		logger.Log(
			"level", 2,
			"msg", "handshake failed 1",
			"err", err,
		)
		goto reject
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Status %s", resp.Status)
		logger.Log(
			"level", 2,
			"msg", "handshake failed 2",
			"err", err,
		)
		goto reject
	}

	if resp.ContentLength == 0 {
		err = fmt.Errorf("Tunnels Content-Legth: 0")
		logger.Log(
			"level", 2,
			"msg", "handshake failed 3 ",
			"err", err,
		)
		goto reject
	}

	if err = json.NewDecoder(&io.LimitedReader{R: resp.Body, N: 126976}).Decode(&tunnels); err != nil {
		logger.Log(
			"level", 2,
			"msg", "handshake failed 4 ",
			"err", err,
		)
		goto reject
	}

	logger.Log(
		"level", 1,
		"msg", "CLIENT NAME HAS BEEN SET to",
		"client-id", conid,
		"name", tunnels.IdName,
	)

	s.Subscribe(tunnels.IdName, conid)

	if len(tunnels.Tunnels) == 0 {
		err = fmt.Errorf("No tunnels")
		logger.Log(
			"level", 2,
			"msg", "handshake failed 5 ",
			"err", err,
		)
		goto reject
	}

	if err = s.addTunnels(tunnels.IdName, tunnels.Tunnels); err != nil {
		logger.Log(
			"level", 2,
			"msg", "handshake failed 6 ",
			"err", err,
		)
		goto reject
	}

	logger.Log(
		"level", 1,
		"action", "connected",
		"name-id", tunnels.IdName,
	)

	return

reject:
	logger.Log(
		"level", 1,
		"action", "rejected",
	)

	if inConnPool {
		s.notifyError(err, conid)
		s.connPool.DeleteConn(tunnels.IdName)
	}

	conn.Close()
}

// notifyError tries to send error to client.
func (s *Server) notifyError(serverError error, conid string) {
	if serverError == nil {
		return
	}

	req, err := http.NewRequest(http.MethodConnect, s.connPool.URL(conid), nil)
	if err != nil {
		s.logger.Log(
			"level", 2,
			"action", "client error notification failed",
			"identifier", conid,
			//			"name-id", s.idname,
		)
		return
	}

	req.Header.Set(proto.HeaderError, serverError.Error())

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	s.httpClient.Do(req.WithContext(ctx))
}

func (s *Server) adrListenRegister(in string, cid string, portname string) (string, error) {

	inarr := strings.Split(in, ":")
	host := inarr[0]
	port := inarr[1]
	if port == "AUTO" {
		port, err := s.PortPool.Acquire(cid, portname)
		if err != nil {
			return "", fmt.Errorf("Error on acquire port from port pool:%s", err)
		}
		addr := host + ":" + strconv.Itoa(port)

		s.logger.Log(
			"level", 1,
			"action", "address auto assign",
			"cliend-id", cid,
			"portname", portname,
			"addr", addr,
		)
		return addr, nil
	}
	return in, nil
}

// addTunnels invokes addHost or addListener based on data from proto.Tunnel. If
// a tunnel cannot be added whole batch is reverted.
func (s *Server) addTunnels(cname string, tunnels map[string]*proto.Tunnel) error {
	i := &RegistryItem{
		Hosts:      []*HostAuth{},
		Listeners:  []net.Listener{},
		ClientName: cname,
	}

	var err error
	var portnames []string

	for name, t := range tunnels {
		portnames = append(portnames, name)
		switch t.Protocol {
		case proto.HTTP:
			i.Hosts = append(i.Hosts, &HostAuth{t.Host, NewAuth(t.Auth)})
		case proto.TCP, proto.TCP4, proto.TCP6, proto.UNIX:
			var l net.Listener
			addr, err := s.adrListenRegister(t.Addr, cname, name)
			if err != nil {
				goto rollback
			}
			l, err = net.Listen(t.Protocol, addr)
			if err != nil {
				goto rollback
			}

			s.logger.Log(
				"level", 2,
				"action", "open listener",
				"client-id", cname,
				"port-name", name,
				"addr", l.Addr(),
			)

			i.Listeners = append(i.Listeners, l)
		case proto.SNI:
			if s.vhostMuxer == nil {
				err = fmt.Errorf("unable to configure SNI for tunnel %s: %s", name, t.Protocol)
				goto rollback
			}
			var l net.Listener
			l, err = s.vhostMuxer.Listen(t.Host)
			if err != nil {
				goto rollback
			}

			s.logger.Log(
				"level", 2,
				"action", "add SNI vhost",
				"client-id", cname,
				"port-name", name,
				"host", t.Host,
			)

			i.Listeners = append(i.Listeners, l)
		default:
			err = fmt.Errorf("unsupported protocol for tunnel %s: %s", name, t.Protocol)
			goto rollback
		}
	}
	i.ListenerNames = portnames

	err = s.set(i, cname)
	if err != nil {
		goto rollback
	}

	for k, l := range i.Listeners {
		go s.listen(l, i.ClientName, i.ListenerNames[k])
	}

	return nil

rollback:
	for _, l := range i.Listeners {
		l.Close()
	}

	return err
}

// Unsubscribe removes client from registry, disconnects client if already
// connected and returns it's RegistryItem.
func (s *Server) Unsubscribe(identifier string, idname string) *RegistryItem {
	s.connPool.DeleteConn(identifier)
	return s.registry.Unsubscribe(identifier, idname)
}

// Ping measures the RTT response time.
func (s *Server) Ping(identifier string) (time.Duration, error) {
	return s.connPool.Ping(identifier)
}

func (s *Server) listen(l net.Listener, cname string, pname string) {
	addr := l.Addr().String()

	for {
		conn, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "Listener closed") {
				s.logger.Log(
					"level", 2,
					"action", "listener closed",
					"client-name", cname,
					"port-name", pname,
					"addr", addr,
				)
				return
			}

			s.logger.Log(
				"level", 0,
				"msg", "accept of connection failed",
				"client-name", cname,
				"port-name", pname,
				"addr", addr,
				"err", err,
			)
			continue
		}

		msg := &proto.ControlMessage{
			Action:         proto.ActionProxy,
			ForwardedProto: l.Addr().Network(),
		}

		tlsConn, ok := conn.(*vhost.TLSConn)
		if ok {
			msg.ForwardedHost = tlsConn.Host()
			err = keepAlive(tlsConn.Conn)

		} else {
			msg.ForwardedId = pname
			msg.ForwardedHost = l.Addr().String()
			err = keepAlive(conn)
		}

		if err != nil {
			s.logger.Log(
				"level", 1,
				"msg", "TCP keepalive for tunneled connection failed",
				"client-name", cname,
				"port-name", pname,
				"ctrlMsg", msg,
				"err", err,
			)
		}

		go func() {
			if err := s.proxyConn(cname, conn, msg); err != nil {
				s.logger.Log(
					"level", 0,
					"msg", "proxy error",
					"client-name", cname,
					"port-name", pname,
					"ctrlMsg", msg,
					"err", err,
				)
			}
		}()
	}
}

// ServeHTTP proxies http connection to the client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := s.RoundTrip(r)
	if err == errUnauthorised {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"User Visible Realm\"")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err != nil {
		s.logger.Log(
			"level", 0,
			"action", "round trip failed",
			"addr", r.RemoteAddr,
			"host", r.Host,
			"url", r.URL,
			"err", err,
		)

		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	transfer(w, resp.Body, log.NewContext(s.logger).With(
		"dir", "client to user",
		"dst", r.RemoteAddr,
		"src", r.Host,
	))
}

// RoundTrip is http.RoundTriper implementation.
func (s *Server) RoundTrip(r *http.Request) (*http.Response, error) {
	identifier, auth, ok := s.Subscriber(r.Host)
	if !ok {
		return nil, errClientNotSubscribed
	}

	outr := r.WithContext(r.Context())
	if r.ContentLength == 0 {
		outr.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	outr.Header = cloneHeader(r.Header)

	if auth != nil {
		user, password, _ := r.BasicAuth()
		if auth.User != user || auth.Password != password {
			return nil, errUnauthorised
		}
		outr.Header.Del("Authorization")
	}

	setXForwardedFor(outr.Header, r.RemoteAddr)

	scheme := r.URL.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = proto.HTTPS
		} else {
			scheme = proto.HTTP
		}
	}
	if r.Header.Get("X-Forwarded-Host") == "" {
		outr.Header.Set("X-Forwarded-Host", r.Host)
		outr.Header.Set("X-Forwarded-Proto", scheme)
	}

	msg := &proto.ControlMessage{
		Action:         proto.ActionProxy,
		ForwardedHost:  r.Host,
		ForwardedProto: scheme,
	}

	return s.proxyHTTP(identifier, outr, msg)
}

func (s *Server) proxyConn(identifier string, conn net.Conn, msg *proto.ControlMessage) error {
	s.logger.Log(
		"level", 2,
		"action", "proxy conn",
		"identifier", identifier,
		//		"name-id", s.idname,
		"ctrlMsg", msg,
	)

	defer conn.Close()

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	req, err := s.connectRequest(identifier, msg, pr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	done := make(chan struct{})
	go func() {
		transfer(pw, conn, log.NewContext(s.logger).With(
			"dir", "user to client",
			"dst", identifier,
			"src", conn.RemoteAddr(),
		))
		cancel()
		close(done)
	}()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("io error: %s", err)
	}
	defer resp.Body.Close()

	transfer(conn, resp.Body, log.NewContext(s.logger).With(
		"dir", "client to user",
		"dst", conn.RemoteAddr(),
		"src", identifier,
	))

	select {
	case <-done:
	case <-time.After(DefaultTimeout):
	}

	s.logger.Log(
		"level", 2,
		"action", "proxy conn done",
		"identifier", identifier,
		//		"name-id", s.idname,
		"ctrlMsg", msg,
	)

	return nil
}

func (s *Server) proxyHTTP(identifier string, r *http.Request, msg *proto.ControlMessage) (*http.Response, error) {
	s.logger.Log(
		"level", 2,
		"action", "proxy HTTP",
		"identifier", identifier,
		//		"name-id", s.idname,
		"ctrlMsg", msg,
	)

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	req, err := s.connectRequest(identifier, msg, pr)
	if err != nil {
		return nil, fmt.Errorf("proxy request error: %s", err)
	}

	go func() {
		cw := &countWriter{pw, 0}
		err := r.Write(cw)
		if err != nil {
			s.logger.Log(
				"level", 0,
				"msg", "proxy error",
				"identifier", identifier,
				//				"name-id", s.idname,
				"ctrlMsg", msg,
				"err", err,
			)
		}

		s.logger.Log(
			"level", 3,
			"action", "transferred",
			"identifier", identifier,
			//			"name-id", s.idname,
			"bytes", cw.count,
			"dir", "user to client",
			"dst", r.Host,
			"src", r.RemoteAddr,
		)

		if r.Body != nil {
			r.Body.Close()
		}
	}()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("io error: %s", err)
	}

	s.logger.Log(
		"level", 2,
		"action", "proxy HTTP done",
		"identifier", identifier,
		//		"name-id", s.idname,
		"ctrlMsg", msg,
		"status code", resp.StatusCode,
	)

	return resp, nil
}

// connectRequest creates HTTP request to client with a given identifier having
// control message and data input stream, output data stream results from
// response the created request.
func (s *Server) connectRequest(cname string, msg *proto.ControlMessage, r io.Reader) (*http.Request, error) {
	conid := s.registry.GetID(cname)
	req, err := http.NewRequest(http.MethodPut, s.connPool.URL(conid), r)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %s", err)
	}
	msg.WriteToHeader(req.Header)

	return req, nil
}

// Addr returns network address clients connect to.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop closes the server.
func (s *Server) Stop() {
	s.logger.Log(
		"level", 1,
		"action", "stop",
	)

	if s.listener != nil {
		s.listener.Close()
	}
}
