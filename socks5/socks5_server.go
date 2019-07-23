package socks5

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

var (
	ErrServerClosed = errors.New("socks server closed")
)

type Server struct {
	// basic info
	Username string
	Password string

	ValidateMode    byte   // username/password or anonymous
	SupportCommands []byte // support client command ranges

	TCPAddr     *net.TCPAddr
	TCPDeadline int
	TCPTimeout  int

	UDPAddr     *net.UDPAddr
	UDPDeadline int
	UDPTimeout  int

	mu sync.Mutex

	// runtime info
	TCPListen *net.Listener
	UDPConn   *net.UDPConn

	doneChan chan struct{}
}

func NewSocks5Server(addr, ip, username, password string, tcpDeadline, tcpTimeout, udpDeadline, udpTimeout int) (*Server, error) {
	//_, port, err := net.SplitHostPort(addr)
	//if nil != err {
	//	return nil, err
	//}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if nil != err {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if nil != err {
		return nil, err
	}

	validateMode := MethodNoAuthRequired
	if "" != username && "" != password {
		validateMode = MethodUsernamePassword
	}

	return &Server{
		Username:        username,
		Password:        password,
		ValidateMode:    validateMode,
		SupportCommands: []byte{CMDConnect, CMDUDPAssociate},

		TCPAddr:     tcpAddr,
		TCPDeadline: tcpDeadline,
		TCPTimeout:  tcpTimeout,

		UDPAddr:     udpAddr,
		UDPDeadline: udpDeadline,
		UDPTimeout:  udpTimeout,

		mu: sync.Mutex{},
	}, nil
}

func (s *Server) Run() error {
	errch := make(chan error, 2)
	go func() {
		errch <- s.RunTCPServer()
	}()
	go func() {
		errch <- s.RunUDPServer()
	}()
	return <-errch
}

func (s *Server) RunTCPServer() error {
	tcpListener, err := net.ListenTCP("tcp", s.TCPAddr)
	if nil != err {
		return err
	}
	defer tcpListener.Close()

	var tempDelay time.Duration
	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if nil != err {
			select {
			case <-s.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("tcp server: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		go func(conn *net.TCPConn) {
			// TODO: ...
		}(tcpConn)
	}
	return nil
}

func (s *Server) RunUDPServer() error {
	return nil
}

func (s *Server) getDoneChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDoneChanLocked()
}

func (s *Server) getDoneChanLocked() chan struct{} {
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}
