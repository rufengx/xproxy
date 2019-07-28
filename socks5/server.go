package socks5

import (
	"errors"
	"github.com/patrickmn/go-cache"
	"net"
	"sync"
)

var (
	ErrServerClosed       = errors.New("socks server closed")
	ErrUnamePasswdVersion = errors.New("invalid uname/passwd version")
	ErrBadRequest         = errors.New("bad request")
	ErrNonSupportCommand  = errors.New("nonsupport command")
)

type Server struct {
	// basic info
	Username string
	Password string

	AuthValidateMethod byte   // username/password or anonymous
	SupportCommands    []byte // support client command ranges

	TCPAddr     *net.TCPAddr
	TCPDeadline int
	TCPTimeout  int

	UDPAddr     *net.UDPAddr
	UDPDeadline int
	UDPTimeout  int

	mu sync.Mutex

	// runtime info
	TCPListen       *net.Listener
	UDPConn         *net.UDPConn
	Handler         Handler
	TCPUDPAssociate *cache.Cache

	doneChan chan struct{}
}

func NewServer(addr, ip, username, password string, tcpDeadline, tcpTimeout, udpDeadline, udpTimeout int) (*Server, error) {
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
		Username:           username,
		Password:           password,
		AuthValidateMethod: validateMode,
		SupportCommands:    []byte{CMDConnect, CMDUDPAssociate},

		TCPAddr:     tcpAddr,
		TCPDeadline: tcpDeadline,
		TCPTimeout:  tcpTimeout,

		UDPAddr:     udpAddr,
		UDPDeadline: udpDeadline,
		UDPTimeout:  udpTimeout,
		mu:          sync.Mutex{},
	}, nil
}

func (s *Server) Run() error {
	s.Handler = &DefaultHandler{}

	errch := make(chan error, 2)
	go func() {
		errch <- s.RunTCPServer()
	}()
	go func() {
		errch <- s.RunUDPServer()
	}()
	return <-errch
}

func (s *Server) Stop() {

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
