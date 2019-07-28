package socks5

import (
	"io"
	"log"
	"net"
	"strings"
	"time"
)

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
		go s.processTCPConn(tcpConn)
	}
	return nil
}

func (s *Server) processTCPConn(conn *net.TCPConn) {
	defer conn.Close()

	if s.TCPTimeout != 0 {
		if err := conn.SetKeepAlivePeriod(time.Duration(s.TCPTimeout) * time.Second); err != nil {
			log.Println(err)
			return
		}
	}

	if s.TCPDeadline != 0 {
		if err := conn.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
			log.Println(err)
			return
		}
	}

	// step 1: negotiation
	if err := s.negotiation(conn); nil != err {
		log.Println(err)
		return
	}

	// step 2: get request
	request, err := s.parseRequest(conn)
	if nil != err {
		log.Println(err)
		return
	}

	// step 3: process
	if err := s.Handler.TCPHandler(s, conn, request); nil != err {
		log.Println(err)
		return
	}
}

func (s *Server) negotiation(conn *net.TCPConn) error {
	negotiationRequest, err := ParseNegotiationRequest(conn)
	if nil != err {
		return err
	}

	isEqual := false
	for _, method := range negotiationRequest.Methods {
		if s.AuthValidateMethod == method {
			isEqual = true
			break
		}
	}

	// step 1: check client negotiation method.
	if !isEqual {
		reply := NewNegotiationReply(MethodNoAcceptableMethods)
		if err := reply.WriteTo(conn); nil != err {
			return err
		}
	}

	// step 2: agree client authentication
	reply := NewNegotiationReply(s.AuthValidateMethod)
	if err := reply.WriteTo(conn); nil != err {
		return err
	}

	// step 3: wait receive client username/password
	if s.AuthValidateMethod == MethodUsernamePassword {
		request, err := ParseUnamePasswdNegotiationRequest(conn)
		if nil != err {
			return err
		}
		// sample validate

		if !strings.EqualFold(s.Username, string(request.Uname)) || !strings.EqualFold(s.Password, string(request.Password)) {
			if Debug {
				log.Printf("server receive uname: '%s', passwd: '%s' \n", string(request.Uname), string(request.Password))
				log.Printf("server set uname: '%s', passwd: '%s' \n", s.Username, s.Password)
			}
			failReply := NewUserPassNegotiationReply(UsernamePasswordStatusFail)
			if err := failReply.WriteTo(conn); nil != err {
				return err
			}
			return nil
		}
		successReply := NewUserPassNegotiationReply(UsernamePasswordStatusSuccess)
		if err := successReply.WriteTo(conn); nil != err {
			return err
		}
	}
	return nil
}

func (s *Server) parseRequest(conn *net.TCPConn) (*SocksRequest, error) {
	request, err := ParseSocksRequest(conn)
	if nil != err {
		return nil, err
	}

	isSupport := false
	for _, command := range s.SupportCommands {
		if request.CMD == command {
			isSupport = true
			break
		}
	}

	if !isSupport {
		reply := NewSocksReply(ReplyCommandNonSupport, request.ATYP, request.DstAddr, request.DstPort)
		if err := reply.WriteTo(conn); nil != err {
			return nil, err
		}
		return nil, ErrNonSupportCommand
	}
	return request, nil
}

// help func ===========================================================================================================

// 1. parse negotiation request
func ParseNegotiationRequest(conn *net.TCPConn) (*NegotiationRequest, error) {
	body := make([]byte, 2)
	if _, err := io.ReadFull(conn, body); nil != err {
		return nil, err
	}

	if SocksVer != body[0] {
		return nil, ErrNonSupportCurrentSocksProtocolVersion
	}

	nmethos := uint(body[1])
	methods := make([]byte, nmethos)
	if _, err := io.ReadFull(conn, methods); nil != err {
		return nil, err
	}

	if Debug {
		log.Printf("Received NegotiationReply: socks protocol version: %#v, nmethods: %#v, methods: %#v \n", body[0], body[1], methods)
	}

	return &NegotiationRequest{
		Ver:      body[0],
		NMethods: body[1],
		Methods:  methods,
	}, nil
}

// 2. negotiation reply.
func NewNegotiationReply(method byte) *NegotiationReply {
	return &NegotiationReply{
		Ver:    SocksVer,
		Method: method,
	}
}

func (r *NegotiationReply) WriteTo(w *net.TCPConn) error {
	if _, err := w.Write([]byte{r.Ver, r.Method}); err != nil {
		return err
	}
	if Debug {
		log.Printf("Sent NegotiationReply: %#v %#v\n", r.Ver, r.Method)
	}
	return nil
}

// 3. parse username/password negotiation request
func ParseUnamePasswdNegotiationRequest(conn *net.TCPConn) (*UsernamePasswordNegotiationRequest, error) {
	body := make([]byte, 2)
	if _, err := io.ReadFull(conn, body); nil != err {
		return nil, err
	}

	// validate username/password version
	if UsernamePasswordVer != body[0] {
		return nil, ErrUnamePasswdVersion
	}

	ulen := uint8(body[1])
	if ulen == 0 {
		return nil, ErrBadRequest
	}

	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); nil != err {
		return nil, err
	}

	plenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenByte); nil != err {
		return nil, err
	}
	plen := uint8(plenByte[0])
	if plen == 0 {
		return nil, ErrBadRequest
	}

	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); nil != err {
		return nil, err
	}

	if Debug {
		log.Printf("Parse UnamePasswdNegotiationRequest: uname/passwd version: %#v, ulen: %#v, uname: %#v, plen: %#v, passwd: %#v \n", body[0], ulen, uname, plen, passwd)
	}
	return &UsernamePasswordNegotiationRequest{
		Ver:      body[0],
		ULen:     ulen,
		Uname:    uname,
		PLen:     plen,
		Password: passwd,
	}, nil
}

// 4. username/password negotiation reply
func NewUserPassNegotiationReply(status byte) *UsernamePasswordNegotiationReply {
	return &UsernamePasswordNegotiationReply{
		Ver:    UsernamePasswordVer,
		Status: status,
	}
}

func (r *UsernamePasswordNegotiationReply) WriteTo(w *net.TCPConn) error {
	if _, err := w.Write([]byte{r.Ver, r.Status}); err != nil {
		return err
	}
	if Debug {
		log.Printf("Sent UserPassNegotiationReply: %#v %#v \n", r.Ver, r.Status)
	}
	return nil
}

// 5. parse socks request
func ParseSocksRequest(conn *net.TCPConn) (*SocksRequest, error) {
	body := make([]byte, 4)
	if _, err := io.ReadFull(conn, body); nil != err {
		return nil, err
	}

	if SocksVer != body[0] {
		return nil, ErrNonSupportCurrentUnamePasswdVersion
	}

	addrType := body[3]
	var addr []byte
	if addrType == ATYPIPv4 {
		// the address is a version-4 IP address, with a length of 4 octets.
		addr = make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); nil != err {
			return nil, err
		}
	} else if addrType == ATYPDomain {
		// the address field contains a fully-qualified domain name.  The first
		// octet of the address field contains the number of octets of name that
		// follow, there is no terminating NUL octet.
		addrLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, addrLen); nil != err {
			return nil, err
		}
		if addrLen[0] == 0 {
			return nil, ErrBadRequest
		}
		// first byte is domain length.
		addr = make([]byte, uint(addrLen[0]))
		if _, err := io.ReadFull(conn, addr); nil != err {
			return nil, err
		}
		addr = append(addrLen, addr...)
	} else if addrType == ATYPIPv6 {
		// the address is a version-6 IP address, with a length of 16 octets.
		addr = make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); nil != err {
			return nil, err
		}
	} else {
		return nil, ErrBadRequest
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); nil != err {
		return nil, err
	}

	if Debug {
		log.Printf("Server receive socks request, socks protocol version: %#v, cmd: %#v, atyp: %#v, dstAddr: %#v, dstPort: %#v \n", body[0], body[1], addrType, addr, port)
	}

	return &SocksRequest{
		Ver:     body[0],
		CMD:     body[1],
		RSV:     body[2],
		ATYP:    addrType,
		DstAddr: addr,
		DstPort: port,
	}, nil
}

// 6. socks reply
func NewSocksReply(rep byte, atyp byte, bndaddr []byte, bndport []byte) *SocksReply {
	if atyp == ATYPDomain {
		bndaddr = append([]byte{byte(len(bndaddr))}, bndaddr...)
	}
	return &SocksReply{
		Ver:     SocksVer,
		REP:     rep,
		RSV:     0x00,
		ATYP:    atyp,
		BndAddr: bndaddr,
		BndPort: bndport,
	}
}

func (r *SocksReply) WriteTo(conn *net.TCPConn) error {
	if _, err := conn.Write([]byte{r.Ver, r.REP, r.RSV, r.ATYP}); err != nil {
		return err
	}
	if _, err := conn.Write(r.BndAddr); err != nil {
		return err
	}
	if _, err := conn.Write(r.BndPort); err != nil {
		return err
	}
	if Debug {
		log.Printf("Sent Reply: %#v %#v %#v %#v %#v %#v\n", r.Ver, r.REP, r.RSV, r.ATYP, r.BndAddr, r.BndPort)
	}
	return nil
}
