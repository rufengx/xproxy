package socks5

import (
	"errors"
	"io"
	"log"
	"net"
	"time"
)

var (
	ErrNonSupportCurrentMethod               = errors.New("nonsupport current method")
	ErrNonSupportCurrentSocksProtocolVersion = errors.New("nonsupport current socks protocol version")
	ErrUnameOrPasswdTooLength                = errors.New("username or password too length")
	ErrNonSupportCurrentUnamePasswdVersion   = errors.New("nonsupport current username/password version")
	ErrUnameOrPasswdError                    = errors.New("invalid username or password")
	ErrBadReply                              = errors.New("bad reply")
	ErrRequestFail                           = errors.New("socks client request fail")
)

// it's a socks5 client wrapper
type Client struct {
	Username string
	Password string

	DstTCPAddr  *net.TCPAddr
	DstTCPConn  *net.TCPConn
	TCPDeadline int
	TCPTimeout  int

	DstUDPAddr  *net.UDPAddr
	UDPDeadline int
}

func NewClient(username, password, addr string, tcpTimeout, tcpDeadline, udpDeadline int) (*Client, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if nil != err {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if nil != err {
		return nil, err
	}

	client := &Client{
		Username:    username,
		Password:    password,
		DstTCPAddr:  tcpAddr,
		TCPTimeout:  tcpTimeout,
		TCPDeadline: tcpDeadline,

		DstUDPAddr:  udpAddr,
		UDPDeadline: udpDeadline,
	}
	return client, nil
}

func (c *Client) Negotiation() error {
	// step 1: prepare stage.
	conn, err := net.Dial("tcp", c.DstTCPAddr.String())
	if nil != err {
		return err
	}
	c.DstTCPConn = conn.(*net.TCPConn)

	if c.TCPTimeout != 0 {
		c.DstTCPConn.SetKeepAlivePeriod(time.Duration(c.TCPTimeout) * time.Second)
	}

	if c.TCPDeadline != 0 {
		if err := c.DstTCPConn.SetDeadline(time.Now().Add(time.Duration(c.TCPDeadline) * time.Second)); nil != err {
			return err
		}
	}

	// step 2: first negotiation.
	// tell proxy server, current used socks protocol version and next action.
	method := MethodNoAcceptableMethods
	if c.Username != "" && c.Password != "" {
		method = MethodUsernamePassword
	}

	negotiationRequest := NewNegotiationRequest([]byte{method})
	if err := negotiationRequest.WriteTo(c.DstTCPConn); nil != err {
		return err
	}

	// step 3: read proxy server reply.
	// proxy server return expect socks protocol version and next action.
	negotiationReply, err := ParseNegotiationReply(c.DstTCPConn)
	if nil != err {
		return err
	}

	// step 4: authorization validate
	if negotiationReply.Method != method {
		return ErrNonSupportCurrentMethod
	}

	if method == MethodUsernamePassword {
		negotiationAuthRequest, err := NewUsernamePasswordNegotiationRequest(c.Username, c.Password)
		if nil != err {
			return err
		}
		if err := negotiationAuthRequest.WriteTo(c.DstTCPConn); nil != err {
			return err
		}
		authReply, err := NewUsernamePasswordNegotiationReply(c.DstTCPConn)
		if nil != err {
			return err
		}
		if authReply.Status != UsernamePasswordStatusSuccess {
			return ErrUnameOrPasswdError
		}
	}
	return nil
}

func (c *Client) Request(request *SocksRequest) (*SocksReply, error) {
	if err := request.WriteTo(c.DstTCPConn); nil != err {
		return nil, err
	}

	socksReply, err := ParseSocksReply(c.DstTCPConn)
	if nil != err {
		return nil, err
	}

	if socksReply.REP != SocksReplySuccess {
		return nil, ErrRequestFail
	}
	return socksReply, nil
}

// help func ===========================================================================================================

// 1. negotiation request
func NewNegotiationRequest(methods []byte) *NegotiationRequest {
	return &NegotiationRequest{
		Ver:      SocksVer,
		NMethods: byte(len(methods)), // methods length
		Methods:  methods,
	}
}

func (request *NegotiationRequest) WriteTo(dstConn *net.TCPConn) error {
	if _, err := dstConn.Write([]byte{request.Ver}); nil != err {
		return err
	}

	if _, err := dstConn.Write([]byte{request.NMethods}); nil != err {
		return err
	}

	if _, err := dstConn.Write(request.Methods); nil != err {
		return err
	}

	if Debug {
		log.Printf("Sent NegotiationRequest: socks protocol version: %#v, nmethods: %#v, methods: %#v \n", request.Ver, request.NMethods, request.Methods)
	}
	return nil
}

// 2. parse negotiation reply
func ParseNegotiationReply(conn *net.TCPConn) (*NegotiationReply, error) {
	reply := make([]byte, 2) // according to socks protocol, it's only two bytes.
	if _, err := io.ReadFull(conn, reply); nil != err {
		return nil, err
	}

	if reply[0] != SocksVer {
		return nil, ErrNonSupportCurrentSocksProtocolVersion
	}

	if Debug {
		log.Printf("Received NegotiationReply: expect socks protocol version: %#v, methods: %#v \n", reply[0], reply[1])
	}

	return &NegotiationReply{
		Ver:    reply[0],
		Method: reply[1],
	}, nil
}

// 3. username/password negotiation request
func NewUsernamePasswordNegotiationRequest(username, password string) (*UsernamePasswordNegotiationRequest, error) {
	unameBytes := []byte(username)
	passwdBytes := []byte(password)

	ulen := len(unameBytes)
	plen := len(passwdBytes)
	if ulen > 255 || plen > 255 {
		return nil, ErrUnameOrPasswdTooLength
	}

	return &UsernamePasswordNegotiationRequest{
		Ver:      UsernamePasswordVer,
		ULen:     byte(ulen),
		Uname:    unameBytes,
		PLen:     byte(plen),
		Password: passwdBytes,
	}, nil
}

func (u *UsernamePasswordNegotiationRequest) WriteTo(dstConn *net.TCPConn) error {
	if _, err := dstConn.Write([]byte{u.Ver, u.ULen}); nil != err {
		return err
	}

	if _, err := dstConn.Write(u.Uname); nil != err {
		return err
	}

	if _, err := dstConn.Write([]byte{u.PLen}); nil != err {
		return err
	}

	if _, err := dstConn.Write(u.Password); nil != err {
		return err
	}

	if Debug {
		log.Printf("Sent UsernamePasswdNegotiationRequest: username/passed version: %#v, ulen: %#v, username: %#v, plen: %#v, passwd: %#v \n", u.Ver, u.ULen, u.Uname, u.PLen, u.Password)
	}
	return nil
}

// 4. username/password negotiation reply
func NewUsernamePasswordNegotiationReply(conn *net.TCPConn) (*UsernamePasswordNegotiationReply, error) {
	reply := make([]byte, 2) // according to socks protocol, it's only two bytes.
	if _, err := io.ReadFull(conn, reply); nil != err {
		return nil, err
	}

	if reply[0] != UsernamePasswordVer {
		return nil, ErrNonSupportCurrentUnamePasswdVersion
	}

	if Debug {
		log.Printf("Received UsernamePasswdNegotiationReply: expect username/password version: %#v, status: %#v \n", reply[0], reply[1])
	}

	return &UsernamePasswordNegotiationReply{
		Ver:    reply[0],
		Status: reply[1],
	}, nil
}

// 5. socks request
func NewSocksRequest(cmd, atyp byte, dstAddr, dstPort []byte) (*SocksRequest, error) {
	if len(dstAddr) == 0 || len(dstAddr) < 2 {
		return nil, ErrBadRequest
	}

	// first byte is domain length.
	if atyp == ATYPDomain {
		dstAddr = append([]byte{byte(len(dstAddr))}, dstAddr...)
	}
	return &SocksRequest{
		Ver:     SocksVer,
		CMD:     cmd,
		RSV:     0x00,
		ATYP:    atyp,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}, nil
}

func (r *SocksRequest) WriteTo(conn *net.TCPConn) error {
	if _, err := conn.Write([]byte{r.Ver, r.CMD, r.RSV, r.ATYP}); nil != err {
		return err
	}

	if _, err := conn.Write(r.DstAddr); nil != err {
		return err
	}

	if _, err := conn.Write(r.DstPort); nil != err {
		return err
	}

	if Debug {
		log.Printf("Client Sent Socks5Request: socks protocol version: %#v, cmd: %#v, atyp: %#v, dst_addr: %#v, dst_port: %#v \n", r.Ver, r.CMD, r.ATYP, r.DstAddr, r.DstPort)
	}
	return nil
}

// 6. parse socks reply
func ParseSocksReply(dstConn *net.TCPConn) (*SocksReply, error) {
	reply := make([]byte, 4) // every field 1 byte. VER, REP, RSV(resevred field), ATYP
	if _, err := io.ReadFull(dstConn, reply); nil != err {
		return nil, err
	}

	// validate socks protocol version
	if reply[0] != SocksVer {
		return nil, ErrNonSupportCurrentSocksProtocolVersion
	}

	// parse response packet
	var addr []byte
	atyp := reply[3]
	if atyp == ATYPIPv4 {
		addr = make([]byte, 4) // ip v4 address
		if _, err := io.ReadFull(dstConn, addr); nil != err {
			return nil, err
		}
	} else if atyp == ATYPDomain {
		addr = make([]byte, 16) // ip v6 address
		if _, err := io.ReadFull(dstConn, addr); nil != err {
			return nil, err
		}
	} else if atyp == ATYPIPv6 {
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(dstConn, domainLen); nil != err {
			return nil, err
		}

		if domainLen[0] == 0 {
			return nil, ErrBadReply
		}

		addr := make([]byte, int(domainLen[0]))
		if _, err := io.ReadFull(dstConn, addr); nil != err {
			return nil, err
		}
		addr = append(domainLen, addr...)
	} else {
		return nil, ErrBadReply
	}

	port := make([]byte, 2) // 0 ~ 65535, 2 bytes.
	if _, err := io.ReadFull(dstConn, port); nil != err {
		return nil, err
	}

	if Debug {
		log.Printf("Client Received SocksReply: socks protocol version: %#v, rep status: %#v, atyp: %#v, bind_address: %#v, bind_port: %#v \n", SocksVer, reply[1], atyp, addr, port)
	}

	return &SocksReply{
		Ver:     SocksVer,
		REP:     reply[1],
		RSV:     reply[2],
		ATYP:    atyp,
		BndAddr: addr,
		BndPort: port,
	}, nil
}
