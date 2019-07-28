package socks5

import (
	"bytes"
	"encoding/binary"
	"github.com/patrickmn/go-cache"
	"log"
	"net"
	"strconv"
	"time"
)

type Handler interface {
	TCPHandler(s *Server, conn *net.TCPConn, request *SocksRequest) error
	UDPHandler(s *Server, conn *net.UDPAddr, request *SocksUDPDatagram) error
}

type DefaultHandler struct {
}

func (h *DefaultHandler) TCPHandler(s *Server, conn *net.TCPConn, request *SocksRequest) error {
	reqCmd := request.CMD
	if CMDConnect == reqCmd {
		remoteTCPConn, err := h.establishTCPRemoteConn(request)
		if nil != err {
			// connection remote addr fail.
			reply := NewSocksReply(ReplyRemoteAddrConnFail, request.ATYP, []byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00})
			reply.WriteTo(conn)
			return err
		}
		defer remoteTCPConn.Close()

		// connection remote addr success, parse local connection address, tell to client.
		localAddr := remoteTCPConn.LocalAddr().String()
		atyp, lhost, lport, err := ParseAddress(localAddr)
		if nil != err {
			// connection remote addr fail.
			reply := NewSocksReply(ReplyRemoteAddrConnFail, request.ATYP, []byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00})
			reply.WriteTo(conn)
			return err
		} else {
			reply := NewSocksReply(ReplySuccess, atyp, lhost, lport)
			reply.WriteTo(conn)
		}

		// connection bridge
		// 1. read client request content, write to remote connection.
		go func() {
			var buff [1024 * 2]byte
			for {
				if s.TCPDeadline != 0 {
					if err := conn.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); nil != err {
						return
					}
				}
				offset, err := conn.Read(buff[:])
				if nil != err {
					return
				}

				if _, err := remoteTCPConn.Write(buff[0:offset]); nil != err {
					return
				}
			}
		}()

		// 2. read remote connection return content, write to client.
		go func() {
			var buff [1024 * 2]byte
			for {
				if s.TCPDeadline != 0 {
					if err := remoteTCPConn.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); nil != err {
						return
					}
				}
				offset, err := remoteTCPConn.Read(buff[:])
				if nil != err {
					return
				}

				if _, err := conn.Write(buff[0:offset]); nil != err {
					return
				}
			}
		}()
	}

	if CMDUDPAssociate == reqCmd {
		remoteUDPAddr, err := h.parseUDPRemoteAddr(request)
		if nil != err {
			reply := NewSocksReply(ReplyRemoteAddrConnFail, request.ATYP, []byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00})
			reply.WriteTo(conn)
			return err
		}

		// connection remote addr success, parse local connection address, tell to client.
		localAddr := s.UDPAddr.String()
		atyp, lhost, lport, err := ParseAddress(localAddr)
		if nil != err {
			// connection remote addr fail.
			reply := NewSocksReply(ReplyRemoteAddrConnFail, request.ATYP, []byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00})
			reply.WriteTo(conn)
			return err
		} else {
			reply := NewSocksReply(ReplySuccess, atyp, lhost, lport)
			reply.WriteTo(conn)
		}
		ch := make(chan byte)
		s.TCPUDPAssociate.Set(remoteUDPAddr.String(), ch, cache.DefaultExpiration)
		<-ch
		return nil
	}
	return ErrNonSupportCommand
}

func (h *DefaultHandler) UDPHandler(s *Server, conn *net.UDPAddr, request *SocksUDPDatagram) error {
	return ErrNonSupportCommand
}

// help func ===========================================================================================================
func (h *DefaultHandler) establishTCPRemoteConn(request *SocksRequest) (*net.TCPConn, error) {
	// gen connection address by request address type.
	var host string
	atyp := request.ATYP
	if ATYPDomain == atyp {
		host = bytes.NewBuffer(request.DstAddr[1:]).String()
	} else {
		host = net.IP(request.DstAddr).String()
	}
	// notes: CPU big-endian type.
	port := strconv.Itoa(int(binary.BigEndian.Uint16(request.DstPort)))
	addr := net.JoinHostPort(host, port)

	conn, err := net.Dial("tcp", addr)
	if nil != err {
		return nil, err
	}

	if Debug {
		log.Printf("TCP Handler. tcp remote conn established. addr: %s", addr)
	}
	return conn.(*net.TCPConn), nil
}

func (h *DefaultHandler) parseUDPRemoteAddr(request *SocksRequest) (*net.UDPAddr, error) {
	// gen connection address by request address type.
	var host string
	atyp := request.ATYP
	if ATYPDomain == atyp {
		host = bytes.NewBuffer(request.DstAddr[1:]).String()
	} else {
		host = net.IP(request.DstAddr).String()
	}
	// notes: CPU big-endian type.
	port := strconv.Itoa(int(binary.BigEndian.Uint16(request.DstPort)))
	addr := net.JoinHostPort(host, port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if nil != err {
		return nil, err
	}
	return udpAddr, nil
}
