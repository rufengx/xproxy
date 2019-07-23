package socks5

// Implement socks5 protocol.
// See: socks5 protocol RFC.
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt

const (
	// socks protocol version.
	SocksVer          byte = 0x05
	SocksReplySuccess byte = 0x00

	MethodNoAuthRequired   byte = 0x00
	MethodGSSAPI           byte = 0x01
	MethodUsernamePassword byte = 0x02
	// 0x03 to 0x7F IANA assigned.
	// 0x80 to 0xFE reserved for private methods.
	MethodNoAcceptableMethods byte = 0xFF

	// use in user negotiation stage.
	UsernamePasswordVer           byte = 0x01
	UsernamePasswordStatusSuccess byte = 0x00
	UsernamePasswordStatusFail    byte = 0x01

	CMDConnect      byte = 0x01
	CMDBind         byte = 0x02
	CMDUDPAssociate byte = 0x03

	ATYPIPv4   byte = 0x01
	ATYPDomain byte = 0x03
	ATYPIPv6   byte = 0x04
)

// NegotiationRequest is the negotiation request packet.
type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1 to 255 bytes
}

// NegotiationReply is the negotiation reply packet.
type NegotiationReply struct {
	Ver     byte
	Methods byte
}

// UsernamePasswordNegotiationRequest is the negotiation username/password request packet.
type UsernamePasswordNegotiationRequest struct {
	Ver      byte   // the Ver field contains the current version of the subnegotiation, which is 0x01.
	ULen     byte   // username length
	Uname    []byte // 1 to 255 bytes
	PLen     byte   // password length
	Password []byte // 1 to 255 bytes
}

// UsernamePasswordNegotiationReply is the negotiation username/password reply packet.
type UsernamePasswordNegotiationReply struct {
	Ver    byte
	Status byte // 0x00 indicates negotiation success.
}

// SocksRequest is the request packet.
type SocksRequest struct {
	Ver     byte   // socks protocol version: 0x05
	CMD     byte   // connect : 0x01, bind : 0x02, udp associate : 0x03
	RSV     byte   // reserved field, 0x00
	ATYP    byte   // address type, IPv4 : 0x01, domain name : 0x03, IPv6 : 0x04
	DstAddr []byte // desired destination address
	DstPort []byte // desired destination port in network octet order, it's 2 bytes.
}

// SocksReply is the reply packet.
type SocksReply struct {
	Ver     byte
	REP     byte
	RSV     byte   // 0x00
	ATYP    byte   // address type, IPv4 : 0x01, domain name : 0x03, IPv6 : 0x04
	BndAddr []byte // server bound address
	BndPort []byte // server bound port in network octet order, it's 2 bytes.
}

// SocksUDPDatagramRequest is the UDP packet.
type SocksUDPDatagramRequest struct {
	Ver     byte
	FRAG    byte   // current fragment number
	ATYP    byte   // address type, IP V4 : 0x01, domain name : 0x03, IP V6 : 0x04
	DstAddr []byte // desired destination address
	DstPort []byte // desired destination port in network octet order, it's 2 bytes.
	Data    []byte // user data
}
