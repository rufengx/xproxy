package socks5

// Implement socks5 protocol.
// See: socks5 protocol RFC.
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt

const (
	// socks protocol version.
	SocksVer = 0x05

	MethodNoAuthRequired = 0x00
)

type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1 to 255 bytes
}

type NegotiationReply struct {
	Ver     byte
	Methods byte
}
