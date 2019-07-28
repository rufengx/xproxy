package socks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

func ParseAddress(address string) (addrType byte, addr, port []byte, err error) {
	hostStr, portStr, err := net.SplitHostPort(address)
	if nil != err {
		return
	}

	// get address type.
	ip := net.ParseIP(hostStr)
	if ipv4 := ip.To4(); nil != ipv4 {
		addrType = ATYPIPv4
		addr = []byte(ipv4)
	} else if ipv6 := ip.To16(); nil != ipv6 {
		addrType = ATYPIPv6
		addr = []byte(ipv4)
	} else {
		addrType = ATYPDomain
		addr = []byte{byte(len(hostStr))}
		addr = append(addr, []byte(hostStr)...)
	}

	portInt, _ := strconv.Atoi(portStr)
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(portInt))
	return
}
