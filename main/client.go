package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"xproxy/socks5"
)

func main() {
	socks5.Debug = true
	client, err := socks5.NewClient("admin", "admin", "127.0.0.1:8090", 120, 120, 120)
	if nil != err {
		panic(err)
	}
	err = client.Negotiation()
	if nil != err {
		panic(err)
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(80))
	request, err := socks5.NewSocksRequest(socks5.CMDConnect, socks5.ATYPDomain, []byte("www.baidu.com"), port)
	if nil != err {
		panic(err)
	}
	reply, err := client.Request(request)
	if nil != err {
		panic(err)
	}

	fmt.Println(net.IP(reply.BndAddr).String())
}
