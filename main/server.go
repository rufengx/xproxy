package main

import (
	"xproxy/socks5"
)

func main() {
	socks5.Debug = true
	server, err := socks5.NewServer("127.0.0.1:8090", "", "admin", "admin", 120, 120, 120, 120)
	if nil != err {
		panic(err)
	}
	server.Run()
}
