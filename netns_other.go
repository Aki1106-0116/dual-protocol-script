//go:build !linux

package main

import (
	"fmt"
	"net"
)

func dialerInNetns(_ string) func(network, addr string) (net.Conn, error) {
	return func(_, _ string) (net.Conn, error) {
		return nil, fmt.Errorf("dual-protocol-script netns is only supported on Linux")
	}
}
