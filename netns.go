//go:build linux

package main

import (
	"net"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// dialerInNetns creates sockets inside a tunnel's network namespace while the
// SOCKS5 listener itself remains on the host loopback interface.
func dialerInNetns(nsName string) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			runtime.LockOSThread()

			origin, err := os.Open("/proc/self/ns/net")
			if err != nil {
				done <- result{err: err}
				return
			}
			defer origin.Close()
			target, err := os.Open("/var/run/netns/" + nsName)
			if err != nil {
				done <- result{err: err}
				return
			}
			defer target.Close()
			if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
				done <- result{err: err}
				return
			}

			conn, dialErr := net.Dial(forceIPv4Network(network), addr)
			if err := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET); err != nil {
				if conn != nil {
					_ = conn.Close()
				}
				done <- result{err: err}
				return
			}
			runtime.UnlockOSThread()
			done <- result{conn: conn, err: dialErr}
		}()
		r := <-done
		return r.conn, r.err
	}
}

func forceIPv4Network(network string) string {
	switch network {
	case "tcp":
		return "tcp4"
	case "udp":
		return "udp4"
	default:
		return network
	}
}
