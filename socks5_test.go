package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKSUDPDatagramIPv4RoundTrip(t *testing.T) {
	target := socksTarget{host: "1.1.1.1", port: 53}
	payload := []byte{0x12, 0x34, 0x01, 0x00}
	packet, err := buildSOCKSUDPDatagram(target, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotTarget, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("round trip mismatch: target=%#v payload=%x", gotTarget, gotPayload)
	}
}

func TestSOCKSUDPDatagramDomainRoundTrip(t *testing.T) {
	target := socksTarget{host: "dns.example", port: 5353}
	payload := []byte("query")
	packet, err := buildSOCKSUDPDatagram(target, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotTarget, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("round trip mismatch: target=%#v payload=%q", gotTarget, gotPayload)
	}
}

func TestSOCKSUDPDatagramRejectsFragment(t *testing.T) {
	fragment := []byte{0, 0, 1, addrIPv4, 1, 1, 1, 1, 0, 53}
	if _, _, err := parseSOCKSUDPDatagram(fragment); !errors.Is(err, errUDPFragment) {
		t.Fatalf("fragment error = %v", err)
	}
}

func TestSOCKSUDPDatagramIPv6RoundTrip(t *testing.T) {
	target := socksTarget{host: "2001:4860:4860::8888", port: 53}
	payload := []byte{0x12, 0x34, 0x01, 0x00}
	packet, err := buildSOCKSUDPDatagram(target, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotTarget, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("round trip mismatch: target=%#v payload=%x", gotTarget, gotPayload)
	}
}

func TestSOCKSUDPAssociateEndToEnd(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, 2048)
		size, source, readErr := echo.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = echo.WriteToUDP(buffer[:size], source)
		}
	}()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			serveSOCKS(conn, net.Dial)
		}
	}()

	control, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{socksVersion5, 1, authNone}); err != nil {
		t.Fatal(err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(control, authReply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authReply, []byte{socksVersion5, authNone}) {
		t.Fatalf("unexpected auth reply: %x", authReply)
	}

	request := []byte{socksVersion5, cmdUDP, 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := control.Write(request); err != nil {
		t.Fatal(err)
	}
	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(control, replyHead); err != nil {
		t.Fatal(err)
	}
	if replyHead[0] != socksVersion5 || replyHead[1] != replyOK {
		t.Fatalf("UDP associate rejected: %x", replyHead)
	}
	relayTarget, err := readSOCKSTarget(control, replyHead[3])
	if err != nil {
		t.Fatal(err)
	}
	if relayTarget.host != "127.0.0.1" || relayTarget.port == 0 {
		t.Fatalf("unsafe or invalid relay address: %#v", relayTarget)
	}

	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(3 * time.Second))
	echoAddress := echo.LocalAddr().(*net.UDPAddr)
	echoTarget := socksTarget{host: echoAddress.IP.String(), port: uint16(echoAddress.Port)}
	payload := []byte("mobile-dns-over-hy2")
	packet, err := buildSOCKSUDPDatagram(echoTarget, payload)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress, err := net.ResolveUDPAddr("udp4", relayTarget.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpClient.WriteToUDP(packet, relayAddress); err != nil {
		t.Fatal(err)
	}

	response := make([]byte, 2048)
	size, _, err := udpClient.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	responseTarget, responsePayload, err := parseSOCKSUDPDatagram(response[:size])
	if err != nil {
		t.Fatal(err)
	}
	if responseTarget != echoTarget {
		t.Fatalf("response target = %#v, want %#v", responseTarget, echoTarget)
	}
	if !bytes.Equal(responsePayload, payload) {
		t.Fatalf("response payload = %q, want %q", responsePayload, payload)
	}

	_ = control.Close()
	_ = echo.Close()
	<-echoDone
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS5 UDP association did not close with its TCP control connection")
	}
}

func TestSOCKSUDPEncodingUsesNetworkByteOrder(t *testing.T) {
	packet, err := buildSOCKSUDPDatagram(socksTarget{host: "8.8.8.8", port: 0x1234}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(packet[len(packet)-2:]); got != 0x1234 {
		t.Fatalf("port = %#x", got)
	}
}

func TestSOCKSUDPAssociateBridgesMobileDNSOverTCP(t *testing.T) {
	dnsListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsListener.Close()
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		conn, acceptErr := dnsListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		length := make([]byte, 2)
		if _, readErr := io.ReadFull(conn, length); readErr != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length))
		if _, readErr := io.ReadFull(conn, query); readErr != nil {
			return
		}
		response := append([]byte(nil), query...)
		response[2] |= 0x80
		frame := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(response)))
		copy(frame[2:], response)
		_, _ = conn.Write(frame)
	}()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			serveSOCKS(conn, func(network, address string) (net.Conn, error) {
				if network != "tcp" {
					return nil, errors.New("DNS bridge unexpectedly used UDP")
				}
				if address != "1.1.1.1:53" {
					return nil, errors.New("private mobile DNS was not replaced by a public IPv4 fallback")
				}
				return net.Dial("tcp4", dnsListener.Addr().String())
			})
		}
	}()

	control, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{socksVersion5, 1, authNone}); err != nil {
		t.Fatal(err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(control, authReply); err != nil {
		t.Fatal(err)
	}
	request := []byte{socksVersion5, cmdUDP, 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := control.Write(request); err != nil {
		t.Fatal(err)
	}
	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(control, replyHead); err != nil {
		t.Fatal(err)
	}
	relayTarget, err := readSOCKSTarget(control, replyHead[3])
	if err != nil {
		t.Fatal(err)
	}

	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(3 * time.Second))
	relayAddress, err := net.ResolveUDPAddr("udp4", relayTarget.String())
	if err != nil {
		t.Fatal(err)
	}
	originalTarget := socksTarget{host: "192.168.1.1", port: 53}
	query := []byte{
		0x61, 0x7a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	packet, err := buildSOCKSUDPDatagram(originalTarget, query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpClient.WriteToUDP(packet, relayAddress); err != nil {
		t.Fatal(err)
	}
	responsePacket := make([]byte, 2048)
	size, _, err := udpClient.ReadFromUDP(responsePacket)
	if err != nil {
		t.Fatal(err)
	}
	responseTarget, response, err := parseSOCKSUDPDatagram(responsePacket[:size])
	if err != nil {
		t.Fatal(err)
	}
	if responseTarget != originalTarget {
		t.Fatalf("response target = %#v, want original %#v", responseTarget, originalTarget)
	}
	if len(response) != len(query) || response[0] != query[0] || response[1] != query[1] ||
		response[2]&0x80 == 0 {
		t.Fatalf("invalid bridged DNS response: %x", response)
	}

	_ = control.Close()
	<-dnsDone
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS5 DNS association did not close")
	}
}
