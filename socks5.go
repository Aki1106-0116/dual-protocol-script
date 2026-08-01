package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion5 = 0x05
	authNone      = 0x00
	authReject    = 0xff
	cmdConnect    = 0x01
	cmdUDP        = 0x03
	addrIPv4      = 0x01
	addrDomain    = 0x03
	addrIPv6      = 0x04
	replyOK       = 0x00
	replyGeneral  = 0x01
	replyHost     = 0x04
	replyCommand  = 0x07
	replyAddress  = 0x08

	udpPeerLimit   = 256
	udpIdleTimeout = 2 * time.Minute
	udpIOTimeout   = 10 * time.Second
	dnsTCPTimeout  = 4 * time.Second
	dnsConcurrency = 64
)

var (
	errCommandUnsupported = errors.New("不支持该 SOCKS5 命令")
	errAddressUnsupported = errors.New("VPN Gate 隧道只提供 IPv4")
	errUDPFragment        = errors.New("不支持 SOCKS5 UDP 分片")
	dnsFallbackTargets    = []socksTarget{
		{host: "1.1.1.1", port: 53},
		{host: "8.8.8.8", port: 53},
		{host: "9.9.9.9", port: 53},
	}
)

type socksTarget struct {
	host string
	port uint16
}

func (t socksTarget) String() string {
	return net.JoinHostPort(t.host, strconv.Itoa(int(t.port)))
}

// serveSOCKS supports both TCP CONNECT and UDP ASSOCIATE. The TCP control
// listener and every UDP relay are bound to 127.0.0.1, while dial creates the
// destination sockets inside the selected VPN Gate network namespace.
func serveSOCKS(client net.Conn, dial func(network, addr string) (net.Conn, error)) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	if err := socksHandshake(client); err != nil {
		return
	}
	command, target, err := socksRequest(client)
	if err != nil {
		switch {
		case errors.Is(err, errCommandUnsupported):
			_ = socksReply(client, replyCommand, nil)
		case errors.Is(err, errAddressUnsupported):
			_ = socksReply(client, replyAddress, nil)
		default:
			_ = socksReply(client, replyGeneral, nil)
		}
		return
	}

	switch command {
	case cmdConnect:
		serveSOCKSConnect(client, target, dial)
	case cmdUDP:
		serveSOCKSUDP(client, dial)
	default:
		_ = socksReply(client, replyCommand, nil)
	}
}

func serveSOCKSConnect(client net.Conn, target socksTarget, dial func(network, addr string) (net.Conn, error)) {
	if ip := net.ParseIP(target.host); ip != nil && ip.To4() == nil {
		_ = socksReply(client, replyAddress, nil)
		return
	}
	remote, err := dial("tcp", target.String())
	if err != nil {
		_ = socksReply(client, replyHost, nil)
		return
	}
	defer remote.Close()
	if err := socksReply(client, replyOK, nil); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	relay(client, remote)
}

func serveSOCKSUDP(client net.Conn, dial func(network, addr string) (net.Conn, error)) {
	udpRelay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = socksReply(client, replyGeneral, nil)
		return
	}
	association := &socksUDPAssociation{
		relay:    udpRelay,
		dial:     dial,
		peers:    make(map[string]*socksUDPPeer),
		dnsSlots: make(chan struct{}, dnsConcurrency),
	}
	if err := socksReply(client, replyOK, udpRelay.LocalAddr()); err != nil {
		association.close()
		return
	}

	_ = client.SetDeadline(time.Time{})
	runDone := make(chan struct{})
	go func() {
		association.run()
		close(runDone)
	}()

	// RFC 1928 ties the UDP relay lifetime to this TCP control connection.
	_, _ = io.Copy(io.Discard, client)
	association.close()
	<-runDone
}

func socksHandshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != socksVersion5 {
		return errors.New("不是 SOCKS5")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == authNone {
			_, err := conn.Write([]byte{socksVersion5, authNone})
			return err
		}
	}
	_, _ = conn.Write([]byte{socksVersion5, authReject})
	return errors.New("客户端未提供无认证方式")
}

func socksRequest(conn net.Conn) (byte, socksTarget, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, socksTarget{}, err
	}
	if head[0] != socksVersion5 || head[2] != 0 {
		return 0, socksTarget{}, errors.New("SOCKS5 请求头无效")
	}
	if head[1] != cmdConnect && head[1] != cmdUDP {
		return 0, socksTarget{}, errCommandUnsupported
	}
	target, err := readSOCKSTarget(conn, head[3])
	if err != nil {
		return 0, socksTarget{}, err
	}
	return head[1], target, nil
}

func readSOCKSTarget(reader io.Reader, addressType byte) (socksTarget, error) {
	var host string
	switch addressType {
	case addrIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(raw).String()
	case addrIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(raw).String()
	case addrDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return socksTarget{}, err
		}
		if length[0] == 0 {
			return socksTarget{}, errors.New("SOCKS5 域名为空")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return socksTarget{}, err
		}
		host = string(raw)
	default:
		return socksTarget{}, fmt.Errorf("%w: 未知 SOCKS5 地址类型 %d", errAddressUnsupported, addressType)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return socksTarget{}, err
	}
	return socksTarget{host: host, port: binary.BigEndian.Uint16(portBytes)}, nil
}

func socksReply(conn net.Conn, code byte, bound net.Addr) error {
	target := socksTarget{host: "0.0.0.0"}
	if bound != nil {
		host, portText, err := net.SplitHostPort(bound.String())
		if err != nil {
			return err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return err
		}
		target = socksTarget{host: host, port: uint16(port)}
	}
	address, err := encodeSOCKSTarget(target)
	if err != nil {
		return err
	}
	reply := append([]byte{socksVersion5, code, 0}, address...)
	_, err = conn.Write(reply)
	return err
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

type socksUDPAssociation struct {
	relay *net.UDPConn
	dial  func(network, addr string) (net.Conn, error)

	mu       sync.Mutex
	client   *net.UDPAddr
	peers    map[string]*socksUDPPeer
	dnsSlots chan struct{}
	closed   bool
	closeOne sync.Once
}

type socksUDPPeer struct {
	key      string
	conn     net.Conn
	response socksTarget
	owner    *socksUDPAssociation
}

func (a *socksUDPAssociation) run() {
	buffer := make([]byte, 65535)
	for {
		size, source, err := a.relay.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !source.IP.IsLoopback() || !a.acceptClient(source) {
			continue
		}
		target, payload, err := parseSOCKSUDPDatagram(buffer[:size])
		if err != nil {
			continue
		}
		if target.port == 53 {
			// Android/v2rayNG commonly sends classic UDP DNS through the proxy.
			// A number of volunteer VPN Gate exits drop UDP/53 even though TCP
			// traffic works. Carry the same DNS message over TCP through the
			// selected netns and return a normal SOCKS5 UDP response.
			select {
			case a.dnsSlots <- struct{}{}:
				go func(target socksTarget, payload []byte) {
					defer func() { <-a.dnsSlots }()
					a.relayDNSOverTCP(target, payload)
				}(target, append([]byte(nil), payload...))
			default:
				// Bound outstanding TCP DNS work for a local client that floods
				// unique requests. Android will retry a dropped query.
			}
			continue
		}
		peer, err := a.peerFor(target)
		if err != nil {
			continue
		}
		_ = peer.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		_ = peer.conn.SetWriteDeadline(time.Now().Add(udpIOTimeout))
		if _, err := peer.conn.Write(payload); err != nil {
			a.removePeer(peer)
		}
	}
}

func (a *socksUDPAssociation) relayDNSOverTCP(original socksTarget, query []byte) {
	if len(query) < 12 || len(query) > 65535 || query[2]&0x80 != 0 {
		return
	}
	for _, upstream := range dnsTCPUpstreams(original) {
		response, err := exchangeDNSOverTCP(a.dial, upstream, query)
		if err != nil {
			continue
		}
		packet, err := buildSOCKSUDPDatagram(original, response)
		if err != nil {
			return
		}
		client := a.clientAddr()
		if client == nil {
			return
		}
		_ = a.relay.SetWriteDeadline(time.Now().Add(udpIOTimeout))
		_, _ = a.relay.WriteToUDP(packet, client)
		return
	}
}

func dnsTCPUpstreams(original socksTarget) []socksTarget {
	result := make([]socksTarget, 0, 1+len(dnsFallbackTargets))
	ip := net.ParseIP(original.host)
	if ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
		result = append(result, original)
	}
	for _, fallback := range dnsFallbackTargets {
		duplicate := false
		for _, existing := range result {
			if existing == fallback {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, fallback)
		}
	}
	return result
}

func exchangeDNSOverTCP(
	dial func(network, addr string) (net.Conn, error),
	target socksTarget,
	query []byte,
) ([]byte, error) {
	conn, err := dial("tcp", target.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsTCPTimeout))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if err := writeAll(conn, frame); err != nil {
		return nil, err
	}

	length := make([]byte, 2)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 12 {
		return nil, errors.New("DNS TCP 响应过短")
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	if response[0] != query[0] || response[1] != query[1] || response[2]&0x80 == 0 {
		return nil, errors.New("DNS TCP 响应与请求不匹配")
	}
	return response, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		data = data[written:]
	}
	return nil
}

func (a *socksUDPAssociation) acceptClient(source *net.UDPAddr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	if a.client == nil {
		a.client = cloneUDPAddr(source)
		return true
	}
	return a.client.Port == source.Port && a.client.IP.Equal(source.IP)
}

func (a *socksUDPAssociation) peerFor(target socksTarget) (*socksUDPPeer, error) {
	if ip := net.ParseIP(target.host); ip != nil && ip.To4() == nil {
		return nil, errAddressUnsupported
	}
	key := target.String()
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, net.ErrClosed
	}
	if peer := a.peers[key]; peer != nil {
		a.mu.Unlock()
		return peer, nil
	}
	if len(a.peers) >= udpPeerLimit {
		a.mu.Unlock()
		return nil, errors.New("SOCKS5 UDP 会话目标过多")
	}
	a.mu.Unlock()

	conn, err := a.dial("udp", key)
	if err != nil {
		return nil, err
	}
	response := target
	if resolved, ok := targetFromAddr(conn.RemoteAddr()); ok {
		response = resolved
	}
	peer := &socksUDPPeer{key: key, conn: conn, response: response, owner: a}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if existing := a.peers[key]; existing != nil {
		a.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	a.peers[key] = peer
	a.mu.Unlock()
	go peer.readResponses()
	return peer, nil
}

func (p *socksUDPPeer) readResponses() {
	defer p.owner.removePeer(p)
	buffer := make([]byte, 65535)
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		size, err := p.conn.Read(buffer)
		if err != nil {
			return
		}
		packet, err := buildSOCKSUDPDatagram(p.response, buffer[:size])
		if err != nil {
			return
		}
		client := p.owner.clientAddr()
		if client == nil {
			continue
		}
		_ = p.owner.relay.SetWriteDeadline(time.Now().Add(udpIOTimeout))
		if _, err := p.owner.relay.WriteToUDP(packet, client); err != nil {
			return
		}
	}
}

func (a *socksUDPAssociation) clientAddr() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneUDPAddr(a.client)
}

func (a *socksUDPAssociation) removePeer(peer *socksUDPPeer) {
	a.mu.Lock()
	if a.peers[peer.key] == peer {
		delete(a.peers, peer.key)
	}
	a.mu.Unlock()
	_ = peer.conn.Close()
}

func (a *socksUDPAssociation) close() {
	a.closeOne.Do(func() {
		a.mu.Lock()
		a.closed = true
		peers := make([]*socksUDPPeer, 0, len(a.peers))
		for _, peer := range a.peers {
			peers = append(peers, peer)
		}
		a.peers = make(map[string]*socksUDPPeer)
		a.mu.Unlock()

		_ = a.relay.Close()
		for _, peer := range peers {
			_ = peer.conn.Close()
		}
	})
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	copyAddress := *address
	copyAddress.IP = append(net.IP(nil), address.IP...)
	return &copyAddress
}

func parseSOCKSUDPDatagram(packet []byte) (socksTarget, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return socksTarget{}, nil, errors.New("SOCKS5 UDP 数据头无效")
	}
	if packet[2] != 0 {
		return socksTarget{}, nil, errUDPFragment
	}
	target, consumed, err := parseSOCKSTargetBytes(packet[3:])
	if err != nil {
		return socksTarget{}, nil, err
	}
	return target, packet[3+consumed:], nil
}

func buildSOCKSUDPDatagram(target socksTarget, payload []byte) ([]byte, error) {
	address, err := encodeSOCKSTarget(target)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 3, 3+len(address)+len(payload))
	packet = append(packet, address...)
	packet = append(packet, payload...)
	return packet, nil
}

func parseSOCKSTargetBytes(data []byte) (socksTarget, int, error) {
	if len(data) < 1 {
		return socksTarget{}, 0, io.ErrUnexpectedEOF
	}
	index := 1
	var host string
	switch data[0] {
	case addrIPv4:
		if len(data) < index+net.IPv4len+2 {
			return socksTarget{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(data[index : index+net.IPv4len]).String()
		index += net.IPv4len
	case addrIPv6:
		if len(data) < index+net.IPv6len+2 {
			return socksTarget{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(data[index : index+net.IPv6len]).String()
		index += net.IPv6len
	case addrDomain:
		if len(data) < index+1 {
			return socksTarget{}, 0, io.ErrUnexpectedEOF
		}
		length := int(data[index])
		index++
		if length == 0 || len(data) < index+length+2 {
			return socksTarget{}, 0, io.ErrUnexpectedEOF
		}
		host = string(data[index : index+length])
		index += length
	default:
		return socksTarget{}, 0, fmt.Errorf("%w: 未知 SOCKS5 地址类型 %d", errAddressUnsupported, data[0])
	}
	port := binary.BigEndian.Uint16(data[index : index+2])
	index += 2
	return socksTarget{host: host, port: port}, index, nil
}

func encodeSOCKSTarget(target socksTarget) ([]byte, error) {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, target.port)
	if ip := net.ParseIP(target.host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return append(append([]byte{addrIPv4}, ipv4...), port...), nil
		}
		ipv6 := ip.To16()
		if ipv6 == nil {
			return nil, errAddressUnsupported
		}
		return append(append([]byte{addrIPv6}, ipv6...), port...), nil
	}
	if len(target.host) == 0 || len(target.host) > 255 {
		return nil, errors.New("SOCKS5 域名长度无效")
	}
	result := make([]byte, 0, 2+len(target.host)+2)
	result = append(result, addrDomain, byte(len(target.host)))
	result = append(result, target.host...)
	result = append(result, port...)
	return result, nil
}

func targetFromAddr(address net.Addr) (socksTarget, bool) {
	if address == nil {
		return socksTarget{}, false
	}
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return socksTarget{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return socksTarget{}, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return socksTarget{}, false
	}
	return socksTarget{host: ip.String(), port: uint16(port)}, true
}
