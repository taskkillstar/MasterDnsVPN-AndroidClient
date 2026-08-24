package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
)

type FakeDNSProxy struct {
	RealSocksAddr string
	LocalPort     int
	dnsMap        *DNSMapper
	listener      net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func NewFakeDNSProxy(realSocksAddr string, dnsMap *DNSMapper) *FakeDNSProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &FakeDNSProxy{
		RealSocksAddr: realSocksAddr,
		dnsMap:        dnsMap,
		ctx:           ctx,
		cancel:        cancel,
	}
}

func (p *FakeDNSProxy) Start() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.listener = l
	p.LocalPort = l.Addr().(*net.TCPAddr).Port

	p.wg.Add(1)
	go p.acceptLoop()

	return l.Addr().String(), nil
}

func (p *FakeDNSProxy) Stop() {
	p.cancel()
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *FakeDNSProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			continue
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConnection(c)
		}(conn)
	}
}

func (p *FakeDNSProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read greeting
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Send auth response: NO_AUTH
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// Read request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]

	var targetAddr []byte
	if atyp == 1 { // IPV4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetAddr = ip
	} else if atyp == 3 { // DOMAIN
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return
		}
		targetAddr = append(l, dom...)
	} else if atyp == 4 { // IPV6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetAddr = ip
	}

	targetPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, targetPort); err != nil {
		return
	}

	// FakeDNS Interception for TCP CONNECT
	if cmd == 1 && atyp == 1 {
		ipStr := net.IP(targetAddr).String()
		if hostname, ok := p.dnsMap.GetHostname(ipStr); ok {
			atyp = 3
			l := byte(len(hostname))
			targetAddr = append([]byte{l}, []byte(hostname)...)
		}
	}

	if cmd == 3 { // UDP ASSOCIATE
		p.handleUDPAssociate(conn, atyp, targetAddr, targetPort)
		return
	}

	// Dial Real SOCKS
	realConn, err := net.Dial("tcp", p.RealSocksAddr)
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer realConn.Close()

	if _, err := realConn.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(realConn, authResp); err != nil {
		return
	}

	req := []byte{5, 1, 0, atyp}
	req = append(req, targetAddr...)
	req = append(req, targetPort...)
	if _, err := realConn.Write(req); err != nil {
		return
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(realConn, replyHeader); err != nil {
		return
	}
	if _, err := conn.Write(replyHeader); err != nil {
		return
	}

	var bndAddr []byte
	if replyHeader[3] == 1 {
		bndAddr = make([]byte, 4)
	} else if replyHeader[3] == 3 {
		l := make([]byte, 1)
		io.ReadFull(realConn, l)
		bndAddr = make([]byte, l[0])
		bndAddr = append(l, bndAddr...)
	} else if replyHeader[3] == 4 {
		bndAddr = make([]byte, 16)
	}
	if len(bndAddr) > 0 {
		io.ReadFull(realConn, bndAddr)
		conn.Write(bndAddr)
	}

	bndPort := make([]byte, 2)
	io.ReadFull(realConn, bndPort)
	conn.Write(bndPort)

	go io.Copy(realConn, conn)
	io.Copy(conn, realConn)
}

func (p *FakeDNSProxy) handleUDPAssociate(tcpConn net.Conn, atyp byte, targetAddr []byte, targetPort []byte) {
	realConn, err := net.Dial("tcp", p.RealSocksAddr)
	if err != nil {
		tcpConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer realConn.Close()

	if _, err := realConn.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(realConn, authResp); err != nil {
		return
	}

	req := []byte{5, 3, 0, atyp}
	req = append(req, targetAddr...)
	req = append(req, targetPort...)
	if _, err := realConn.Write(req); err != nil {
		return
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(realConn, replyHeader); err != nil {
		return
	}

	var bndAddr []byte
	if replyHeader[3] == 1 {
		bndAddr = make([]byte, 4)
	} else if replyHeader[3] == 3 {
		l := make([]byte, 1)
		io.ReadFull(realConn, l)
		dom := make([]byte, l[0])
		io.ReadFull(realConn, dom)
		bndAddr = append(l, dom...)
	} else if replyHeader[3] == 4 {
		bndAddr = make([]byte, 16)
	}
	if len(bndAddr) > 0 {
		io.ReadFull(realConn, bndAddr)
	}

	bndPortBuf := make([]byte, 2)
	io.ReadFull(realConn, bndPortBuf)

	var realUdpAddr *net.UDPAddr
	if replyHeader[3] == 1 {
		realUdpAddr = &net.UDPAddr{IP: net.IP(bndAddr), Port: int(binary.BigEndian.Uint16(bndPortBuf))}
	} else if replyHeader[3] == 4 {
		realUdpAddr = &net.UDPAddr{IP: net.IP(bndAddr), Port: int(binary.BigEndian.Uint16(bndPortBuf))}
	}
	if realUdpAddr != nil && realUdpAddr.IP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(p.RealSocksAddr)
		realUdpAddr.IP = net.ParseIP(host)
	}

	localUdp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tcpConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer localUdp.Close()

	localPort := localUdp.LocalAddr().(*net.UDPAddr).Port

	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, uint16(localPort))
	reply = append(reply, pBuf...)
	if _, err := tcpConn.Write(reply); err != nil {
		return
	}

	go func() {
		buf := make([]byte, 65535)
		var tun2socksAddr *net.UDPAddr
		for {
			n, rAddr, err := localUdp.ReadFromUDP(buf)
			if err != nil {
				return
			}

			if realUdpAddr != nil && rAddr.IP.Equal(realUdpAddr.IP) && rAddr.Port == realUdpAddr.Port {
				if tun2socksAddr != nil {
					localUdp.WriteToUDP(buf[:n], tun2socksAddr)
				}
				continue
			}

			tun2socksAddr = rAddr

			if n < 4 || buf[2] != 0 {
				continue
			}
			frag := buf[2]
			if frag != 0 {
				continue
			}

			atyp := buf[3]
			var offset int
			var tPort uint16

			if atyp == 1 {
				offset = 10
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[8:10])
			} else if atyp == 3 {
				l := int(buf[4])
				offset = 5 + l + 2
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[5+l : offset])
			} else if atyp == 4 {
				offset = 22
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[20:22])
			} else {
				continue
			}

			if tPort == 53 {
				// Plan 015: previously `append(buf[:offset], resp...)` reused
				// the receive buffer's backing array. On the next ReadFromUDP,
				// only `n` bytes overwrite buf, leaving stale response bytes
				// past `n` — parseDNSQuery then read corrupted offsets from
				// the previous iteration's reply. Build in a fresh slice.
				dnsQuery := make([]byte, n-offset)
				copy(dnsQuery, buf[offset:n])
				parsed, ok := parseDNSQuery(dnsQuery)
				if ok {
					var fakeIP string
					if parsed.qtype == dnsTypeA {
						fakeIP = p.dnsMap.GetFakeIP(parsed.hostname)
					}
					resp := buildDNSResponse(dnsQuery, parsed, fakeIP)
					if resp != nil {
						fullResp := make([]byte, 0, offset+len(resp))
						fullResp = append(fullResp, buf[:offset]...)
						fullResp = append(fullResp, resp...)
						localUdp.WriteToUDP(fullResp, rAddr)
					}
				}
				continue
			}

			// ponytail: non-DNS UDP (QUIC, etc.) dropped, not forwarded.
			// Upstream SOCKS5 UDP_ASSOCIATE rejects non-53 targets
			// (socks_manager.go:665), forwarding would close the association
			// and break subsequent DNS queries. Dropping lets the browser's
			// QUIC probe time out fast and fall back to TCP (issue #32).
		}
	}()

	// Keep TCP connection open
	io.Copy(io.Discard, tcpConn)
}

const (
	dnsTypeA   = 1
	dnsClassIN = 1
)

type dnsParsedQuery struct {
	hostname    string
	qtype       uint16
	qclass      uint16
	questionLen int // exact offset where the Question section ends (12 + len(QNAME) + 4)
}

func parseDNSQuery(query []byte) (dnsParsedQuery, bool) {
	if len(query) < 12 {
		return dnsParsedQuery{}, false
	}
	qdcount := binary.BigEndian.Uint16(query[4:6])
	if qdcount == 0 {
		return dnsParsedQuery{}, false
	}
	pos := 12
	labels := []string{}
	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			pos++ // consume terminating null byte
			break
		}
		if length > 63 || pos+1+length > len(query) {
			return dnsParsedQuery{}, false
		}
		pos++
		labels = append(labels, string(query[pos:pos+length]))
		pos += length
	}
	if len(labels) == 0 || pos+4 > len(query) {
		return dnsParsedQuery{}, false
	}
	qtype := binary.BigEndian.Uint16(query[pos : pos+2])
	qclass := binary.BigEndian.Uint16(query[pos+2 : pos+4])
	pos += 4

	return dnsParsedQuery{
		hostname:    strings.Join(labels, "."),
		qtype:       qtype,
		qclass:      qclass,
		questionLen: pos,
	}, true
}

func buildDNSResponse(query []byte, parsed dnsParsedQuery, fakeIP string) []byte {
	if len(query) < parsed.questionLen || parsed.questionLen < 12 {
		return nil
	}

	queryFlags := binary.BigEndian.Uint16(query[2:4])
	// Set QR=1 (response), AA=1 (Authoritative), RA=1 (Recursion Available),
	// preserve RD (Recursion Desired, bit 8: 0x0100), RCODE=0 (NOERROR)
	respFlags := (queryFlags & 0x0100) | 0x8480

	if parsed.qtype == dnsTypeA {
		ip := net.ParseIP(fakeIP).To4()
		if ip == nil {
			return nil
		}

		// Total size = question section + 16-byte Answer RR
		response := make([]byte, parsed.questionLen+16)
		copy(response, query[:parsed.questionLen])

		binary.BigEndian.PutUint16(response[2:4], respFlags)
		binary.BigEndian.PutUint16(response[4:6], 1) // QDCOUNT = 1
		binary.BigEndian.PutUint16(response[6:8], 1) // ANCOUNT = 1
		binary.BigEndian.PutUint16(response[8:10], 0) // NSCOUNT = 0
		binary.BigEndian.PutUint16(response[10:12], 0) // ARCOUNT = 0

		p := parsed.questionLen
		response[p] = 0xC0
		response[p+1] = 0x0C // Compression pointer to QNAME at offset 12
		p += 2
		binary.BigEndian.PutUint16(response[p:p+2], dnsTypeA)
		binary.BigEndian.PutUint16(response[p+2:p+4], dnsClassIN)
		p += 4
		binary.BigEndian.PutUint32(response[p:p+4], 60) // TTL = 60s
		p += 4
		binary.BigEndian.PutUint16(response[p:p+2], 4) // RDLENGTH = 4
		p += 2
		copy(response[p:p+4], ip)
		return response
	}

	// For non-A queries (AAAA, HTTPS, TXT, MX, etc.): return NODATA (NOERROR, ANCOUNT=0)
	response := make([]byte, parsed.questionLen)
	copy(response, query[:parsed.questionLen])

	binary.BigEndian.PutUint16(response[2:4], respFlags)
	binary.BigEndian.PutUint16(response[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(response[6:8], 0) // ANCOUNT = 0
	binary.BigEndian.PutUint16(response[8:10], 0) // NSCOUNT = 0
	binary.BigEndian.PutUint16(response[10:12], 0) // ARCOUNT = 0

	return response
}
