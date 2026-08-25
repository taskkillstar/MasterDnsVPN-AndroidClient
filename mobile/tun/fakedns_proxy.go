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
	udpPort       int
	udpConn       *net.UDPConn
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
	// 1. TCP Listener for SOCKS5 requests
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.listener = l
	p.LocalPort = l.Addr().(*net.TCPAddr).Port

	// 2. Persistent UDP Listener for FakeDNS datagrams
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		p.listener.Close()
		return "", err
	}
	p.udpConn = u
	p.udpPort = u.LocalAddr().(*net.UDPAddr).Port

	p.wg.Add(2)
	go p.acceptLoop()
	go p.udpLoop()

	return l.Addr().String(), nil
}

func (p *FakeDNSProxy) Stop() {
	p.cancel()
	if p.listener != nil {
		p.listener.Close()
	}
	if p.udpConn != nil {
		p.udpConn.Close()
	}
	p.wg.Wait()
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

func (p *FakeDNSProxy) udpLoop() {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, rAddr, err := p.udpConn.ReadFromUDP(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			return
		}

		if n < 4 || buf[2] != 0 {
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
					p.udpConn.WriteToUDP(fullResp, rAddr)
				}
			}
			continue
		}

		// Non-DNS UDP (e.g. QUIC) is dropped so browser quickly falls back to TCP
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
		p.handleUDPAssociate(conn)
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
		if _, err := io.ReadFull(realConn, bndAddr); err != nil {
			return
		}
	} else if replyHeader[3] == 3 {
		l := make([]byte, 1)
		if _, err := io.ReadFull(realConn, l); err != nil {
			return
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(realConn, dom); err != nil {
			return
		}
		bndAddr = append(l, dom...)
	} else if replyHeader[3] == 4 {
		bndAddr = make([]byte, 16)
		if _, err := io.ReadFull(realConn, bndAddr); err != nil {
			return
		}
	}
	if len(bndAddr) > 0 {
		if _, err := conn.Write(bndAddr); err != nil {
			return
		}
	}

	bndPort := make([]byte, 2)
	if _, err := io.ReadFull(realConn, bndPort); err != nil {
		return
	}
	if _, err := conn.Write(bndPort); err != nil {
		return
	}

	go io.Copy(realConn, conn)
	io.Copy(conn, realConn)
}

func (p *FakeDNSProxy) handleUDPAssociate(tcpConn net.Conn) {
	// SOCKS5 UDP ASSOCIATE reply: BND.ADDR = 127.0.0.1, BND.PORT = p.udpPort
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, uint16(p.udpPort))
	reply = append(reply, pBuf...)
	if _, err := tcpConn.Write(reply); err != nil {
		return
	}

	// Keep the TCP connection open until the client disconnects, as required by SOCKS5 spec.
	buf := make([]byte, 512)
	for {
		_, err := tcpConn.Read(buf)
		if err != nil {
			return
		}
	}
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
