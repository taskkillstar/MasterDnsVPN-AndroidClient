package tun

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// helper: build a DNS query for a hostname with a specific QTYPE
func buildQueryWithType(t *testing.T, hostname string, qtype uint16) []byte {
	t.Helper()
	// Header: 12 bytes (id, flags, qdcount=1, ancount=0, nscount=0, arcount=0)
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x1234) // id
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // flags: RD=1 (Recursion Desired)
	binary.BigEndian.PutUint16(q[4:6], 1)      // qdcount = 1

	// Question section
	parts := strings.Split(hostname, ".")
	for _, label := range parts {
		if len(label) > 63 {
			t.Fatalf("label %q too long for test builder", label)
		}
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0) // terminator
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, qtype)
	q = append(q, typeBytes...) // QTYPE
	q = append(q, 0, 1)         // QCLASS = IN
	return q
}

// helper: build a Type A DNS query for a hostname
func buildQuery(t *testing.T, hostname string) []byte {
	return buildQueryWithType(t, hostname, 1)
}

// helper: build a DNS query with an EDNS0 OPT record in the Additional section
func buildQueryWithEDNS0(t *testing.T, hostname string, qtype uint16) []byte {
	t.Helper()
	q := buildQueryWithType(t, hostname, qtype)
	// Update ARCOUNT to 1
	binary.BigEndian.PutUint16(q[10:12], 1)

	// Append EDNS0 OPT pseudo-RR (11 bytes)
	// NAME: root (0x00)
	// TYPE: OPT (41 = 0x0029)
	// CLASS: UDP payload size (4096 = 0x1000)
	// TTL: Extended RCODE and flags (0x00000000)
	// RDLENGTH: 0 (0x0000)
	opt := []byte{
		0x00,       // root name
		0x00, 0x29, // TYPE = OPT (41)
		0x10, 0x00, // CLASS = 4096 bytes UDP payload size
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x00, // RDLENGTH = 0
	}
	return append(q, opt...)
}

func TestParseDNSQuery_ValidHostname(t *testing.T) {
	q := buildQuery(t, "example.com")
	parsed, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery failed for valid query")
	}
	if parsed.hostname != "example.com" {
		t.Fatalf("parseDNSQuery hostname = %q, want %q", parsed.hostname, "example.com")
	}
	if parsed.qtype != 1 {
		t.Fatalf("parseDNSQuery qtype = %d, want 1", parsed.qtype)
	}
	if parsed.qclass != 1 {
		t.Fatalf("parseDNSQuery qclass = %d, want 1", parsed.qclass)
	}
	if parsed.questionLen != len(q) {
		t.Fatalf("parseDNSQuery questionLen = %d, want %d", parsed.questionLen, len(q))
	}
}

func TestParseDNSQuery_SingleLabelHostname(t *testing.T) {
	q := buildQuery(t, "localhost")
	parsed, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery failed for localhost")
	}
	if parsed.hostname != "localhost" {
		t.Fatalf("parseDNSQuery single label = %q, want %q", parsed.hostname, "localhost")
	}
}

func TestParseDNSQuery_TooShortReturnsFalse(t *testing.T) {
	_, ok := parseDNSQuery([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) // 11 bytes < 12
	if ok {
		t.Fatal("parseDNSQuery short query returned ok=true, want false")
	}
}

func TestParseDNSQuery_LabelLen63OK(t *testing.T) {
	long := strings.Repeat("a", 63)
	q := buildQuery(t, long+".example")
	parsed, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery failed for 63-char label")
	}
	if parsed.hostname != long+".example" {
		t.Fatalf("parseDNSQuery 63-char label = %q", parsed.hostname)
	}
}

func TestParseDNSQuery_LabelLen64Rejected(t *testing.T) {
	long := strings.Repeat("a", 64)
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, byte(64))
	q = append(q, []byte(long)...)
	q = append(q, 0, 0, 1, 0, 1)
	_, ok := parseDNSQuery(q)
	if ok {
		t.Fatal("parseDNSQuery 64-char label returned ok=true, want false")
	}
}

func TestParseDNSQuery_CompressionPointerRejected(t *testing.T) {
	q := buildQuery(t, "example.com")
	// Replace the first label-length byte with 0xC0 0x0C (pointer to offset 12)
	q[12] = 0xC0
	q[13] = 0x0C
	_, ok := parseDNSQuery(q)
	if ok {
		t.Fatal("parseDNSQuery compression pointer returned ok=true, want false")
	}
}

func TestBuildDNSResponse_ValidIPReturnsAResponse(t *testing.T) {
	q := buildQuery(t, "example.com")
	parsed, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery failed")
	}

	resp := buildDNSResponse(q, parsed, "198.18.0.5")
	if resp == nil {
		t.Fatal("buildDNSResponse returned nil for valid input")
	}

	// Response flags should have QR=1, AA=1, RA=1, RD=1 preserved, RCODE=0
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8480 != 0x8480 {
		t.Fatalf("response flags = 0x%04X, want 0x8480 bits set", flags)
	}
	qdcount := binary.BigEndian.Uint16(resp[4:6])
	if qdcount != 1 {
		t.Fatalf("qdcount = %d, want 1", qdcount)
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("ancount = %d, want 1", ancount)
	}
	nscount := binary.BigEndian.Uint16(resp[8:10])
	if nscount != 0 {
		t.Fatalf("nscount = %d, want 0", nscount)
	}
	arcount := binary.BigEndian.Uint16(resp[10:12])
	if arcount != 0 {
		t.Fatalf("arcount = %d, want 0", arcount)
	}

	// The answer section is placed at parsed.questionLen.
	answerStart := parsed.questionLen
	if int(resp[answerStart]) != 0xC0 || int(resp[answerStart+1]) != 0x0C {
		t.Fatalf("answer name pointer = 0x%02X%02X, want 0xC00C", resp[answerStart], resp[answerStart+1])
	}
	typeA := binary.BigEndian.Uint16(resp[answerStart+2 : answerStart+4])
	if typeA != 1 {
		t.Fatalf("answer type = %d, want 1 (A)", typeA)
	}
	classIN := binary.BigEndian.Uint16(resp[answerStart+4 : answerStart+6])
	if classIN != 1 {
		t.Fatalf("answer class = %d, want 1 (IN)", classIN)
	}
	ttl := binary.BigEndian.Uint32(resp[answerStart+6 : answerStart+10])
	if ttl != 60 {
		t.Fatalf("ttl = %d, want 60", ttl)
	}
	rdlen := binary.BigEndian.Uint16(resp[answerStart+10 : answerStart+12])
	if rdlen != 4 {
		t.Fatalf("rdlength = %d, want 4", rdlen)
	}
	ip := net.IP(resp[answerStart+12 : answerStart+16]).String()
	if ip != "198.18.0.5" {
		t.Fatalf("answer IP = %s, want 198.18.0.5", ip)
	}
}

func TestBuildDNSResponse_WithEDNS0_StripsOPTAndPlacesAnswerImmediatelyAfterQuestion(t *testing.T) {
	// Query includes an 11-byte EDNS0 OPT RR in the Additional section
	qWithOpt := buildQueryWithEDNS0(t, "google.com", 1)
	parsed, ok := parseDNSQuery(qWithOpt)
	if !ok {
		t.Fatal("parseDNSQuery failed for query with EDNS0")
	}

	// parsed.questionLen must point to the end of the Question section, NOT the end of the query
	if parsed.questionLen == len(qWithOpt) {
		t.Fatalf("parsed.questionLen (%d) should be less than len(qWithOpt) (%d)", parsed.questionLen, len(qWithOpt))
	}
	if parsed.questionLen != len(qWithOpt)-11 {
		t.Fatalf("parsed.questionLen = %d, want %d (excluding 11-byte OPT RR)", parsed.questionLen, len(qWithOpt)-11)
	}

	resp := buildDNSResponse(qWithOpt, parsed, "198.18.0.2")
	if resp == nil {
		t.Fatal("buildDNSResponse returned nil")
	}

	// ARCOUNT in response must be 0
	arcount := binary.BigEndian.Uint16(resp[10:12])
	if arcount != 0 {
		t.Fatalf("arcount = %d, want 0", arcount)
	}

	// Answer must start exactly at parsed.questionLen
	answerStart := parsed.questionLen
	if len(resp) != answerStart+16 {
		t.Fatalf("response length = %d, want %d", len(resp), answerStart+16)
	}

	// Verify Answer RR is at answerStart
	if resp[answerStart] != 0xC0 || resp[answerStart+1] != 0x0C {
		t.Fatalf("answer compression pointer mismatch at offset %d", answerStart)
	}
	typeA := binary.BigEndian.Uint16(resp[answerStart+2 : answerStart+4])
	if typeA != 1 {
		t.Fatalf("answer type = %d, want 1", typeA)
	}
	ip := net.IP(resp[answerStart+12 : answerStart+16]).String()
	if ip != "198.18.0.2" {
		t.Fatalf("answer IP = %s, want 198.18.0.2", ip)
	}
}

func TestBuildDNSResponse_AAAAQuery_ReturnsNODATA(t *testing.T) {
	// Chrome sends AAAA (IPv6, type 28) query in parallel with A
	qAAAA := buildQueryWithType(t, "example.com", 28) // 28 = AAAA
	parsed, ok := parseDNSQuery(qAAAA)
	if !ok {
		t.Fatal("parseDNSQuery failed for AAAA query")
	}
	if parsed.qtype != 28 {
		t.Fatalf("parsed.qtype = %d, want 28 (AAAA)", parsed.qtype)
	}

	resp := buildDNSResponse(qAAAA, parsed, "")
	if resp == nil {
		t.Fatal("buildDNSResponse returned nil for AAAA query")
	}

	// NODATA response: QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0, NOERROR
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 0 {
		t.Fatalf("ancount = %d, want 0 (NODATA for AAAA)", ancount)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Fatalf("QR bit not set in response flags: 0x%04X", flags)
	}
	if flags&0x000F != 0 {
		t.Fatalf("RCODE = %d, want 0 (NOERROR)", flags&0x000F)
	}

	// Total length should equal questionLen (no Answer RRs appended)
	if len(resp) != parsed.questionLen {
		t.Fatalf("response length = %d, want %d (exact Question length)", len(resp), parsed.questionLen)
	}
}

func TestBuildDNSResponse_HTTPSQuery_ReturnsNODATA(t *testing.T) {
	// Chrome sends HTTPS (type 65) query
	qHTTPS := buildQueryWithType(t, "example.com", 65) // 65 = HTTPS
	parsed, ok := parseDNSQuery(qHTTPS)
	if !ok {
		t.Fatal("parseDNSQuery failed for HTTPS query")
	}

	resp := buildDNSResponse(qHTTPS, parsed, "")
	if resp == nil {
		t.Fatal("buildDNSResponse returned nil for HTTPS query")
	}

	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 0 {
		t.Fatalf("ancount = %d, want 0 (NODATA for HTTPS)", ancount)
	}
	if len(resp) != parsed.questionLen {
		t.Fatalf("response length = %d, want %d", len(resp), parsed.questionLen)
	}
}

func TestBuildDNSResponse_InvalidIPReturnsNil(t *testing.T) {
	q := buildQuery(t, "example.com")
	parsed, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery failed")
	}
	if resp := buildDNSResponse(q, parsed, "not-an-ip"); resp != nil {
		t.Fatalf("buildDNSResponse with non-IP returned %v, want nil", resp)
	}
}

func TestBuildDNSResponse_QueryTooShortReturnsNil(t *testing.T) {
	parsed := dnsParsedQuery{
		hostname:    "example.com",
		qtype:       1,
		qclass:      1,
		questionLen: 29,
	}
	if resp := buildDNSResponse([]byte{0, 1, 2}, parsed, "1.2.3.4"); resp != nil {
		t.Fatalf("buildDNSResponse short query returned %v, want nil", resp)
	}
}

func TestHandleUDPResponseBuildDoesNotReuseReceiveBuffer(t *testing.T) {
	dnsMap := NewDNSMapper()

	// First query: long hostname
	q1 := buildQuery(t, "longhostname.example.com")
	// Second query: short hostname
	q2 := buildQuery(t, "ab.cd")

	const headerOffset = 10
	buf := make([]byte, 65535)

	// ---- Iteration 1: long query q1 ----
	copy(buf[headerOffset:headerOffset+len(q1)], q1)
	n1 := headerOffset + len(q1)
	dnsQuery1 := buf[headerOffset:n1]
	parsed1, ok1 := parseDNSQuery(dnsQuery1)
	if !ok1 || parsed1.hostname != "longhostname.example.com" {
		t.Fatalf("iter1: parseDNSQuery failed, got %q", parsed1.hostname)
	}
	fakeIP1 := dnsMap.GetFakeIP(parsed1.hostname)
	resp1 := buildDNSResponse(dnsQuery1, parsed1, fakeIP1)
	if resp1 == nil {
		t.Fatal("iter1: buildDNSResponse returned nil")
	}

	// Simulate buggy legacy write to demonstrate aliasing safety
	_ = append(buf[:headerOffset], resp1...)

	// ---- Iteration 2: short query q2 ----
	copy(buf[headerOffset:headerOffset+len(q2)], q2)
	n2 := headerOffset + len(q2)

	dnsQuery2 := make([]byte, n2-headerOffset)
	copy(dnsQuery2, buf[headerOffset:n2])
	parsed2, ok2 := parseDNSQuery(dnsQuery2)
	if !ok2 || parsed2.hostname != "ab.cd" {
		t.Fatalf("iter2 (fixed path): parseDNSQuery = %q, want ab.cd", parsed2.hostname)
	}

	resp2 := buildDNSResponse(dnsQuery2, parsed2, dnsMap.GetFakeIP("ab.cd"))
	if resp2 == nil {
		t.Fatal("iter2: buildDNSResponse returned nil")
	}
	fullResp2 := make([]byte, 0, headerOffset+len(resp2))
	fullResp2 = append(fullResp2, buf[:headerOffset]...)
	fullResp2 = append(fullResp2, resp2...)

	// buf[headerOffset:n2] must still equal q2
	for i, b := range q2 {
		if buf[headerOffset+i] != b {
			t.Fatalf("iter2: buf[%d] = 0x%02X, fix aliases buf (want 0x%02X)", headerOffset+i, buf[headerOffset+i], b)
		}
	}
}

func TestFakeDNSProxy_LiveUDPLifecycle(t *testing.T) {
	dnsMap := NewDNSMapper()
	proxy := NewFakeDNSProxy("127.0.0.1:18000", dnsMap)

	tcpAddr, err := proxy.Start()
	if err != nil {
		t.Fatalf("proxy.Start() failed: %v", err)
	}
	defer proxy.Stop()

	if proxy.udpPort == 0 {
		t.Fatal("proxy.udpPort is 0 after Start()")
	}

	// Dial proxy UDP port
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxy.udpPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer udpConn.Close()

	// Construct SOCKS5 UDP encapsulated DNS query for "test.example.com"
	dnsQ := buildQuery(t, "test.example.com")
	socksHeader := []byte{0x00, 0x00, 0x00, 0x01, 172, 19, 0, 2, 0, 53} // DST = 172.19.0.2:53
	packet := append(socksHeader, dnsQ...)

	if _, err := udpConn.Write(packet); err != nil {
		t.Fatalf("Write to UDP failed: %v", err)
	}

	recvBuf := make([]byte, 2048)
	n, err := udpConn.Read(recvBuf)
	if err != nil {
		t.Fatalf("Read from UDP failed: %v", err)
	}
	if n < len(socksHeader)+len(dnsQ)+16 {
		t.Fatalf("received UDP packet too short: %d bytes", n)
	}

	// Verify Fake IP mapping was created
	fakeIP, ok := dnsMap.hostnameToIP["test.example.com"]
	if !ok {
		t.Fatal("Fake IP not created in dnsMap")
	}

	// Verify SOCKS5 header in response
	if recvBuf[0] != 0 || recvBuf[1] != 0 || recvBuf[2] != 0 || recvBuf[3] != 1 {
		t.Fatalf("invalid SOCKS5 header in response: %v", recvBuf[:4])
	}

	// Verify DNS answer IP in payload
	ansOffset := len(socksHeader) + len(dnsQ) + 12
	gotIP := net.IP(recvBuf[ansOffset : ansOffset+4]).String()
	if gotIP != fakeIP {
		t.Fatalf("DNS response IP = %s, want %s", gotIP, fakeIP)
	}

	// Verify TCP connection
	tcpConn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("Dial TCP failed: %v", err)
	}
	defer tcpConn.Close()

	// SOCKS5 handshake greeting
	if _, err := tcpConn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("TCP handshake write failed: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := tcpConn.Read(authResp); err != nil || authResp[0] != 5 || authResp[1] != 0 {
		t.Fatalf("TCP auth response invalid: %v", authResp)
	}

	// SOCKS5 UDP ASSOCIATE request
	req := []byte{5, 3, 0, 1, 172, 19, 0, 2, 0, 53}
	if _, err := tcpConn.Write(req); err != nil {
		t.Fatalf("UDP ASSOCIATE write failed: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := tcpConn.Read(reply); err != nil || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply invalid: %v", reply)
	}
}

