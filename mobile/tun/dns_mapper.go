package tun

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
)

type DNSMapper struct {
	mu           sync.RWMutex
	hostnameToIP map[string]string
	ipToHostname map[string]string
	counter      uint32
}

func NewDNSMapper() *DNSMapper {
	return &DNSMapper{
		hostnameToIP: make(map[string]string),
		ipToHostname: make(map[string]string),
		counter:      1,
	}
}

func (d *DNSMapper) GetFakeIP(hostname string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	normalized := strings.ToLower(strings.TrimSuffix(hostname, "."))

	if ip, ok := d.hostnameToIP[normalized]; ok {
		return ip
	}

	counter := atomic.AddUint32(&d.counter, 1)
	if counter > 65535 {
		atomic.StoreUint32(&d.counter, 1)
		counter = 1
	}

	octet3 := byte(counter >> 8)
	octet4 := byte(counter & 0xFF)
	fakeIP := fmt.Sprintf("198.18.%d.%d", octet3, octet4)

	d.hostnameToIP[normalized] = fakeIP
	d.ipToHostname[fakeIP] = normalized

	log.Printf("[TUN-DNS] Mapped %s -> %s", normalized, fakeIP)
	return fakeIP
}

func (d *DNSMapper) GetHostname(fakeIP string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	hostname, ok := d.ipToHostname[fakeIP]
	return hostname, ok
}
