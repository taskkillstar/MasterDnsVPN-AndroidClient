package tun

import (
	"testing"
)

func TestDNSMapper_GetFakeIP_AssignsSequentialIPsIn198_18Range(t *testing.T) {
	d := NewDNSMapper()

	first := d.GetFakeIP("a.example")
	if first != "198.18.0.2" {
		// counter starts at 1; first AddUint32 -> 2 in NewDNSMapper's setup
		t.Fatalf("first fake IP = %q, want 198.18.0.2", first)
	}

	second := d.GetFakeIP("b.example")
	if second != "198.18.0.3" {
		t.Fatalf("second fake IP = %q, want 198.18.0.3", second)
	}
}

func TestDNSMapper_GetFakeIP_StableForSameHostname(t *testing.T) {
	d := NewDNSMapper()

	first := d.GetFakeIP("dup.example")
	second := d.GetFakeIP("dup.example")
	if first != second {
		t.Fatalf("duplicate hostname mapped to %q then %q", first, second)
	}
}

func TestDNSMapper_GetFakeIP_CaseInsensitiveAndDotNormalization(t *testing.T) {
	d := NewDNSMapper()

	first := d.GetFakeIP("WwW.GoOgLe.CoM")
	second := d.GetFakeIP("www.google.com.")
	third := d.GetFakeIP("WWW.GOOGLE.COM")
	if first != second || second != third {
		t.Fatalf("case-randomized hostnames mapped differently: %q vs %q vs %q", first, second, third)
	}

	host, ok := d.GetHostname(first)
	if !ok || host != "www.google.com" {
		t.Fatalf("GetHostname(%q) = %q (ok=%v), want www.google.com", first, host, ok)
	}
}

func TestDNSMapper_GetHostname_RoundTrips(t *testing.T) {
	d := NewDNSMapper()

	const host = "roundtrip.example"
	ip := d.GetFakeIP(host)

	got, ok := d.GetHostname(ip)
	if !ok {
		t.Fatalf("GetHostname(%q) returned ok=false", ip)
	}
	if got != host {
		t.Fatalf("GetHostname(%q) = %q, want %q", ip, got, host)
	}
}

func TestDNSMapper_GetHostname_UnknownIPOKFalse(t *testing.T) {
	d := NewDNSMapper()
	if _, ok := d.GetHostname("198.18.99.99"); ok {
		t.Fatal("GetHostname returned ok=true for unmapped IP")
	}
}
