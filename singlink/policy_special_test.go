// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"net/netip"
	"testing"
)

// lastAddr returns the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// ianaNotGloballyReachable lists every entry of the IANA IPv4 and IPv6
// Special-Purpose Address Registries (snapshot 2026-11-19) whose "Globally
// Reachable" field is False or N/A, plus the deprecated entries. A public
// node must refuse every address in them. 64:ff9b::/96 is absent: it is
// globally reachable and handled by checking the embedded IPv4 address.
var ianaNotGloballyReachable = []string{
	// IPv4 (iana-ipv4-special-registry)
	"0.0.0.0/8", "0.0.0.0/32", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
	"192.0.0.8/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
	"192.88.99.0/24", "192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
	// IPv6 (iana-ipv6-special-registry)
	"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
	"100:0:0:1::/64", "2001::/23", "2001::/32", "2001:2::/48", "2001:10::/28",
	"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7",
	"fe80::/10",
}

func TestIANASpecialPurposeBlocksDenied(t *testing.T) {
	rs := &resolver{}
	for _, s := range ianaNotGloballyReachable {
		p := netip.MustParsePrefix(s)
		for _, ip := range []netip.Addr{p.Masked().Addr(), lastAddr(p)} {
			if p.Addr().Is4() {
				// The IPv4-mapped form must be refused as well.
				for _, v := range []netip.Addr{ip, netip.AddrFrom16(ip.As16())} {
					if publicIP(v) || rs.configAllowed(v) {
						t.Errorf("%s (from %s) allowed", v, s)
					}
				}
				continue
			}
			if publicIP(ip) || rs.configAllowed(ip) {
				t.Errorf("%s (from %s) allowed", ip, s)
			}
		}
	}
}

// F-03 (VPN Labs, VPNL-2026-0013): documentation (RFC 9637), SRv6 SIDs
// (RFC 9602), the dummy prefix (RFC 9780) and the RFC 2765 IPv4-translated
// format were accepted as public destinations.
func TestF03SpecialPurposeIPv6(t *testing.T) {
	denied := []string{
		"3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
		"5f00::1", "5f00:ffff::1",
		"100:0:0:1::1",
		"::ffff:0:a00:1", "::ffff:0:808:808", "::ffff:0:0:0", "::ffff:0:ffff:ffff",
		// IETF-reserved space outside 2000::/3 (IANA IPv6 Address Space
		// registry): no global unicast assignments exist there.
		"200::1", "400::1", "800::1", "1000::1", "1fff:ffff::1", "4000::1",
		"5eff::1", "5f01::1", "6000::1", "8000::1", "a000::1", "c000::1",
		"e000::1", "f000::1", "f800::1", "fe00::1",
	}
	rs := &resolver{}
	for _, s := range denied {
		ip := netip.MustParseAddr(s)
		if publicIP(ip) {
			t.Errorf("publicIP(%s) = true", s)
		}
		if rs.configAllowed(ip) {
			t.Errorf("configAllowed(%s) = true", s)
		}
		if st := rs.configStatus(Addr{IP: ip, Port: 443}); st != StatusForbiddenDest {
			t.Errorf("configStatus(%s) = %d", s, st)
		}
		if _, st := rs.resolve(context.Background(), Addr{IP: ip, Port: 443}); st != StatusForbiddenDest {
			t.Errorf("resolve(%s) = %d", s, st)
		}
	}
	// Controls: globally reachable unicast next to the new blocks, and the
	// globally reachable special-purpose entries, stay allowed.
	for _, s := range []string{
		"3fff:1000::1", "3ffe::1", "2606:4700:4700::1111", "2001:4860:4860::8888",
		"2620:4f:8000::1", "64:ff9b::808:808", "::ffff:8.8.8.8", "8.8.8.8",
		"192.31.196.1", "192.52.193.1", "192.175.48.1",
	} {
		ip := netip.MustParseAddr(s)
		if !publicIP(ip) || !rs.configAllowed(ip) {
			t.Errorf("%s refused", s)
		}
	}
}

// An address with an IPv6 zone never matches a prefix, so it is refused.
func TestZonedAddressRefused(t *testing.T) {
	for _, rs := range []*resolver{{}, {allowPrivate: true}} {
		for _, s := range []string{"2606:4700:4700::1111%eth0", "fe80::1%eth0"} {
			if rs.configAllowed(netip.MustParseAddr(s)) {
				t.Errorf("allow_private=%v: %s allowed", rs.allowPrivate, s)
			}
		}
	}
}

// The IPv4 address embedded in the IPv4-translated format is matched against
// deny_cidrs like the NAT64 and IPv4-mapped forms, also with allow_private.
func TestIPv4TranslatedEquivalentPolicy(t *testing.T) {
	deny := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, rs := range []*resolver{{deny: deny}, {allowPrivate: true, deny: deny}} {
		for _, s := range []string{"10.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "::ffff:0:a00:1"} {
			if rs.configAllowed(netip.MustParseAddr(s)) {
				t.Errorf("allow_private=%v: %s allowed despite deny_cidrs", rs.allowPrivate, s)
			}
		}
	}
	got := policyAddresses(netip.MustParseAddr("::ffff:0:a00:1"))
	if len(got) != 2 || got[1] != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("policyAddresses = %v", got)
	}
}
