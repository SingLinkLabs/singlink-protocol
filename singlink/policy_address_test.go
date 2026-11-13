// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestNAT64EquivalentPolicies(t *testing.T) {
	v4 := netip.MustParseAddr("8.8.8.8")
	v6 := netip.MustParseAddr("64:ff9b::808:808")
	cases := []*resolver{
		{deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}},
		{local: localAddrs{set: map[netip.Addr]bool{v4: true}, when: time.Now()}},
		{allowPrivate: true, deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}},
	}
	for _, rs := range cases {
		for _, ip := range []netip.Addr{v4, v6, netip.MustParseAddr("::ffff:8.8.8.8")} {
			if _, st := rs.resolve(context.Background(), Addr{IP: ip, Port: 443}); st != StatusForbiddenDest {
				t.Fatal("equivalent destination allowed")
			}
		}
	}
	rs := &resolver{}
	for _, s := range []string{"8.8.4.4", "64:ff9b::808:404"} {
		ip := netip.MustParseAddr(s)
		if ap, st := rs.resolve(context.Background(), Addr{IP: ip, Port: 443}); st != StatusOK || ap.Addr() != ip {
			t.Fatal("public control changed")
		}
	}
	for _, s := range []string{"64:ff9b::a00:1", "64:ff9b::7f00:1"} {
		if _, st := rs.resolve(context.Background(), Addr{IP: netip.MustParseAddr(s), Port: 443}); st != StatusForbiddenDest {
			t.Fatal("private equivalent allowed")
		}
	}
	// No DNS/dial/translator is used in this policy-level regression.
}
