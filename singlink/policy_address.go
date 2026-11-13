// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import "net/netip"

// Every supported representation is checked; the original dial target is kept.
func policyAddresses(ip netip.Addr) []netip.Addr {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		return []netip.Addr{ip, netip.AddrFrom4([4]byte(b[12:]))}
	}
	return []netip.Addr{ip}
}

func (rs *resolver) allowedAddress(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, equivalent := range policyAddresses(ip) {
		for _, p := range rs.deny {
			if p.Contains(equivalent) {
				return false
			}
		}
		if !rs.allowPrivate && (!publicIP(equivalent) || rs.local.has(equivalent)) {
			return false
		}
	}
	return true
}
