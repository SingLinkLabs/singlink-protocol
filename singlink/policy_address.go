// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import "net/netip"

// policyAddresses returns ip and the IPv4 address it embeds, if any: the
// IPv4-mapped form is unmapped, and the well-known NAT64 prefix (RFC 6052) and
// the IPv4-translated format (RFC 2765) also yield their embedded IPv4
// address. Every representation is checked; the original dial target is kept.
func policyAddresses(ip netip.Addr) []netip.Addr {
	ip = ip.Unmap()
	if nat64.Contains(ip) || ipv4Translated.Contains(ip) {
		b := ip.As16()
		return []netip.Addr{ip, netip.AddrFrom4([4]byte(b[12:]))}
	}
	return []netip.Addr{ip}
}

func (rs *resolver) allowedAddress(ip netip.Addr) bool {
	if !rs.configAllowed(ip) {
		return false
	}
	if !rs.allowPrivate {
		for _, equivalent := range policyAddresses(ip) {
			if rs.local.has(equivalent) {
				return false
			}
		}
	}
	return true
}

// configAllowed applies only the node's configured, host-independent address
// policy (deny_cidrs and the special-purpose ranges). It performs no I/O.
func (rs *resolver) configAllowed(ip netip.Addr) bool {
	// A zoned address never matches a prefix; none reaches here today (the
	// wire format has no zone and the resolver strips it), so refuse it.
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	for _, equivalent := range policyAddresses(ip) {
		for _, p := range rs.deny {
			if p.Contains(equivalent) {
				return false
			}
		}
		if !rs.allowPrivate && !publicIP(equivalent) {
			return false
		}
	}
	return true
}

// configStatus is the part of the destination policy that depends only on
// the request and the node's configuration: blocked ports and IP literals in
// configured or special-purpose ranges. It performs no DNS lookup, no dial
// and no other destination operation, so a node may decide it before the
// durable replay check. Host-dependent checks (the node's own interface
// addresses) and name resolution stay after admission, in resolve.
func (rs *resolver) configStatus(a Addr) Status {
	if rs.blockedPorts[a.Port] || a.Port == 0 {
		return StatusForbiddenDest
	}
	if a.IP.IsValid() && !rs.configAllowed(a.IP) {
		return StatusForbiddenDest
	}
	return StatusOK
}
