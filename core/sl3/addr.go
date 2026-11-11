package sl3

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// Addr is a destination: either an IP or a domain name, plus a port.
type Addr struct {
	IP   netip.Addr // valid when the destination is an IP literal
	Host string     // set when the destination is a domain name
	Port uint16
}

// ParseAddr parses "host:port".
func ParseAddr(s string) (Addr, error) {
	host, ps, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return Addr{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return Addr{IP: ip.Unmap(), Port: uint16(p)}, nil
	}
	if host == "" || len(host) > 255 {
		return Addr{}, errors.New("sl3: bad host")
	}
	return Addr{Host: host, Port: uint16(p)}, nil
}

// AddrFromAddrPort converts a netip.AddrPort.
func AddrFromAddrPort(ap netip.AddrPort) Addr {
	return Addr{IP: ap.Addr().Unmap(), Port: ap.Port()}
}

func (a Addr) String() string {
	if a.IP.IsValid() {
		return netip.AddrPortFrom(a.IP, a.Port).String()
	}
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// appendTo encodes a as ATYP || address || port.
func (a Addr) appendTo(b []byte) []byte {
	switch {
	case a.IP.Is4():
		b = append(b, atypIPv4)
		ip := a.IP.As4()
		b = append(b, ip[:]...)
	case a.IP.Is6():
		b = append(b, atypIPv6)
		ip := a.IP.As16()
		b = append(b, ip[:]...)
	default:
		b = append(b, atypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}

// decodeAddr reads an address from the front of b and returns the rest.
func decodeAddr(b []byte) (Addr, []byte, error) {
	if len(b) < 1 {
		return Addr{}, nil, io.ErrUnexpectedEOF
	}
	var a Addr
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return Addr{}, nil, io.ErrUnexpectedEOF
		}
		a.IP = netip.AddrFrom4([4]byte(b[1:5]))
		b = b[5:]
	case atypIPv6:
		if len(b) < 1+16+2 {
			return Addr{}, nil, io.ErrUnexpectedEOF
		}
		a.IP = netip.AddrFrom16([16]byte(b[1:17])).Unmap()
		b = b[17:]
	case atypDomain:
		if len(b) < 2 {
			return Addr{}, nil, io.ErrUnexpectedEOF
		}
		n := int(b[1])
		if n == 0 || len(b) < 2+n+2 {
			return Addr{}, nil, io.ErrUnexpectedEOF
		}
		a.Host = string(b[2 : 2+n])
		b = b[2+n:]
	default:
		return Addr{}, nil, errors.New("sl3: bad address type")
	}
	a.Port = binary.BigEndian.Uint16(b[:2])
	return a, b[2:], nil
}
