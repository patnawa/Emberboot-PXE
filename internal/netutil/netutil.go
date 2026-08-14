// Package netutil holds small networking helpers.
package netutil

import (
	"fmt"
	"net"
)

// OutboundIP returns the host's primary outbound IPv4 address — the address
// clients on the LAN can reach. Used when network.advertise_ip is empty.
// No packets are sent; the OS just picks a route.
func OutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp4", "255.255.255.255:67")
	if err != nil {
		// Fall back to the first global unicast IPv4 on any interface.
		return firstUnicastIPv4()
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil {
		return addr.IP.To4(), nil
	}
	return firstUnicastIPv4()
}

func firstUnicastIPv4() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
			if ip4 := n.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no usable IPv4 address found; set network.advertise_ip")
}
