//go:build darwin

package systemconfig

import (
	"net"
	"net/netip"
	"regexp"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
)

// Clients that hijack DNS point the system resolver at their own tun, so the
// scoped resolver of the default interface names an address on that tun and a
// query dialed from the physical interface goes nowhere. The DHCP lease still
// carries the network's own servers; use those in that case.
func replaceOwnTunServers(config *Config, interfaceIndex int) {
	if interfaceIndex == 0 || !serversOnPointToPointInterface(config.Servers) {
		return
	}
	iface, err := net.InterfaceByIndex(interfaceIndex)
	if err != nil {
		return
	}
	if servers := leaseServers(iface.Name); len(servers) > 0 {
		config.Servers = servers
	}
}

func serversOnPointToPointInterface(servers []M.Socksaddr) bool {
	if len(servers) == 0 {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, server := range servers {
		if !server.Addr.IsValid() || !isPointToPointAddress(interfaces, server.Addr) {
			return false
		}
	}
	return true
}

func isPointToPointAddress(interfaces []net.Interface, addr netip.Addr) bool {
	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if ipNet, isIPNet := address.(*net.IPNet); isIPNet && ipNet.Contains(addr.AsSlice()) {
				return true
			}
		}
	}
	return false
}

var leaseServersRegexp = regexp.MustCompile(`(?m)^\s*domain_name_server \((?:ip|ip_mult)\): \{?([^}\n]*)\}?$`)

func leaseServers(interfaceName string) []M.Socksaddr {
	output, err := shell.Exec("/usr/sbin/ipconfig", "getsummary", interfaceName).ReadOutput()
	if err != nil {
		return nil
	}
	return parseLeaseServers(output)
}

func parseLeaseServers(summary string) []M.Socksaddr {
	match := leaseServersRegexp.FindStringSubmatch(strings.ReplaceAll(summary, "\r\n", "\n"))
	if match == nil {
		return nil
	}
	var servers []M.Socksaddr
	for _, field := range strings.Split(match[1], ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil {
			continue
		}
		servers = append(servers, M.SocksaddrFrom(addr, 53))
	}
	return servers
}
