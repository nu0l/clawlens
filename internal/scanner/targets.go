package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const maxCIDRHosts = 65536

// ParseTargets parses a target list from CLI input and expands IPv4 CIDR ranges.
func ParseTargets(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	parts := strings.Split(spec, ",")
	targets := make([]string, 0, len(parts))
	seen := make(map[string]struct{})

	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		if ip := net.ParseIP(item); ip != nil {
			normalized := ip.String()
			if _, ok := seen[normalized]; !ok {
				targets = append(targets, normalized)
				seen[normalized] = struct{}{}
			}
			continue
		}

		ip, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("非法目标: %q，需为 IP 或 CIDR", item)
		}

		base := ip.To4()
		if base == nil {
			return nil, fmt.Errorf("暂不支持 IPv6 网段扩展: %q", item)
		}
		maskSize, bits := ipNet.Mask.Size()
		hostBits := bits - maskSize
		hostCount := 1 << hostBits
		if hostCount > maxCIDRHosts {
			return nil, fmt.Errorf("网段 %q 主机数过大（%d），请拆分后重试", item, hostCount)
		}

		networkBase := binary.BigEndian.Uint32(base) & binary.BigEndian.Uint32(ipNet.Mask)
		firstHost := 0
		lastHost := hostCount - 1
		if hostCount > 2 {
			// 对常见 IPv4 子网，跳过网络地址与广播地址。
			firstHost = 1
			lastHost = hostCount - 2
		}

		for i := firstHost; i <= lastHost; i++ {
			addr := make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(addr, networkBase+uint32(i))
			normalized := addr.String()
			if _, ok := seen[normalized]; !ok {
				targets = append(targets, normalized)
				seen[normalized] = struct{}{}
			}
		}
	}

	return targets, nil
}
