package main

import "strings"

// parseUserHostPort splits "user@host:port" and returns user, host, port.
// For ipv6 with port, use "user@[2001:db8::1]:2222".
func parseUserHostPort(spec string) (string, string, int) {
	user, hostPort := splitUserFromHostSpec(spec)
	host, port := splitHostPort(hostPort)
	return strings.TrimSpace(user), strings.TrimSpace(host), port
}

func splitUserFromHostSpec(spec string) (string, string) {
	spec = strings.TrimSpace(spec)
	if at := strings.LastIndex(spec, "@"); at != -1 {
		return strings.TrimSpace(spec[:at]), spec[at+1:]
	}
	return "", spec
}

func splitHostPort(hostPort string) (string, int) {
	hostPort = strings.TrimSpace(hostPort)
	host := hostPort
	port := 0

	if strings.HasPrefix(hostPort, "[") {
		end := strings.Index(hostPort, "]")
		if end == -1 {
			return host, port
		}

		host = hostPort[1:end]
		rest := hostPort[end+1:]
		if strings.HasPrefix(rest, ":") {
			if parsed, err := parseInt(rest[1:]); err == nil {
				port = parsed
			}
		}
		return host, port
	}

	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		if parsed, err := parseInt(hostPort[idx+1:]); err == nil {
			port = parsed
			host = hostPort[:idx]
		}
	}

	return host, port
}
