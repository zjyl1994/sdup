package sshclient

import "strings"

func parseUserHostPort(spec string) (string, string, int, error) {
	user, hostPort := splitUserFromHostSpec(spec)
	host, port, err := splitHostPort(hostPort)
	return strings.TrimSpace(user), strings.TrimSpace(host), port, err
}

func splitUserFromHostSpec(spec string) (string, string) {
	spec = strings.TrimSpace(spec)
	if at := strings.LastIndex(spec, "@"); at != -1 {
		return strings.TrimSpace(spec[:at]), spec[at+1:]
	}
	return "", spec
}

func splitHostPort(hostPort string) (string, int, error) {
	hostPort = strings.TrimSpace(hostPort)
	host := hostPort
	port := 0

	if strings.HasPrefix(hostPort, "[") {
		end := strings.Index(hostPort, "]")
		if end == -1 {
			return host, port, nil
		}

		host = hostPort[1:end]
		rest := hostPort[end+1:]
		if strings.HasPrefix(rest, ":") {
			if parsed, err := parseInt(rest[1:]); err == nil {
				if err := ValidatePort(parsed); err != nil {
					return hostPort, 0, err
				}
				port = parsed
			}
		}
		return host, port, nil
	}

	if strings.Count(hostPort, ":") > 1 {
		return host, port, nil
	}

	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		if parsed, err := parseInt(hostPort[idx+1:]); err == nil {
			if err := ValidatePort(parsed); err != nil {
				return hostPort, 0, err
			}
			port = parsed
			host = hostPort[:idx]
		}
	}

	return host, port, nil
}
