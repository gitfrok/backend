package gitfrontdoor

import "strings"

// ParseSSHCommand accepts the only two forced commands Git needs. It is not a
// shell parser: quotes are required, extra bytes are rejected, and the handle
// is passed through the same opaque-ID validation as Smart-HTTP.
func ParseSSHCommand(command string) (service, handle string, err error) {
	for _, candidate := range []string{"git-upload-pack", "git-receive-pack"} {
		prefix := candidate + " '"
		if strings.HasPrefix(command, prefix) && strings.HasSuffix(command, "'") {
			handle = strings.TrimSuffix(strings.TrimPrefix(command, prefix), "'")
			if _, _, parseErr := ParseHandle(handle); parseErr == nil {
				return candidate, handle, nil
			}
		}
	}
	return "", "", ErrDenied
}
