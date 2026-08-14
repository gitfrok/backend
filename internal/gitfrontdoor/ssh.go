package gitfrontdoor

import "strings"

// ParseSSHCommand accepts the only two forced commands Git needs. It is not a
// shell parser: quotes are required, extra bytes are rejected, and the handle
// is passed through the same opaque-ID validation as Smart-HTTP.
func ParseSSHCommand(command string) (service, handle string, err error) {
	for _, candidate := range []string{"git-upload-pack", "git-receive-pack"} {
		prefix := candidate + " '"
		if rest, found := strings.CutPrefix(command, prefix); found && strings.HasSuffix(command, "'") {
			handle = strings.TrimSuffix(rest, "'")
			// git uses a rooted path for ssh://host/tenant/repo.git. This
			// slash is URI framing, not a filesystem path; the normalized
			// value still has to pass the same opaque-handle validation.
			handle = strings.TrimPrefix(handle, "/")
			if _, _, parseErr := ParseHandle(handle); parseErr == nil {
				return candidate, handle, nil
			}
		}
	}
	return "", "", ErrDenied
}
