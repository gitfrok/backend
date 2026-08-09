package gitfrontdoor

import "testing"

func TestParseSSHCommandAcceptsOnlyGitServiceAndOpaqueHandle(t *testing.T) {
	for _, test := range []struct {
		command string
		service string
		handle  string
	}{
		{command: "git-upload-pack 'tenant-a/repo-a.git'", service: "git-upload-pack", handle: "tenant-a/repo-a.git"},
		{command: "git-receive-pack 'tenant-a/repo-a.git'", service: "git-receive-pack", handle: "tenant-a/repo-a.git"},
	} {
		service, handle, err := ParseSSHCommand(test.command)
		if err != nil || service != test.service || handle != test.handle {
			t.Fatalf("ParseSSHCommand(%q) = %q, %q, %v", test.command, service, handle, err)
		}
	}
}

func TestParseSSHCommandRejectsShellPathsAndExtraArguments(t *testing.T) {
	for _, command := range []string{"", "sh", "git-upload-pack tenant-a/repo-a.git", "git-upload-pack 'tenant-a/../repo-a.git'", "git-upload-pack 'tenant-a/repo-a.git' --upload-pack=sh", "git-upload-pack 'tenant-a/repo-a.git'; id"} {
		if _, _, err := ParseSSHCommand(command); err == nil {
			t.Errorf("ParseSSHCommand(%q) succeeded", command)
		}
	}
}
