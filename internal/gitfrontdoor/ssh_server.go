package gitfrontdoor

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/gitfrok/backend/platform/ids"
	"golang.org/x/crypto/ssh"
)

// SSH serves the restricted Git SSH boundary. It has no shell, subsystem, port
// forwarding, or arbitrary command path: one session may run one forced Git
// command and is then closed.
type SSH struct {
	Router        Router
	Storage       Storage
	HostSigner    ssh.Signer
	VerifierKeyID string
}

// Serve accepts connections until ctx is cancelled. Listener ownership remains
// with the caller so dataplane composition controls its configured address.
func (s SSH) Serve(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() { _ = s.ServeConn(ctx, connection) }()
	}
}

// ServeConn performs SSH authentication then serves at most one forced command
// per session. Authentication is repeated immediately before storage routing so
// a revocation between the key exchange and exec request still denies access.
func (s SSH) ServeConn(ctx context.Context, connection net.Conn) error {
	if s.Router.Authenticator == nil || s.Storage == nil || s.HostSigner == nil || s.VerifierKeyID == "" {
		return ErrDenied
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		_, ok := s.Router.Authenticator.AuthenticateSSHKey(ctx, canonicalPublicKey(key), s.VerifierKeyID)
		if !ok {
			return nil, ErrDenied
		}
		return &ssh.Permissions{Extensions: map[string]string{"gitfrok.public_key": canonicalPublicKey(key)}}, nil
	}}
	config.AddHostKey(s.HostSigner)
	serverConn, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	verifiedKey := ""
	if serverConn.Permissions != nil {
		verifiedKey = serverConn.Permissions.Extensions["gitfrok.public_key"]
	}
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "git sessions only")
			continue
		}
		accepted, requests, err := channel.Accept()
		if err != nil {
			continue
		}
		go s.serveSession(ctx, accepted, requests, verifiedKey)
	}
	return nil
}

func (s SSH) serveSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, verifiedKey string) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		command, ok := sshCommand(request.Payload)
		service, handle, err := ParseSSHCommand(command)
		if !ok || err != nil {
			_ = request.Reply(false, nil)
			return
		}
		operation, err := s.Router.RouteSSH(ctx, handle, verifiedKey, s.VerifierKeyID, ids.NewULID())
		if err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		if service == "git-upload-pack" {
			err = s.Storage.UploadPack(ctx, operation, channel, channel)
		} else {
			err = s.Storage.ReceivePack(ctx, operation, channel, channel)
		}
		status := uint32(0)
		if err != nil {
			status = 1
		}
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, status)
		_, _ = channel.SendRequest("exit-status", false, payload)
		return
	}
}

func canonicalPublicKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func sshCommand(payload []byte) (string, bool) {
	if len(payload) < 4 {
		return "", false
	}
	length := int(binary.BigEndian.Uint32(payload[:4]))
	if length < 0 || length != len(payload)-4 {
		return "", false
	}
	return string(payload[4:]), true
}
