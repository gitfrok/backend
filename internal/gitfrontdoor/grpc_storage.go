package gitfrontdoor

import (
	"context"
	"errors"
	"io"
	"slices"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
)

// GRPCStorage adapts the internal GitStorage client to the transport-neutral
// Storage port. It sends the authenticated context first and streams protocol
// chunks in both directions without retaining a Git pack in memory.
type GRPCStorage struct {
	Client gitv1.GitStorageClient
}

func (s GRPCStorage) UploadPack(ctx context.Context, operation *gitv1.OperationContext, input io.Reader, output io.Writer) error {
	if s.Client == nil {
		return ErrDenied
	}
	stream, err := s.Client.UploadPack(ctx)
	if err != nil {
		return err
	}
	return bridge(ctx, input, output,
		func() error {
			return stream.Send(&gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Context{Context: operation}})
		},
		func(data []byte) error {
			return stream.Send(&gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Data{Data: data}})
		},
		func() error {
			if err := stream.Send(&gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Close{Close: true}}); err != nil {
				return err
			}
			return stream.CloseSend()
		},
		func() ([]byte, error) {
			response, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return response.GetData(), nil
		},
	)
}

func (s GRPCStorage) ReceivePack(ctx context.Context, operation *gitv1.OperationContext, input io.Reader, output io.Writer) error {
	if s.Client == nil {
		return ErrDenied
	}
	stream, err := s.Client.ReceivePack(ctx)
	if err != nil {
		return err
	}
	return bridge(ctx, input, output,
		func() error {
			return stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Context{Context: operation}})
		},
		func(data []byte) error {
			return stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Data{Data: data}})
		},
		func() error {
			if err := stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Close{Close: true}}); err != nil {
				return err
			}
			return stream.CloseSend()
		},
		func() ([]byte, error) {
			response, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return response.GetData(), nil
		},
	)
}

type sendContext func() error
type sendChunk func([]byte) error
type closeStream func() error
type receiveChunk func() ([]byte, error)

func bridge(parent context.Context, input io.Reader, output io.Writer, sendFirst sendContext, sendData sendChunk, closeInput closeStream, receive receiveChunk) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	sendResult := make(chan error, 1)
	go func() {
		if err := sendFirst(); err != nil {
			sendResult <- err
			return
		}
		buffer := make([]byte, 32*1024)
		for {
			count, err := input.Read(buffer)
			if count > 0 {
				if sendErr := sendData(slices.Clone(buffer[:count])); sendErr != nil {
					sendResult <- sendErr
					return
				}
			}
			if errors.Is(err, io.EOF) {
				sendResult <- closeInput()
				return
			}
			if err != nil {
				sendResult <- err
				return
			}
			select {
			case <-ctx.Done():
				sendResult <- ctx.Err()
				return
			default:
			}
		}
	}()

	for {
		data, err := receive()
		if errors.Is(err, io.EOF) {
			return <-sendResult
		}
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if _, err := output.Write(data); err != nil {
				return err
			}
		}
	}
}
