package userland

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/afterdarksys/adssh/internal/userland/pb"
	"github.com/muesli/cancelreader"
	"google.golang.org/grpc"
)

// Execute streams a command and returns its process exit code separately from
// transport failure. stdin must be a file or an in-memory reader so an early
// worker exit cannot leave a goroutine consuming the next shell command.
func Execute(ctx context.Context, conn *grpc.ClientConn, start *pb.Start, stdin io.Reader, stdout, stderr io.Writer) (code int, err error) {
	if err := ValidateStart(start); err != nil {
		return 0, err
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	switch stdin.(type) {
	case cancelreader.File, *bytes.Reader, *bytes.Buffer, *strings.Reader:
	default:
		return 0, fmt.Errorf("userland: stdin must be a cancellable file or in-memory reader")
	}
	reader, err := cancelreader.NewReader(stdin)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	defer func() { err = errors.Join(err, reader.Close()) }()
	stream, err := pb.NewUserlandClient(conn).Execute(ctx)
	if err != nil {
		return 0, err
	}
	if err := stream.Send(&pb.ExecuteRequest{Event: &pb.ExecuteRequest_Start{Start: start}}); err != nil {
		return 0, err
	}
	sent := make(chan struct{})
	var sendErr error
	go func() {
		defer close(sent)
		sendErr = sendInput(stream, reader)
		if sendErr != nil && !errors.Is(sendErr, io.EOF) {
			cancel()
		}
	}()
	defer func() { cancel(); reader.Cancel(); <-sent }()
	for {
		msg, recvErr := stream.Recv()
		if recvErr != nil {
			if recvErr == io.EOF {
				return 0, fmt.Errorf("userland: stream ended without exit status")
			}
			return 0, recvErr
		}
		switch e := msg.Event.(type) {
		case *pb.ExecuteResponse_Stdout:
			if _, err := stdout.Write(e.Stdout); err != nil {
				return 0, err
			}
		case *pb.ExecuteResponse_Stderr:
			if _, err := stderr.Write(e.Stderr); err != nil {
				return 0, err
			}
		case *pb.ExecuteResponse_Exit:
			if e.Exit == nil || e.Exit.Code < 0 || e.Exit.Code > 255 {
				return 0, fmt.Errorf("userland: invalid exit status")
			}
			// Require the final RPC status too: a transport error must not become success.
			if _, err := stream.Recv(); err != io.EOF {
				if err == nil {
					err = fmt.Errorf("userland: frame after exit")
				}
				return 0, err
			}
			select {
			case <-sent:
				if sendErr != nil && !errors.Is(sendErr, io.EOF) {
					return 0, sendErr
				}
			default:
			}
			return int(e.Exit.Code), nil
		default:
			return 0, fmt.Errorf("userland: unknown response frame")
		}
	}
}

func sendInput(stream grpc.BidiStreamingClient[pb.ExecuteRequest, pb.ExecuteResponse], input io.Reader) error {
	buf := make([]byte, ChunkSize)
	total := 0
	for {
		n, err := input.Read(buf)
		total += n
		if total > MaxBytes {
			return fmt.Errorf("userland: stdin exceeds 64 MiB")
		}
		if n > 0 {
			if e := stream.Send(&pb.ExecuteRequest{Event: &pb.ExecuteRequest_Stdin{Stdin: buf[:n]}}); e != nil {
				return e
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			if err := stream.Send(&pb.ExecuteRequest{Event: &pb.ExecuteRequest_Eof{Eof: true}}); err != nil {
				return err
			}
			return stream.CloseSend()
		}
	}
}
