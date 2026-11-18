package userland

// Threats: fixed command names, required authorization, bounded streams and
// deadlines prevent arbitrary worker selection and unbounded RPC execution.
// Workers run as the daemon UID, with that UID's filesystem access. They are
// process-isolated, not sandboxed. The daemon must never run as root.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/userland/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
)

const (
	MaxMessage  = 128 << 10
	ChunkSize   = 32 << 10
	MaxBytes    = 64 << 20
	MaxDuration = 30 * time.Second
)

var commands = []string{"cat", "find", "grep", "head", "ls"}

func ValidateStart(s *pb.Start) error {
	if s == nil || len(s.Argv) == 0 || len(s.Argv) > 256 || !slices.Contains(commands, s.Argv[0]) {
		return fmt.Errorf("userland: expected one of cat, find, grep, head, ls (at most 256 arguments)")
	}
	size := len(s.Directory)
	if !filepath.IsAbs(s.Directory) || strings.ContainsRune(s.Directory, 0) {
		return fmt.Errorf("userland: absolute working directory required")
	}
	for _, arg := range s.Argv {
		size += len(arg)
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("userland: NUL in argument")
		}
	}
	if size > ChunkSize {
		return fmt.Errorf("userland: arguments exceed 32 KiB")
	}
	return nil
}

type Config struct {
	Worker    string
	Authorize func(context.Context, []string) error
	// Record runs before execution and after completion; failures deny success.
	Record func(context.Context, []string, string) error
}
type server struct {
	pb.UnimplementedUserlandServer
	cfg   Config
	slots chan struct{}
}

func NewServer(cfg Config) (*grpc.Server, error) {
	if cfg.Authorize == nil || cfg.Record == nil {
		return nil, fmt.Errorf("userland: authorization and audit are required")
	}
	if !filepath.IsAbs(cfg.Worker) {
		return nil, fmt.Errorf("userland: absolute worker path required")
	}
	info, err := os.Stat(cfg.Worker)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("userland: worker must be executable")
	}
	s := grpc.NewServer(grpc.Creds(local.NewCredentials()), grpc.MaxRecvMsgSize(MaxMessage), grpc.MaxSendMsgSize(MaxMessage), grpc.ConnectionTimeout(5*time.Second), grpc.MaxConcurrentStreams(32), grpc.WaitForHandlers(true))
	pb.RegisterUserlandServer(s, &server{cfg: cfg, slots: make(chan struct{}, 32)})
	return s, nil
}
func (s *server) Describe(context.Context, *pb.DescribeRequest) (*pb.DescribeResponse, error) {
	return &pb.DescribeResponse{Protocol: "adssh.userland.v1", Implementation: "u-root v0.16.0", Commands: append([]string(nil), commands...)}, nil
}

type received struct {
	msg *pb.ExecuteRequest
	err error
}

func (s *server) Execute(stream grpc.BidiStreamingServer[pb.ExecuteRequest, pb.ExecuteResponse]) (resultErr error) {
	ctx, cancel := context.WithTimeout(stream.Context(), MaxDuration)
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return status.Error(codes.ResourceExhausted, "userland: execution limit reached")
	}
	first := make(chan received, 1)
	go func() { m, e := stream.Recv(); first <- received{m, e} }()
	var start *pb.Start
	select {
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case r := <-first:
		if r.err != nil {
			return status.Error(codes.InvalidArgument, "userland: missing start")
		}
		start = r.msg.GetStart()
	}
	if err := ValidateStart(start); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.cfg.Authorize(ctx, start.Argv); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if err := s.cfg.Record(ctx, start.Argv, "start"); err != nil {
		return status.Error(codes.Internal, "userland: audit failed")
	}

	completed := false
	defer func() {
		if !completed {
			auditCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if err := s.cfg.Record(auditCtx, start.Argv, "aborted"); err != nil {
				resultErr = errors.Join(resultErr, status.Error(codes.Internal, "userland: audit failed"))
			}
		}
	}()

	cmd := exec.CommandContext(ctx, s.cfg.Worker, start.Argv...)
	cmd.Dir = start.Directory
	// No caller-supplied environment or inherited daemon secrets.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	input, err := cmd.StdinPipe()
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	out := &outputStream{ctx: ctx, stream: stream, cancel: cancel}
	cmd.Stdout = &outputWriter{out: out}
	cmd.Stderr = &outputWriter{out: out, stderr: true}
	if err := cmd.Start(); err != nil {
		return closeWithError(input, status.Error(codes.Internal, err.Error()))
	}
	waited := make(chan error, 1)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); waited <- cmd.Wait() }()
	defer func() {
		cancel()
		if err := input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			resultErr = errors.Join(resultErr, err)
		}
		<-workerDone
	}()
	inputErr := make(chan error, 1)
	go func() { inputErr <- receiveInput(stream, input) }()
	var waitErr error
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case err := <-inputErr:
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
			inputErr = nil
		case waitErr = <-waited:
			if err := out.failure(); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			code := 0
			if waitErr != nil {
				var exit *exec.ExitError
				if !errors.As(waitErr, &exit) {
					return status.Error(codes.Internal, waitErr.Error())
				}
				code = exit.ExitCode()
				if code < 0 {
					code = 128
				}
			}
			if err := s.cfg.Record(ctx, start.Argv, fmt.Sprintf("exit=%d", code)); err != nil {
				return status.Error(codes.Internal, "userland: audit failed")
			}
			completed = true
			// The send is bounded by the same deadline even for a peer that stops reading.
			sent := make(chan error, 1)
			go func() {
				sent <- stream.Send(&pb.ExecuteResponse{Event: &pb.ExecuteResponse_Exit{Exit: &pb.Exit{Code: int32(code)}}})
			}()
			select {
			case err := <-sent:
				return err
			case <-ctx.Done():
				return status.FromContextError(ctx.Err()).Err()
			}
		}
	}
}

func receiveInput(stream grpc.BidiStreamingServer[pb.ExecuteRequest, pb.ExecuteResponse], dst io.WriteCloser) error {
	total := 0
	for {
		m, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("userland: stdin missing EOF frame")
			}
			return err
		}
		switch e := m.Event.(type) {
		case *pb.ExecuteRequest_Stdin:
			total += len(e.Stdin)
			if len(e.Stdin) > ChunkSize || total > MaxBytes {
				return fmt.Errorf("userland: stdin limit exceeded")
			}
			if _, err := dst.Write(e.Stdin); err != nil {
				if errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrClosed) {
					return nil
				}
				return err
			}
		case *pb.ExecuteRequest_Eof:
			if !e.Eof {
				return fmt.Errorf("userland: invalid EOF")
			}
			if err := dst.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				return err
			}
			return nil
		default:
			return fmt.Errorf("userland: expected stdin or EOF")
		}
	}
}

type outputStream struct {
	ctx    context.Context
	mu     sync.Mutex
	stream grpc.BidiStreamingServer[pb.ExecuteRequest, pb.ExecuteResponse]
	cancel context.CancelFunc
	total  int
	err    error
}

func (o *outputStream) failure() error { o.mu.Lock(); defer o.mu.Unlock(); return o.err }

type outputWriter struct {
	out    *outputStream
	stderr bool
}

func (w *outputWriter) Write(p []byte) (int, error) {
	o := w.out
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return 0, o.err
	}
	if o.total+len(p) > MaxBytes {
		o.err = status.Error(codes.ResourceExhausted, "userland: output limit exceeded")
		o.cancel()
		return 0, o.err
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), ChunkSize)
		m := &pb.ExecuteResponse{Event: &pb.ExecuteResponse_Stdout{Stdout: append([]byte(nil), p[:n]...)}}
		if w.stderr {
			m.Event = &pb.ExecuteResponse_Stderr{Stderr: append([]byte(nil), p[:n]...)}
		}
		sent := make(chan error, 1)
		go func() { sent <- o.stream.Send(m) }()
		var sendErr error
		select {
		case sendErr = <-sent:
		case <-o.ctx.Done():
			sendErr = status.FromContextError(o.ctx.Err()).Err()
		}
		if err := sendErr; err != nil {
			o.err = err
			o.cancel()
			return written, err
		}
		written += n
		o.total += n
		p = p[n:]
	}
	return written, nil
}
