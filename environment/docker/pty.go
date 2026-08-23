package docker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"

	"github.com/pterodactyl/wings/environment"
)

// Interactive PTY terminal support for instance-mode containers.
//
// Each terminal session is a dedicated Docker exec with Tty=true attached over
// a hijacked bidirectional stream. This is what makes real terminal semantics
// possible (Ctrl+C as 0x03, ncurses programs like vim/htop, tab completion,
// cursor movement): the line-based Attach/SendCommand path used for preset
// consoles cannot provide any of that.
//
// A PTY session is independent of the main container attach stream: closing
// the terminal never stops the container, and the container's application
// console keeps flowing through the regular log callback.

// PTYSession is a single interactive terminal attached to the container.
type PTYSession struct {
	id     string
	execID string

	mu     sync.Mutex
	stream *types.HijackedResponse
	closed bool
}

// ID returns the unique identifier of this terminal session.
func (s *PTYSession) ID() string {
	return s.id
}

// Read reads raw PTY output bytes. It blocks until data is available or the
// session is closed (io.EOF afterwards).
func (s *PTYSession) Read(p []byte) (int, error) {
	s.mu.Lock()
	stream := s.stream
	closed := s.closed
	s.mu.Unlock()
	if closed || stream == nil {
		return 0, io.EOF
	}
	return stream.Reader.Read(p)
}

// Write sends raw input bytes to the PTY stdin. This carries terminal input
// verbatim (keystrokes, escape sequences, 0x03 for Ctrl+C) — it is NOT
// line-based.
func (s *PTYSession) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("environment/docker: pty session already closed")
	}
	return s.stream.Conn.Write(p)
}

// Resize updates the PTY geometry. Dimensions are columns/rows, not pixels.
func (e *Environment) ResizePTY(s *PTYSession, cols, rows uint) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.New("environment/docker: pty session already closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.client.ContainerExecResize(ctx, s.execID, container.ResizeOptions{
		Height: rows,
		Width:  cols,
	})
}

// Close terminates the local side of the session. The underlying exec process
// is left to exit on its own (closing the hijacked stream detaches; the exec
// keeps running until the container stops or the process exits).
//
// TODO(dev-1952): grace-period reconnect will keep detached sessions alive
// deliberately; once that lands, expiry-based cleanup should force-execute
// leftover shells via a follow-up exec so nothing leaks.
func (s *PTYSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.stream != nil {
		s.stream.Close()
	}
}

// pickShell determines the login shell available inside the container by
// probing with short-lived execs. Preference order matches the Instance
// contract: bash, then zsh, then plain sh.
func (e *Environment) pickShell(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for _, shell := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
		id, err := e.client.ContainerExecCreate(ctx, e.Id, container.ExecOptions{
			Cmd:          []string{"command", "-v", shell},
			AttachStdout: true,
		})
		if err != nil {
			return "", errors.WrapIf(err, "environment/docker: failed to create shell probe exec")
		}
		resp, err := e.client.ContainerExecAttach(ctx, id.ID, container.ExecAttachOptions{})
		if err != nil {
			continue
		}
		out, _ := io.ReadAll(resp.Reader)
		resp.Close()
		if len(out) > 0 {
			return shell, nil
		}
	}
	return "", errors.New("environment/docker: no supported shell found in container")
}

// nextPtyID returns a monotonically increasing session identifier.
var ptyCounter uint64
var ptyCounterMu sync.Mutex

func nextPtyID() string {
	ptyCounterMu.Lock()
	defer ptyCounterMu.Unlock()
	ptyCounter += 1
	return fmt.Sprintf("pty-%d", ptyCounter)
}

// OpenPTY creates and starts a new interactive PTY terminal session inside
// the running container. Only instance-mode containers may open terminals:
// preset containers keep their line-based application console exclusively.
func (e *Environment) OpenPTY(ctx context.Context, cols, rows uint) (*PTYSession, error) {
	if mode, _, _ := e.ExecutionContract(); mode != "" && mode != "instance" {
		return nil, errors.New("environment/docker: pty terminal is only available for instance containers")
	}

	state := e.State()
	if state != environment.ProcessRunningState && state != environment.ProcessStartingState {
		return nil, errors.New("environment/docker: container is not running")
	}

	shell, err := e.pickShell(ctx)
	if err != nil {
		return nil, err
	}

	consoleSize := [2]uint{rows, cols}
	create, err := e.client.ContainerExecCreate(ctx, e.Id, container.ExecOptions{
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		ConsoleSize:  &consoleSize,
		Env:          []string{"TERM=xterm-256color", "COLORTERM=truecolor"},
		Cmd:          []string{shell, "-l"},
	})
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to create pty exec")
	}

	resp, err := e.client.ContainerExecAttach(ctx, create.ID, container.ExecAttachOptions{
		Tty:          true,
		ConsoleSize:  &consoleSize,
	})
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to attach pty exec")
	}

	session := &PTYSession{
		id:     nextPtyID(),
		execID: create.ID,
		stream: &resp,
	}

	e.log().WithField("session", session.id).WithField("shell", shell).Debug("opened pty terminal session")
	return session, nil
}
