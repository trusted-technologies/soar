package websocket

// Instance terminal (PTY) support over the existing authenticated server
// websocket. The terminal data path is deliberately separate from the JSON
// event stream used by the preset application console: PTY bytes travel as
// base64 strings inside "pty data" frames so a single websocket serves both
// transports, while the semantics stay raw-byte oriented.
//
// Protocol (all frames are the standard {event, args} Message):
//
//	client → "pty open"   [session_id?, cols, rows]        → opens a new session
//	client → "pty data"   [session_id, base64(bytes)]      → stdin (raw keystrokes)
//	client → "pty resize" [session_id, cols, rows]         → real ExecResize
//	client → "pty close"  [session_id]                     → detach/close
//
//	server → "pty open"   [{id}]                           → session accepted
//	server → "pty data"   [session_id, base64(bytes)]      → stdout/stderr
//	server → "pty exit"   [session_id, exit_code_json]     → exec finished
//	server → errors via the standard daemon error / jwt error events.
//
// Ctrl+C is NOT an event here — it arrives as byte 0x03 inside pty data and
// the PTY delivers SIGINT to the foreground process itself.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync"

	"emperror.dev/errors"

	"github.com/pterodactyl/wings/environment/docker"
)

// PtyExitEvent is published when a PTY exec finishes; args are
// [session_id, exit_code_json].
const PtyExitEvent = Event("pty exit")

const (
	PermissionOpenPty = "control.console"

	// maxPtySessionsPerServer bounds concurrent docker exec sessions so a
	// client cannot leak thousands of shells on one container.
	maxPtySessionsPerServer = 4
)

// ptySessionRegistry tracks live PTY sessions per websocket handler. Sessions
// die with the handler's connection context; multi-connection sharing and
// reconnect grace periods are a later step of the terminal roadmap.
type ptySessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*docker.PTYSession
}

func newPtySessionRegistry() *ptySessionRegistry {
	return &ptySessionRegistry{sessions: make(map[string]*docker.PTYSession)}
}

func (r *ptySessionRegistry) add(s *docker.PTYSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sessions) >= maxPtySessionsPerServer {
		return false
	}
	r.sessions[s.ID()] = s
	return true
}

func (r *ptySessionRegistry) get(id string) (*docker.PTYSession, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

func (r *ptySessionRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}

func (r *ptySessionRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		s.Close()
		delete(r.sessions, id)
	}
}

var ptyRegistriesMu sync.Mutex
var ptyRegistries = map[*Handler]*ptySessionRegistry{}

func (h *Handler) ptyRegistry() *ptySessionRegistry {
	ptyRegistriesMu.Lock()
	defer ptyRegistriesMu.Unlock()
	if r, ok := ptyRegistries[h]; ok {
		return r
	}
	r := newPtySessionRegistry()
	ptyRegistries[h] = r
	return r
}

// CleanupPtySessions closes every PTY session opened over this handler. The
// websocket read loop calls it when the connection dies; sessions are not yet
// kept alive across reconnects (grace period comes later in the roadmap).
func (h *Handler) CleanupPtySessions() {
	ptyRegistriesMu.Lock()
	defer ptyRegistriesMu.Unlock()
	if r, ok := ptyRegistries[h]; ok {
		r.closeAll()
		delete(ptyRegistries, h)
	}
}

// ptyEnv returns the docker environment if this server runs under one.
func (h *Handler) ptyEnv() (*docker.Environment, error) {
	if e, ok := h.server.Environment.(*docker.Environment); ok {
		return e, nil
	}
	return nil, errors.New("websocket: server environment does not support pty terminals")
}

func (h *Handler) handlePtyOpen(ctx context.Context, m Message) error {
	env, err := h.ptyEnv()
	if err != nil {
		return err
	}

	cols, rows := parsePtySize(m.Args)
	session, err := env.OpenPTY(ctx, cols, rows)
	if err != nil {
		return err
	}
	if !h.ptyRegistry().add(session) {
		session.Close()
		return errors.New("websocket: too many concurrent pty sessions for this server")
	}

	idJson, _ := json.Marshal(map[string]string{"id": session.ID()})
	_ = h.SendJson(Message{Event: PtyOpenEvent, Args: []string{string(idJson)}})

	// Pump PTY output to this websocket for the lifetime of the session.
	go h.pumpPtyOutput(session)

	return nil
}

// pumpPtyOutput streams raw PTY bytes to the client as base64 data frames.
// Bounded chunks keep single websocket messages well below daemon limits;
// backpressure beyond that is handled by the socket write itself blocking.
func (h *Handler) pumpPtyOutput(session *docker.PTYSession) {
	defer func() {
		h.ptyRegistry().remove(session.ID())
		session.Close()
	}()

	buf := make([]byte, 8*1024)
	for {
		n, err := session.Read(buf)
		if n > 0 {
			frame := base64.StdEncoding.EncodeToString(buf[:n])
			if sendErr := h.SendJson(Message{
				Event: PtyDataEvent,
				Args:  []string{session.ID(), frame},
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			_ = h.SendJson(Message{Event: PtyExitEvent, Args: []string{session.ID(), "null"}})
			return
		}
	}
}

func (h *Handler) handlePtyData(m Message) error {
	if len(m.Args) < 2 {
		return errors.New("websocket: pty data requires session id and payload")
	}
	session, ok := h.ptyRegistry().get(m.Args[0])
	if !ok {
		return errors.New("websocket: unknown pty session")
	}
	data, err := base64.StdEncoding.DecodeString(m.Args[1])
	if err != nil {
		return errors.Wrap(err, "websocket: invalid pty data encoding")
	}
	_, err = session.Write(data)
	return err
}

func (h *Handler) handlePtyResize(m Message) error {
	if len(m.Args) < 3 {
		return errors.New("websocket: pty resize requires session id, cols and rows")
	}
	session, ok := h.ptyRegistry().get(m.Args[0])
	if !ok {
		return errors.New("websocket: unknown pty session")
	}
	cols, err := strconv.ParseUint(m.Args[1], 10, 16)
	if err != nil {
		return errors.New("websocket: invalid cols value")
	}
	rows, err := strconv.ParseUint(m.Args[2], 10, 16)
	if err != nil {
		return errors.New("websocket: invalid rows value")
	}
	env, err := h.ptyEnv()
	if err != nil {
		return err
	}
	return env.ResizePTY(session, uint(cols), uint(rows))
}

func (h *Handler) handlePtyClose(m Message) error {
	if len(m.Args) < 1 {
		return errors.New("websocket: pty close requires session id")
	}
	session, ok := h.ptyRegistry().get(m.Args[0])
	if !ok {
		return nil
	}
	h.ptyRegistry().remove(session.ID())
	session.Close()
	return nil
}

// parsePtySize extracts optional [session_id?, cols, rows] from an open
// request, defaulting to a sane initial geometry.
func parsePtySize(args []string) (uint, uint) {
	const def = 80
	// Accept both [cols, rows] and [session_id, cols, rows]; only numbers
	// matter here since the session id is generated daemon-side.
	var nums []uint64
	for _, a := range args {
		if v, err := strconv.ParseUint(a, 10, 32); err == nil {
			nums = append(nums, v)
		}
	}
	if len(nums) >= 2 {
		return clampPtyDim(nums[len(nums)-2]), clampPtyDim(nums[len(nums)-1])
	}
	return def, 24
}

func clampPtyDim(v uint64) uint {
	if v < 2 {
		return 2
	}
	if v > 500 {
		return 500
	}
	return uint(v)
}
