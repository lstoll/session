package session

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

var _ interface {
	http.ResponseWriter
	Unwrap() http.ResponseWriter
} = (*hookRW)(nil)

// hookRW can be used to trigger an action before the response writing starts,
// in our case saving the session. It will only be called once
type hookRW struct {
	http.ResponseWriter
	// hook is called with the responsewriter. it returns a bool indicating if
	// we should continue with what we were doing, or if we should interrupt the
	// response because it handled it.
	hook       func(http.ResponseWriter) bool
	hookOnce   sync.Once
	allowWrite bool
	committed  bool
	aborted    func() bool
}

func (h *hookRW) beforeWrite() error {
	if h.aborted != nil && h.aborted() {
		return http.ErrAbortHandler
	}
	h.hookOnce.Do(func() {
		h.committed = true
		h.allowWrite = h.hook(h.ResponseWriter)
	})
	if !h.allowWrite {
		return errors.New("request interrupted by hook")
	}
	return nil
}

func (h *hookRW) Write(b []byte) (int, error) {
	if err := h.beforeWrite(); err != nil {
		return 0, err
	}
	return h.ResponseWriter.Write(b)
}

func (h *hookRW) WriteHeader(statusCode int) {
	// Informational responses other than protocol switching do not commit the
	// final response headers in net/http, so they must not commit the session.
	if statusCode >= 100 && statusCode <= 199 && statusCode != http.StatusSwitchingProtocols {
		h.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if h.beforeWrite() != nil {
		return
	}
	h.ResponseWriter.WriteHeader(statusCode)
}

func (h *hookRW) responseCommitted() bool {
	return h.committed
}

func (h *hookRW) Unwrap() http.ResponseWriter {
	return h.ResponseWriter
}

// FlushError commits session state before flushing buffered response data.
func (h *hookRW) FlushError() error {
	if err := h.beforeWrite(); err != nil {
		return err
	}
	return http.NewResponseController(h.ResponseWriter).Flush()
}

func (h *hookRW) Flush() {
	_ = h.FlushError()
}

func (h *hookRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if err := h.beforeWrite(); err != nil {
		return nil, nil, err
	}
	return http.NewResponseController(h.ResponseWriter).Hijack()
}

func (h *hookRW) Push(target string, opts *http.PushOptions) error {
	p, ok := h.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

func (h *hookRW) ReadFrom(r io.Reader) (int64, error) {
	if err := h.beforeWrite(); err != nil {
		return 0, err
	}
	if rf, ok := h.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(h.ResponseWriter, r)
}
