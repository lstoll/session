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
	// we should continue with what we were doing, or if we should interupt the
	// response because it handled it.
	hook     func(http.ResponseWriter) bool
	hookOnce sync.Once
	sctx     *Session
}

func (h *hookRW) Write(b []byte) (int, error) {
	if h.sctx != nil && h.sctx.aborted {
		return 0, http.ErrAbortHandler
	}
	write := true
	h.hookOnce.Do(func() {
		write = h.hook(h.ResponseWriter)
	})
	if !write {
		return 0, errors.New("request interrupted by hook")
	}
	return h.ResponseWriter.Write(b)
}

func (h *hookRW) WriteHeader(statusCode int) {
	if h.sctx != nil && h.sctx.aborted {
		return
	}
	write := true
	h.hookOnce.Do(func() {
		write = h.hook(h.ResponseWriter)
	})
	if write {
		h.ResponseWriter.WriteHeader(statusCode)
	}
}

func (h *hookRW) Unwrap() http.ResponseWriter {
	return h.ResponseWriter
}

// FlushError commits session state before flushing buffered response data.
func (h *hookRW) FlushError() error {
	if h.sctx != nil && h.sctx.aborted {
		return http.ErrAbortHandler
	}
	write := true
	h.hookOnce.Do(func() { write = h.hook(h.ResponseWriter) })
	if !write {
		return errors.New("request interrupted by hook")
	}
	return http.NewResponseController(h.ResponseWriter).Flush()
}

func (h *hookRW) Flush() {
	_ = h.FlushError()
}

func (h *hookRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.sctx != nil && h.sctx.aborted {
		return nil, nil, http.ErrAbortHandler
	}
	write := true
	h.hookOnce.Do(func() { write = h.hook(h.ResponseWriter) })
	if !write {
		return nil, nil, errors.New("request interrupted by hook")
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
	if h.sctx != nil && h.sctx.aborted {
		return 0, http.ErrAbortHandler
	}
	write := true
	h.hookOnce.Do(func() { write = h.hook(h.ResponseWriter) })
	if !write {
		return 0, errors.New("request interrupted by hook")
	}
	if rf, ok := h.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(h.ResponseWriter, r)
}
