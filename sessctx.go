package session

type sessCtxKey struct{ name string }

type sessCtx[T Sessionable] struct {
	// data is the actuall session data, untyped
	data   any
	delete bool
	save   bool
}
