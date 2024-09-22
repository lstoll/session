package session

type sessCtxKey struct{}

type mgrCtxKey struct{}

type sessCtx struct {
	sessions map[string]*sessCtxSess
}

type sessCtxSess struct {
	// data is the actuall session data, untyped
	data   any
	delete bool
	save   bool
}
