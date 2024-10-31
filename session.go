package session

type Sessionable interface {
	// New() Sessionable

	SessionName() string
	SessionValid() bool
}
