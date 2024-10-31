package session

import "encoding/json"

var DefaultMarshaler Marshaler = &JSONMarshaler{}

type Marshaler interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

type JSONMarshaler struct{}

func (*JSONMarshaler) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (*JSONMarshaler) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
