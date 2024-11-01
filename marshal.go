package session

import (
	"encoding/json"
	"errors"
	"fmt"

	testpb "github.com/lstoll/session/internal/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var DefaultMarshaler Marshaler = &JSONMarshaler{}

var errKeyNotFound = errors.New("key not found in map")

type UnmarshaledMap interface {
	Marshal(key string, v any) error
	Unmarshal(key string, v any) error
	Delete(key string)
}

type Marshaler interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	NewMap() UnmarshaledMap
	UnmarshalMap(data []byte) (UnmarshaledMap, error)
	MarshalMap(UnmarshaledMap) ([]byte, error)
}

type JSONMarshaler struct{}

func (*JSONMarshaler) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (*JSONMarshaler) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (*JSONMarshaler) NewMap() UnmarshaledMap {
	return make(jsonMap)
}

func (*JSONMarshaler) UnmarshalMap(data []byte) (UnmarshaledMap, error) {
	m := make(jsonMap)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (*JSONMarshaler) MarshalMap(m UnmarshaledMap) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type jsonMap map[string]json.RawMessage

func (j jsonMap) Marshal(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	j[key] = b
	return nil
}

func (j jsonMap) Unmarshal(key string, v any) error {
	b, ok := j[key]
	if !ok {
		return errKeyNotFound
	}
	if err := json.Unmarshal(b, v); err != nil {
		return nil
	}
	return nil
}

func (j jsonMap) Delete(key string) {
	delete(j, key)
}

type ProtoMarshaler struct{}

func (*ProtoMarshaler) Marshal(v any) ([]byte, error) {
	pv, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("%T is not a proto.Message", v)
	}
	b, err := proto.Marshal(pv)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (*ProtoMarshaler) Unmarshal(data []byte, v any) error {
	pv, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("%#v is not a proto.Message", v)
	}
	if err := proto.Unmarshal(data, pv); err != nil {
		return err
	}
	return nil
}

func (*ProtoMarshaler) NewMap() UnmarshaledMap {
	return &protoMap{
		SessionMap: testpb.SessionMap{
			Data: make(map[string]*anypb.Any),
		},
	}
}

func (*ProtoMarshaler) UnmarshalMap(data []byte) (UnmarshaledMap, error) {
	m := &protoMap{}
	if err := proto.Unmarshal(data, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (*ProtoMarshaler) MarshalMap(m UnmarshaledMap) ([]byte, error) {
	pv, ok := m.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("%T is not a proto.Message", m)
	}
	b, err := proto.Marshal(pv)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type protoMap struct {
	testpb.SessionMap
}

func (j *protoMap) Marshal(key string, v any) error {
	pv, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("%T is not a proto.Message", v)
	}
	a, err := anypb.New(pv)
	if err != nil {
		return err
	}
	j.Data[key] = a
	return nil
}

func (j *protoMap) Unmarshal(key string, v any) error {
	pv, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("%T is not a proto.Message", v)
	}
	a, ok := j.Data[key]
	if !ok {
		return errKeyNotFound
	}
	if err := a.UnmarshalTo(pv); err != nil {
		return nil
	}
	return nil
}

func (j *protoMap) Delete(key string) {
	delete(j.Data, key)
}
