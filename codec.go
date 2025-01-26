package session

import (
	"fmt"
	"time"

	sessionv1 "github.com/lstoll/session/internal/proto/lstoll/session/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sessionMetadata struct {
	CreatedAt time.Time
}

type codec interface {
	Encode(data any, md *sessionMetadata) ([]byte, error)
	Decode(data []byte, into any) (*sessionMetadata, error)
}

var _ codec = (*protoCodec)(nil)

type protoCodec struct {
}

func (p *protoCodec) Encode(data any, md *sessionMetadata) ([]byte, error) {
	datapb, ok := data.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("failed to convert %T to proto.Message", data)
	}
	dataany, err := anypb.New(datapb)
	if err != nil {
		return nil, fmt.Errorf("encoding data as any: %w", err)
	}

	wr := sessionv1.Session_builder{
		Data:      dataany,
		CreatedAt: timestamppb.New(md.CreatedAt),
	}.Build()

	return proto.Marshal(wr)
}

func (p *protoCodec) Decode(data []byte, into any) (*sessionMetadata, error) {
	intopb, ok := into.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("failed to convert %T to proto.Message", into)
	}

	spb := new(sessionv1.Session)
	if err := proto.Unmarshal(data, spb); err != nil {
		return nil, fmt.Errorf("unmarshaling session: %w", err)
	}

	if err := spb.GetData().UnmarshalTo(intopb); err != nil {
		return nil, fmt.Errorf("unmarshaling session data: %w", err)
	}

	return &sessionMetadata{
		CreatedAt: spb.GetCreatedAt().AsTime(),
	}, nil
}
