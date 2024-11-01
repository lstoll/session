package session

import (
	"reflect"
	"testing"

	testpb "github.com/lstoll/session/internal/proto"
	"google.golang.org/protobuf/proto"
)

func TestMarshal(t *testing.T) {
	type testJsonType struct {
		Message string `json:"message"`
	}
	for _, tc := range []struct {
		Name         string
		Marshaler    Marshaler
		NewEmpty     func() any
		NewPopulated func() any
	}{
		{
			Name:      "JSON",
			Marshaler: &JSONMarshaler{},
			NewEmpty: func() any {
				return &testJsonType{}
			},
			NewPopulated: func() any {
				return &testJsonType{
					Message: "hello",
				}
			},
		},
		{
			Name:      "Proto",
			Marshaler: &ProtoMarshaler{},
			NewEmpty: func() any {
				return &testpb.Session{}
			},
			NewPopulated: func() any {
				return &testpb.Session{
					Message: "hello",
				}
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			origsd := tc.NewPopulated()
			b, err := tc.Marshaler.Marshal(origsd)
			if err != nil {
				t.Fatal(err)
			}

			unmarshalsd := tc.NewEmpty()
			if err := tc.Marshaler.Unmarshal(b, unmarshalsd); err != nil {
				t.Fatal(err)
			}

			assertEqual(t, origsd, unmarshalsd)

			origMap := tc.Marshaler.NewMap()
			if err := origMap.Marshal("test", origsd); err != nil {
				t.Fatal(err)
			}

			mb, err := tc.Marshaler.MarshalMap(origMap)
			if err != nil {
				t.Fatal(err)
			}

			unmarshalMap, err := tc.Marshaler.UnmarshalMap(mb)
			if err != nil {
				t.Fatal(err)
			}

			if err := unmarshalMap.Unmarshal("test", unmarshalsd); err != nil {
				t.Fatal(err)
			}

			assertEqual(t, origsd, unmarshalsd)
		})
	}
}

func assertEqual(t *testing.T, x any, y any) {
	xpb, xpbok := x.(proto.Message)
	ypb, ypbok := x.(proto.Message)
	if xpbok && ypbok {
		if !proto.Equal(xpb, ypb) {
			t.Errorf("proto.Message want %#v, got: %#v", xpb, ypb)
		}
		return
	}
	if !reflect.DeepEqual(x, y) {
		t.Errorf("want %#v, got: %#v", x, y)
	}
}
