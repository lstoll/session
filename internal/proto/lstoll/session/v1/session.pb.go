// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.2
// 	protoc        (unknown)
// source: lstoll/session/v1/session.proto

package sessionv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/gofeaturespb"
	anypb "google.golang.org/protobuf/types/known/anypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Session struct {
	state                protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Data      *anypb.Any             `protobuf:"bytes,1,opt,name=data" json:"data,omitempty"`
	xxx_hidden_CreatedAt *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=created_at,json=createdAt" json:"created_at,omitempty"`
	xxx_hidden_UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=updated_at,json=updatedAt" json:"updated_at,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *Session) Reset() {
	*x = Session{}
	mi := &file_lstoll_session_v1_session_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_lstoll_session_v1_session_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Session) GetData() *anypb.Any {
	if x != nil {
		return x.xxx_hidden_Data
	}
	return nil
}

func (x *Session) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.xxx_hidden_CreatedAt
	}
	return nil
}

func (x *Session) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.xxx_hidden_UpdatedAt
	}
	return nil
}

func (x *Session) SetData(v *anypb.Any) {
	x.xxx_hidden_Data = v
}

func (x *Session) SetCreatedAt(v *timestamppb.Timestamp) {
	x.xxx_hidden_CreatedAt = v
}

func (x *Session) SetUpdatedAt(v *timestamppb.Timestamp) {
	x.xxx_hidden_UpdatedAt = v
}

func (x *Session) HasData() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Data != nil
}

func (x *Session) HasCreatedAt() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_CreatedAt != nil
}

func (x *Session) HasUpdatedAt() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_UpdatedAt != nil
}

func (x *Session) ClearData() {
	x.xxx_hidden_Data = nil
}

func (x *Session) ClearCreatedAt() {
	x.xxx_hidden_CreatedAt = nil
}

func (x *Session) ClearUpdatedAt() {
	x.xxx_hidden_UpdatedAt = nil
}

type Session_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Data      *anypb.Any
	CreatedAt *timestamppb.Timestamp
	UpdatedAt *timestamppb.Timestamp
}

func (b0 Session_builder) Build() *Session {
	m0 := &Session{}
	b, x := &b0, m0
	_, _ = b, x
	x.xxx_hidden_Data = b.Data
	x.xxx_hidden_CreatedAt = b.CreatedAt
	x.xxx_hidden_UpdatedAt = b.UpdatedAt
	return m0
}

var File_lstoll_session_v1_session_proto protoreflect.FileDescriptor

var file_lstoll_session_v1_session_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x6c, 0x73, 0x74, 0x6f, 0x6c, 0x6c, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x11, 0x6c, 0x73, 0x74, 0x6f, 0x6c, 0x6c, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x21, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x67, 0x6f, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xa9, 0x01, 0x0a, 0x07, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x28, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x41, 0x6e, 0x79, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x42,
	0x3c, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x73,
	0x74, 0x6f, 0x6c, 0x6c, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x76, 0x31, 0x92, 0x03, 0x05, 0xd2, 0x3e, 0x02, 0x10, 0x03, 0x62, 0x08, 0x65,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x70, 0xe8, 0x07,
}

var file_lstoll_session_v1_session_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_lstoll_session_v1_session_proto_goTypes = []any{
	(*Session)(nil),               // 0: lstoll.session.v1.Session
	(*anypb.Any)(nil),             // 1: google.protobuf.Any
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_lstoll_session_v1_session_proto_depIdxs = []int32{
	1, // 0: lstoll.session.v1.Session.data:type_name -> google.protobuf.Any
	2, // 1: lstoll.session.v1.Session.created_at:type_name -> google.protobuf.Timestamp
	2, // 2: lstoll.session.v1.Session.updated_at:type_name -> google.protobuf.Timestamp
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_lstoll_session_v1_session_proto_init() }
func file_lstoll_session_v1_session_proto_init() {
	if File_lstoll_session_v1_session_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_lstoll_session_v1_session_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_lstoll_session_v1_session_proto_goTypes,
		DependencyIndexes: file_lstoll_session_v1_session_proto_depIdxs,
		MessageInfos:      file_lstoll_session_v1_session_proto_msgTypes,
	}.Build()
	File_lstoll_session_v1_session_proto = out.File
	file_lstoll_session_v1_session_proto_rawDesc = nil
	file_lstoll_session_v1_session_proto_goTypes = nil
	file_lstoll_session_v1_session_proto_depIdxs = nil
}
