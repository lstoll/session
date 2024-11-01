export PATH := hack:$(PATH)

internal/proto/test.pb.go: internal/proto/test.proto
	protoc -Iinternal/proto --go_out=internal/proto  --go_opt=paths=source_relative test.proto
