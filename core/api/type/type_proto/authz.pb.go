// Code generated by protoc-gen-go. DO NOT EDIT.
// source: type/type_proto/authz.proto

package type_proto

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Permission specifies the permission a role can take.
type Permission int32

const (
	// LOG indicates whether access to resources will be logged.
	Permission_LOG   Permission = 0
	Permission_READ  Permission = 1
	Permission_WRITE Permission = 2
)

var Permission_name = map[int32]string{
	0: "LOG",
	1: "READ",
	2: "WRITE",
}
var Permission_value = map[string]int32{
	"LOG":   0,
	"READ":  1,
	"WRITE": 2,
}

func (x Permission) String() string {
	return proto.EnumName(Permission_name, int32(x))
}
func (Permission) EnumDescriptor() ([]byte, []int) { return fileDescriptor2, []int{0} }

func init() {
	proto.RegisterEnum("google.keytransparency.type.Permission", Permission_name, Permission_value)
}

func init() { proto.RegisterFile("type/type_proto/authz.proto", fileDescriptor2) }

var fileDescriptor2 = []byte{
	// 156 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x2e, 0xa9, 0x2c, 0x48,
	0xd5, 0x07, 0x11, 0xf1, 0x05, 0x45, 0xf9, 0x25, 0xf9, 0xfa, 0x89, 0xa5, 0x25, 0x19, 0x55, 0x7a,
	0x60, 0xb6, 0x90, 0x74, 0x7a, 0x7e, 0x7e, 0x7a, 0x4e, 0xaa, 0x5e, 0x76, 0x6a, 0x65, 0x49, 0x51,
	0x62, 0x5e, 0x71, 0x41, 0x62, 0x51, 0x6a, 0x5e, 0x72, 0xa5, 0x1e, 0x48, 0xb9, 0x96, 0x16, 0x17,
	0x57, 0x40, 0x6a, 0x51, 0x6e, 0x66, 0x71, 0x71, 0x66, 0x7e, 0x9e, 0x10, 0x3b, 0x17, 0xb3, 0x8f,
	0xbf, 0xbb, 0x00, 0x83, 0x10, 0x07, 0x17, 0x4b, 0x90, 0xab, 0xa3, 0x8b, 0x00, 0xa3, 0x10, 0x27,
	0x17, 0x6b, 0x78, 0x90, 0x67, 0x88, 0xab, 0x00, 0x93, 0x93, 0x4d, 0x94, 0x55, 0x7a, 0x66, 0x49,
	0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x3e, 0xc4, 0x54, 0x7d, 0x34, 0x53, 0xf5, 0x93, 0xf3,
	0x8b, 0x52, 0xf5, 0x13, 0x0b, 0x32, 0xf5, 0xd1, 0x9c, 0x94, 0xc4, 0x06, 0xa6, 0x8c, 0x01, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x2d, 0x0d, 0xfc, 0x9b, 0xac, 0x00, 0x00, 0x00,
}
