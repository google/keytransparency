// Code generated by protoc-gen-go. DO NOT EDIT.
// source: type/type.proto

package type_go_proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	tink_go_proto "github.com/google/tink/proto/tink_go_proto"
	status "google.golang.org/genproto/googleapis/rpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// User represents plain account information that gets committed to and
// obfuscated in Entry.
type User struct {
	// directory_id specifies the directory.
	DirectoryId string `protobuf:"bytes,1,opt,name=directory_id,json=directoryId,proto3" json:"directory_id,omitempty"`
	// user_id specifies the user.
	UserId string `protobuf:"bytes,3,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	// public_key_data is the public key material for this account.
	PublicKeyData []byte `protobuf:"bytes,4,opt,name=public_key_data,json=publicKeyData,proto3" json:"public_key_data,omitempty"`
	// authorized_keys is the set of keys allowed to sign updates for this entry.
	AuthorizedKeys *tink_go_proto.Keyset `protobuf:"bytes,5,opt,name=authorized_keys,json=authorizedKeys,proto3" json:"authorized_keys,omitempty"`
	// status is set when account is part of a batch operation.
	Status               *status.Status `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *User) Reset()         { *m = User{} }
func (m *User) String() string { return proto.CompactTextString(m) }
func (*User) ProtoMessage()    {}
func (*User) Descriptor() ([]byte, []int) {
	return fileDescriptor_2be97559bcb7ed35, []int{0}
}

func (m *User) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_User.Unmarshal(m, b)
}
func (m *User) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_User.Marshal(b, m, deterministic)
}
func (m *User) XXX_Merge(src proto.Message) {
	xxx_messageInfo_User.Merge(m, src)
}
func (m *User) XXX_Size() int {
	return xxx_messageInfo_User.Size(m)
}
func (m *User) XXX_DiscardUnknown() {
	xxx_messageInfo_User.DiscardUnknown(m)
}

var xxx_messageInfo_User proto.InternalMessageInfo

func (m *User) GetDirectoryId() string {
	if m != nil {
		return m.DirectoryId
	}
	return ""
}

func (m *User) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *User) GetPublicKeyData() []byte {
	if m != nil {
		return m.PublicKeyData
	}
	return nil
}

func (m *User) GetAuthorizedKeys() *tink_go_proto.Keyset {
	if m != nil {
		return m.AuthorizedKeys
	}
	return nil
}

func (m *User) GetStatus() *status.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterType((*User)(nil), "google.keytransparency.type.User")
}

func init() { proto.RegisterFile("type/type.proto", fileDescriptor_2be97559bcb7ed35) }

var fileDescriptor_2be97559bcb7ed35 = []byte{
	// 285 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x90, 0x3d, 0x4f, 0xf3, 0x30,
	0x10, 0xc7, 0x95, 0xa7, 0x7d, 0x02, 0xb8, 0x85, 0x22, 0x2f, 0x8d, 0xca, 0x52, 0x18, 0x50, 0xc5,
	0x60, 0x4b, 0x30, 0x23, 0x24, 0x60, 0x29, 0xdd, 0x82, 0x58, 0x58, 0x22, 0xd7, 0x39, 0xa5, 0x56,
	0x4b, 0x6d, 0x9d, 0x2f, 0x83, 0xf9, 0xb6, 0x7c, 0x13, 0x64, 0x27, 0x14, 0x89, 0xc5, 0x2f, 0xff,
	0x17, 0xe9, 0xee, 0xc7, 0x26, 0x14, 0x1c, 0xc8, 0x78, 0x08, 0x87, 0x96, 0x2c, 0xbf, 0x68, 0xac,
	0x6d, 0x76, 0x20, 0xb6, 0x10, 0x08, 0xd5, 0xde, 0x3b, 0x85, 0xb0, 0xd7, 0x41, 0xc4, 0xc8, 0x6c,
	0xda, 0x99, 0x12, 0x9d, 0x96, 0x9e, 0x14, 0xb5, 0xbe, 0x6b, 0xcd, 0x18, 0x99, 0xfd, 0xb6, 0x7b,
	0x5f, 0x7d, 0x65, 0x6c, 0xf8, 0xe6, 0x01, 0xf9, 0x25, 0x1b, 0xd7, 0x06, 0x41, 0x93, 0xc5, 0x50,
	0x99, 0xba, 0xc8, 0xe6, 0xd9, 0xe2, 0xa4, 0x1c, 0x1d, 0xb4, 0x65, 0xcd, 0xa7, 0xec, 0xa8, 0xf5,
	0x80, 0xd1, 0x1d, 0x24, 0x37, 0x8f, 0xdf, 0x65, 0xcd, 0xaf, 0xd9, 0xc4, 0xb5, 0xeb, 0x9d, 0xd1,
	0xd5, 0x16, 0x42, 0x55, 0x2b, 0x52, 0xc5, 0x70, 0x9e, 0x2d, 0xc6, 0xe5, 0x69, 0x27, 0xaf, 0x20,
	0x3c, 0x2b, 0x52, 0xfc, 0x89, 0x4d, 0x54, 0x4b, 0x1b, 0x8b, 0xe6, 0x13, 0xea, 0x98, 0xf5, 0xc5,
	0xff, 0x79, 0xb6, 0x18, 0xdd, 0xce, 0x44, 0xbf, 0x88, 0xc6, 0xe0, 0xc8, 0x8a, 0x34, 0xe0, 0x0a,
	0x82, 0x07, 0x2a, 0xcf, 0x7e, 0x2b, 0x51, 0xe1, 0x37, 0x2c, 0xef, 0xb6, 0x29, 0xf2, 0xd4, 0xe5,
	0x3f, 0x5d, 0x74, 0x5a, 0xbc, 0x26, 0xa7, 0xec, 0x13, 0x2f, 0xc3, 0xe3, 0x7f, 0xe7, 0x83, 0xc7,
	0x87, 0xf7, 0xfb, 0xc6, 0xd0, 0xa6, 0x5d, 0x0b, 0x6d, 0x3f, 0x64, 0x4f, 0xe5, 0x0f, 0x32, 0xa9,
	0x2d, 0x82, 0x54, 0xce, 0xc8, 0x03, 0xe3, 0xaa, 0xb1, 0x55, 0x82, 0xb4, 0xce, 0xd3, 0x75, 0xf7,
	0x1d, 0x00, 0x00, 0xff, 0xff, 0x18, 0xb7, 0x0c, 0x6e, 0x80, 0x01, 0x00, 0x00,
}
