// Code generated by protoc-gen-go. DO NOT EDIT.
// source: type/keymaster.proto

package type_go_proto // import "github.com/google/keytransparency/core/api/type/type_go_proto"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// KeyStatus defines a key status.
type SigningKey_KeyStatus int32

const (
	SigningKey_UNKNOWN    SigningKey_KeyStatus = 0
	SigningKey_ACTIVE     SigningKey_KeyStatus = 1
	SigningKey_INACTIVE   SigningKey_KeyStatus = 2
	SigningKey_DEPRECATED SigningKey_KeyStatus = 3
)

var SigningKey_KeyStatus_name = map[int32]string{
	0: "UNKNOWN",
	1: "ACTIVE",
	2: "INACTIVE",
	3: "DEPRECATED",
}
var SigningKey_KeyStatus_value = map[string]int32{
	"UNKNOWN":    0,
	"ACTIVE":     1,
	"INACTIVE":   2,
	"DEPRECATED": 3,
}

func (x SigningKey_KeyStatus) String() string {
	return proto.EnumName(SigningKey_KeyStatus_name, int32(x))
}
func (SigningKey_KeyStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{1, 0}
}

// KeyStatus defines a key status.
type VerifyingKey_KeyStatus int32

const (
	VerifyingKey_UNKNOWN    VerifyingKey_KeyStatus = 0
	VerifyingKey_ACTIVE     VerifyingKey_KeyStatus = 1
	VerifyingKey_DEPRECATED VerifyingKey_KeyStatus = 2
)

var VerifyingKey_KeyStatus_name = map[int32]string{
	0: "UNKNOWN",
	1: "ACTIVE",
	2: "DEPRECATED",
}
var VerifyingKey_KeyStatus_value = map[string]int32{
	"UNKNOWN":    0,
	"ACTIVE":     1,
	"DEPRECATED": 2,
}

func (x VerifyingKey_KeyStatus) String() string {
	return proto.EnumName(VerifyingKey_KeyStatus_name, int32(x))
}
func (VerifyingKey_KeyStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{2, 0}
}

type Metadata struct {
	// key_id represents a key identifier.
	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId" json:"key_id,omitempty"`
	// added_at determines the time this key has been added to the key set.
	AddedAt *timestamp.Timestamp `protobuf:"bytes,2,opt,name=added_at,json=addedAt" json:"added_at,omitempty"`
	// description contains an arbitrary text describing the key.
	Description          string   `protobuf:"bytes,3,opt,name=description" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Metadata) Reset()         { *m = Metadata{} }
func (m *Metadata) String() string { return proto.CompactTextString(m) }
func (*Metadata) ProtoMessage()    {}
func (*Metadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{0}
}
func (m *Metadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Metadata.Unmarshal(m, b)
}
func (m *Metadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Metadata.Marshal(b, m, deterministic)
}
func (dst *Metadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metadata.Merge(dst, src)
}
func (m *Metadata) XXX_Size() int {
	return xxx_messageInfo_Metadata.Size(m)
}
func (m *Metadata) XXX_DiscardUnknown() {
	xxx_messageInfo_Metadata.DiscardUnknown(m)
}

var xxx_messageInfo_Metadata proto.InternalMessageInfo

func (m *Metadata) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *Metadata) GetAddedAt() *timestamp.Timestamp {
	if m != nil {
		return m.AddedAt
	}
	return nil
}

func (m *Metadata) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

// SigningKey represents a private key.
type SigningKey struct {
	// metadata contains information about this key..
	Metadata *Metadata `protobuf:"bytes,1,opt,name=metadata" json:"metadata,omitempty"`
	// key_material contains the key material in PEM format.
	KeyMaterial []byte `protobuf:"bytes,2,opt,name=key_material,json=keyMaterial,proto3" json:"key_material,omitempty"`
	// status determines the status of this key, e.g., active, deprecated, etc.
	Status               SigningKey_KeyStatus `protobuf:"varint,3,opt,name=status,enum=google.keytransparency.type.SigningKey_KeyStatus" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *SigningKey) Reset()         { *m = SigningKey{} }
func (m *SigningKey) String() string { return proto.CompactTextString(m) }
func (*SigningKey) ProtoMessage()    {}
func (*SigningKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{1}
}
func (m *SigningKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SigningKey.Unmarshal(m, b)
}
func (m *SigningKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SigningKey.Marshal(b, m, deterministic)
}
func (dst *SigningKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SigningKey.Merge(dst, src)
}
func (m *SigningKey) XXX_Size() int {
	return xxx_messageInfo_SigningKey.Size(m)
}
func (m *SigningKey) XXX_DiscardUnknown() {
	xxx_messageInfo_SigningKey.DiscardUnknown(m)
}

var xxx_messageInfo_SigningKey proto.InternalMessageInfo

func (m *SigningKey) GetMetadata() *Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *SigningKey) GetKeyMaterial() []byte {
	if m != nil {
		return m.KeyMaterial
	}
	return nil
}

func (m *SigningKey) GetStatus() SigningKey_KeyStatus {
	if m != nil {
		return m.Status
	}
	return SigningKey_UNKNOWN
}

// VerifyingKey represents a public key.
type VerifyingKey struct {
	// metadata contains information about this key..
	Metadata *Metadata `protobuf:"bytes,1,opt,name=metadata" json:"metadata,omitempty"`
	// key_material contains the key material in PEM format.
	KeyMaterial []byte `protobuf:"bytes,2,opt,name=key_material,json=keyMaterial,proto3" json:"key_material,omitempty"`
	// status determines the status of this key, e.g., active, deprecated, etc.
	Status               VerifyingKey_KeyStatus `protobuf:"varint,3,opt,name=status,enum=google.keytransparency.type.VerifyingKey_KeyStatus" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *VerifyingKey) Reset()         { *m = VerifyingKey{} }
func (m *VerifyingKey) String() string { return proto.CompactTextString(m) }
func (*VerifyingKey) ProtoMessage()    {}
func (*VerifyingKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{2}
}
func (m *VerifyingKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyingKey.Unmarshal(m, b)
}
func (m *VerifyingKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyingKey.Marshal(b, m, deterministic)
}
func (dst *VerifyingKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyingKey.Merge(dst, src)
}
func (m *VerifyingKey) XXX_Size() int {
	return xxx_messageInfo_VerifyingKey.Size(m)
}
func (m *VerifyingKey) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyingKey.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyingKey proto.InternalMessageInfo

func (m *VerifyingKey) GetMetadata() *Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *VerifyingKey) GetKeyMaterial() []byte {
	if m != nil {
		return m.KeyMaterial
	}
	return nil
}

func (m *VerifyingKey) GetStatus() VerifyingKey_KeyStatus {
	if m != nil {
		return m.Status
	}
	return VerifyingKey_UNKNOWN
}

// KeySet contains a set of public and private keys.
type KeySet struct {
	// signing_keys holds a map of private keys keyed by the ID of their
	// corresponding public keys.
	SigningKeys map[string]*SigningKey `protobuf:"bytes,1,rep,name=signing_keys,json=signingKeys" json:"signing_keys,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	// verifying_keys holds a map of public keys keyed by their IDs.
	VerifyingKeys        map[string]*VerifyingKey `protobuf:"bytes,2,rep,name=verifying_keys,json=verifyingKeys" json:"verifying_keys,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *KeySet) Reset()         { *m = KeySet{} }
func (m *KeySet) String() string { return proto.CompactTextString(m) }
func (*KeySet) ProtoMessage()    {}
func (*KeySet) Descriptor() ([]byte, []int) {
	return fileDescriptor_keymaster_54e4f35211da03c5, []int{3}
}
func (m *KeySet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeySet.Unmarshal(m, b)
}
func (m *KeySet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeySet.Marshal(b, m, deterministic)
}
func (dst *KeySet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeySet.Merge(dst, src)
}
func (m *KeySet) XXX_Size() int {
	return xxx_messageInfo_KeySet.Size(m)
}
func (m *KeySet) XXX_DiscardUnknown() {
	xxx_messageInfo_KeySet.DiscardUnknown(m)
}

var xxx_messageInfo_KeySet proto.InternalMessageInfo

func (m *KeySet) GetSigningKeys() map[string]*SigningKey {
	if m != nil {
		return m.SigningKeys
	}
	return nil
}

func (m *KeySet) GetVerifyingKeys() map[string]*VerifyingKey {
	if m != nil {
		return m.VerifyingKeys
	}
	return nil
}

func init() {
	proto.RegisterType((*Metadata)(nil), "google.keytransparency.type.Metadata")
	proto.RegisterType((*SigningKey)(nil), "google.keytransparency.type.SigningKey")
	proto.RegisterType((*VerifyingKey)(nil), "google.keytransparency.type.VerifyingKey")
	proto.RegisterType((*KeySet)(nil), "google.keytransparency.type.KeySet")
	proto.RegisterMapType((map[string]*SigningKey)(nil), "google.keytransparency.type.KeySet.SigningKeysEntry")
	proto.RegisterMapType((map[string]*VerifyingKey)(nil), "google.keytransparency.type.KeySet.VerifyingKeysEntry")
	proto.RegisterEnum("google.keytransparency.type.SigningKey_KeyStatus", SigningKey_KeyStatus_name, SigningKey_KeyStatus_value)
	proto.RegisterEnum("google.keytransparency.type.VerifyingKey_KeyStatus", VerifyingKey_KeyStatus_name, VerifyingKey_KeyStatus_value)
}

func init() { proto.RegisterFile("type/keymaster.proto", fileDescriptor_keymaster_54e4f35211da03c5) }

var fileDescriptor_keymaster_54e4f35211da03c5 = []byte{
	// 509 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x54, 0x4b, 0x6b, 0xdb, 0x40,
	0x10, 0xae, 0x64, 0xe2, 0x38, 0x23, 0xd7, 0x88, 0xa5, 0x05, 0xe3, 0x1e, 0xea, 0x0a, 0x4a, 0xdd,
	0x8b, 0x44, 0x9d, 0xb4, 0x94, 0x42, 0x08, 0x4e, 0xa2, 0x83, 0x31, 0x71, 0x8b, 0xe2, 0x26, 0x50,
	0x28, 0x62, 0x63, 0x4d, 0xd4, 0x45, 0xd6, 0x03, 0xed, 0xda, 0xb0, 0xbd, 0xf5, 0x4f, 0xf4, 0xaf,
	0xf6, 0x5a, 0xb4, 0x92, 0x13, 0xc5, 0x0d, 0xc6, 0xa7, 0x5e, 0xf4, 0x18, 0xed, 0xf7, 0x98, 0x6f,
	0xb5, 0x03, 0xcf, 0x84, 0xcc, 0xd0, 0x89, 0x50, 0xc6, 0x94, 0x0b, 0xcc, 0xed, 0x2c, 0x4f, 0x45,
	0x4a, 0x5e, 0x84, 0x69, 0x1a, 0x2e, 0xd0, 0x8e, 0x50, 0x8a, 0x9c, 0x26, 0x3c, 0xa3, 0x39, 0x26,
	0x73, 0x69, 0x17, 0x8b, 0x7b, 0x2f, 0xcb, 0x8f, 0x8e, 0x5a, 0x7a, 0xb3, 0xbc, 0x75, 0x04, 0x8b,
	0x91, 0x0b, 0x1a, 0x67, 0x25, 0xda, 0xfa, 0x09, 0xad, 0x0b, 0x14, 0x34, 0xa0, 0x82, 0x92, 0xe7,
	0xd0, 0x8c, 0x50, 0xfa, 0x2c, 0xe8, 0x6a, 0x7d, 0x6d, 0x70, 0xe0, 0xed, 0x45, 0x28, 0xc7, 0x01,
	0x79, 0x0f, 0x2d, 0x1a, 0x04, 0x18, 0xf8, 0x54, 0x74, 0xf5, 0xbe, 0x36, 0x30, 0x86, 0x3d, 0xbb,
	0xd2, 0x5c, 0xd3, 0xda, 0xb3, 0x35, 0xad, 0xb7, 0xaf, 0xd6, 0x8e, 0x04, 0xe9, 0x83, 0x11, 0x20,
	0x9f, 0xe7, 0x2c, 0x13, 0x2c, 0x4d, 0xba, 0x0d, 0x45, 0x59, 0x2f, 0x59, 0xbf, 0x74, 0x80, 0x4b,
	0x16, 0x26, 0x2c, 0x09, 0x27, 0x28, 0xc9, 0x08, 0x5a, 0x71, 0x65, 0x45, 0x19, 0x30, 0x86, 0xaf,
	0xed, 0x2d, 0xbd, 0xd9, 0x6b, 0xdf, 0xde, 0x1d, 0x8c, 0xbc, 0x82, 0x76, 0xd1, 0x41, 0x4c, 0x05,
	0xe6, 0x8c, 0x2e, 0x94, 0xdd, 0xb6, 0x67, 0x44, 0x28, 0x2f, 0xaa, 0x12, 0x19, 0x43, 0x93, 0x0b,
	0x2a, 0x96, 0x5c, 0x39, 0xea, 0x0c, 0xdf, 0x6d, 0xd5, 0xb8, 0xb7, 0x67, 0x4f, 0x50, 0x5e, 0x2a,
	0xa0, 0x57, 0x11, 0x58, 0xa7, 0x70, 0x70, 0x57, 0x24, 0x06, 0xec, 0x7f, 0x9d, 0x4e, 0xa6, 0x9f,
	0xaf, 0xa7, 0xe6, 0x13, 0x02, 0xd0, 0x1c, 0x9d, 0xcd, 0xc6, 0x57, 0xae, 0xa9, 0x91, 0x36, 0xb4,
	0xc6, 0xd3, 0xea, 0x4d, 0x27, 0x1d, 0x80, 0x73, 0xf7, 0x8b, 0xe7, 0x9e, 0x8d, 0x66, 0xee, 0xb9,
	0xd9, 0xb0, 0xfe, 0x68, 0xd0, 0xbe, 0xc2, 0x9c, 0xdd, 0xca, 0xff, 0x9a, 0xc2, 0x64, 0x23, 0x85,
	0xc3, 0xad, 0x1a, 0x75, 0x83, 0x8f, 0xe4, 0x70, 0xb4, 0x53, 0x0e, 0x0f, 0x3b, 0xd7, 0xad, 0xdf,
	0x0d, 0x68, 0x16, 0x30, 0x14, 0xe4, 0x1a, 0xda, 0xbc, 0x0c, 0xda, 0x8f, 0x50, 0xf2, 0xae, 0xd6,
	0x6f, 0x0c, 0x8c, 0xe1, 0xd1, 0x56, 0x4f, 0x25, 0xb4, 0xb6, 0x41, 0xdc, 0x4d, 0x44, 0x2e, 0x3d,
	0x83, 0xdf, 0x57, 0xc8, 0x77, 0xe8, 0xac, 0xd6, 0xde, 0x4b, 0x6a, 0x5d, 0x51, 0x7f, 0xd8, 0x85,
	0xba, 0xde, 0x75, 0x45, 0xfe, 0x74, 0x55, 0xaf, 0xf5, 0x42, 0x30, 0x37, 0xf5, 0x89, 0x09, 0x8d,
	0x08, 0x65, 0x75, 0x82, 0x8a, 0x47, 0x72, 0x0c, 0x7b, 0x2b, 0xba, 0x58, 0x62, 0x75, 0x78, 0xde,
	0xec, 0xf8, 0xc3, 0x79, 0x25, 0xea, 0x93, 0xfe, 0x51, 0xeb, 0x45, 0x40, 0xfe, 0x75, 0xf3, 0x88,
	0xd4, 0xc9, 0x43, 0xa9, 0xb7, 0x3b, 0xef, 0x6a, 0x4d, 0xec, 0xf4, 0xe4, 0xdb, 0x71, 0xc8, 0xc4,
	0x8f, 0xe5, 0x8d, 0x3d, 0x4f, 0x63, 0xa7, 0x1a, 0x20, 0x1b, 0x0c, 0xce, 0x3c, 0xcd, 0xd1, 0xa1,
	0x19, 0x73, 0xd4, 0x4c, 0x2a, 0x2e, 0x7e, 0x98, 0xfa, 0xe5, 0x3c, 0x68, 0xaa, 0xdb, 0xe1, 0xdf,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0xaf, 0xba, 0x06, 0xb0, 0x04, 0x00, 0x00,
}
