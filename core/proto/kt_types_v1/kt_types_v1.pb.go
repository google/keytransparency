// Code generated by protoc-gen-go.
// source: core/proto/kt_types_v1/kt_types_v1.proto
// DO NOT EDIT!

/*
Package keytransparency_v1 is a generated protocol buffer package.

It is generated from these files:
	core/proto/kt_types_v1/kt_types_v1.proto

It has these top-level messages:
	Committed
	Profile
	EntryUpdate
	Entry
	PublicKey
	KeyValue
	SignedKV
	GetEntryRequest
	GetEntryResponse
	ListEntryHistoryRequest
	ListEntryHistoryResponse
	UpdateEntryRequest
	UpdateEntryResponse
	HkpLookupRequest
	HttpResponse
*/
package keytransparency_v1

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import ctmap "github.com/google/key-transparency/core/proto/ctmap"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Committed represents the data committed to in a cryptographic commitment.
// commitment = HMAC_SHA512_256(key, data)
type Committed struct {
	// key is the 16 byte random commitment key.
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// data is the data being committed to.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Committed) Reset()                    { *m = Committed{} }
func (m *Committed) String() string            { return proto.CompactTextString(m) }
func (*Committed) ProtoMessage()               {}
func (*Committed) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// Profile contains data hidden behind the cryptographic commitment.
type Profile struct {
	// Keys is a map of application IDs to keys.
	Keys map[string][]byte `protobuf:"bytes,1,rep,name=keys" json:"keys,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *Profile) Reset()                    { *m = Profile{} }
func (m *Profile) String() string            { return proto.CompactTextString(m) }
func (*Profile) ProtoMessage()               {}
func (*Profile) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Profile) GetKeys() map[string][]byte {
	if m != nil {
		return m.Keys
	}
	return nil
}

// EntryUpdate contains the user entry update(s).
type EntryUpdate struct {
	// update authorizes the change to profile.
	Update *SignedKV `protobuf:"bytes,2,opt,name=update" json:"update,omitempty"`
	// commitment contains the serialized Profile protobuf.
	Committed *Committed `protobuf:"bytes,3,opt,name=committed" json:"committed,omitempty"`
}

func (m *EntryUpdate) Reset()                    { *m = EntryUpdate{} }
func (m *EntryUpdate) String() string            { return proto.CompactTextString(m) }
func (*EntryUpdate) ProtoMessage()               {}
func (*EntryUpdate) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *EntryUpdate) GetUpdate() *SignedKV {
	if m != nil {
		return m.Update
	}
	return nil
}

func (m *EntryUpdate) GetCommitted() *Committed {
	if m != nil {
		return m.Committed
	}
	return nil
}

// Entry contains a commitment to profile and a set of authorized update keys.
// Entry is placed in the verifiable map as leaf data.
type Entry struct {
	// commitment is a cryptographic commitment to arbitrary data.
	Commitment []byte `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	// authorized_keys is the set of keys allowed to sign updates for this entry.
	AuthorizedKeys []*PublicKey `protobuf:"bytes,2,rep,name=authorized_keys,json=authorizedKeys" json:"authorized_keys,omitempty"`
}

func (m *Entry) Reset()                    { *m = Entry{} }
func (m *Entry) String() string            { return proto.CompactTextString(m) }
func (*Entry) ProtoMessage()               {}
func (*Entry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Entry) GetAuthorizedKeys() []*PublicKey {
	if m != nil {
		return m.AuthorizedKeys
	}
	return nil
}

// PublicKey defines a key this domain uses to sign MapHeads with.
type PublicKey struct {
	// Key formats from Keyczar.
	//
	// Types that are valid to be assigned to KeyType:
	//	*PublicKey_Ed25519
	//	*PublicKey_RsaVerifyingSha256_2048
	//	*PublicKey_EcdsaVerifyingP256
	KeyType isPublicKey_KeyType `protobuf_oneof:"key_type"`
}

func (m *PublicKey) Reset()                    { *m = PublicKey{} }
func (m *PublicKey) String() string            { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()               {}
func (*PublicKey) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

type isPublicKey_KeyType interface {
	isPublicKey_KeyType()
}

type PublicKey_Ed25519 struct {
	Ed25519 []byte `protobuf:"bytes,1,opt,name=ed25519,proto3,oneof"`
}
type PublicKey_RsaVerifyingSha256_2048 struct {
	RsaVerifyingSha256_2048 []byte `protobuf:"bytes,2,opt,name=rsa_verifying_sha256_2048,json=rsaVerifyingSha2562048,proto3,oneof"`
}
type PublicKey_EcdsaVerifyingP256 struct {
	EcdsaVerifyingP256 []byte `protobuf:"bytes,3,opt,name=ecdsa_verifying_p256,json=ecdsaVerifyingP256,proto3,oneof"`
}

func (*PublicKey_Ed25519) isPublicKey_KeyType()                 {}
func (*PublicKey_RsaVerifyingSha256_2048) isPublicKey_KeyType() {}
func (*PublicKey_EcdsaVerifyingP256) isPublicKey_KeyType()      {}

func (m *PublicKey) GetKeyType() isPublicKey_KeyType {
	if m != nil {
		return m.KeyType
	}
	return nil
}

func (m *PublicKey) GetEd25519() []byte {
	if x, ok := m.GetKeyType().(*PublicKey_Ed25519); ok {
		return x.Ed25519
	}
	return nil
}

func (m *PublicKey) GetRsaVerifyingSha256_2048() []byte {
	if x, ok := m.GetKeyType().(*PublicKey_RsaVerifyingSha256_2048); ok {
		return x.RsaVerifyingSha256_2048
	}
	return nil
}

func (m *PublicKey) GetEcdsaVerifyingP256() []byte {
	if x, ok := m.GetKeyType().(*PublicKey_EcdsaVerifyingP256); ok {
		return x.EcdsaVerifyingP256
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*PublicKey) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _PublicKey_OneofMarshaler, _PublicKey_OneofUnmarshaler, _PublicKey_OneofSizer, []interface{}{
		(*PublicKey_Ed25519)(nil),
		(*PublicKey_RsaVerifyingSha256_2048)(nil),
		(*PublicKey_EcdsaVerifyingP256)(nil),
	}
}

func _PublicKey_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*PublicKey)
	// key_type
	switch x := m.KeyType.(type) {
	case *PublicKey_Ed25519:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.Ed25519)
	case *PublicKey_RsaVerifyingSha256_2048:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.RsaVerifyingSha256_2048)
	case *PublicKey_EcdsaVerifyingP256:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.EcdsaVerifyingP256)
	case nil:
	default:
		return fmt.Errorf("PublicKey.KeyType has unexpected type %T", x)
	}
	return nil
}

func _PublicKey_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*PublicKey)
	switch tag {
	case 1: // key_type.ed25519
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.KeyType = &PublicKey_Ed25519{x}
		return true, err
	case 2: // key_type.rsa_verifying_sha256_2048
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.KeyType = &PublicKey_RsaVerifyingSha256_2048{x}
		return true, err
	case 3: // key_type.ecdsa_verifying_p256
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.KeyType = &PublicKey_EcdsaVerifyingP256{x}
		return true, err
	default:
		return false, nil
	}
}

func _PublicKey_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*PublicKey)
	// key_type
	switch x := m.KeyType.(type) {
	case *PublicKey_Ed25519:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.Ed25519)))
		n += len(x.Ed25519)
	case *PublicKey_RsaVerifyingSha256_2048:
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.RsaVerifyingSha256_2048)))
		n += len(x.RsaVerifyingSha256_2048)
	case *PublicKey_EcdsaVerifyingP256:
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.EcdsaVerifyingP256)))
		n += len(x.EcdsaVerifyingP256)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// KeyValue is a map entry.
type KeyValue struct {
	// key contains the map entry key.
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// value contains the map entry value.
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *KeyValue) Reset()                    { *m = KeyValue{} }
func (m *KeyValue) String() string            { return proto.CompactTextString(m) }
func (*KeyValue) ProtoMessage()               {}
func (*KeyValue) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

// SignedKV is a signed change to a map entry.
type SignedKV struct {
	// key_value is a serialized KeyValue.
	KeyValue []byte `protobuf:"bytes,1,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
	// signatures on keyvalue. Must be signed by keys from both previous and
	// current epochs. The first proves ownership of new epoch key, and the
	// second proves that the correct owner is making this change.
	Signatures map[uint64][]byte `protobuf:"bytes,2,rep,name=signatures" json:"signatures,omitempty" protobuf_key:"fixed64,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// previous contains the hash of the previous entry that this mutation is
	// modifying creating a hash chain of all mutations. The hash used is
	// CommonJSON in "github.com/benlaurie/objecthash/go/objecthash".
	Previous []byte `protobuf:"bytes,3,opt,name=previous,proto3" json:"previous,omitempty"`
}

func (m *SignedKV) Reset()                    { *m = SignedKV{} }
func (m *SignedKV) String() string            { return proto.CompactTextString(m) }
func (*SignedKV) ProtoMessage()               {}
func (*SignedKV) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *SignedKV) GetSignatures() map[uint64][]byte {
	if m != nil {
		return m.Signatures
	}
	return nil
}

// GetEntryReqyest for a user object.
type GetEntryRequest struct {
	// Absence of the epoch_end field indicates a request for the current value.
	EpochEnd int64 `protobuf:"varint,1,opt,name=epoch_end,json=epochEnd" json:"epoch_end,omitempty"`
	// User identifier. Most commonly an email address.
	UserId string `protobuf:"bytes,2,opt,name=user_id,json=userId" json:"user_id,omitempty"`
}

func (m *GetEntryRequest) Reset()                    { *m = GetEntryRequest{} }
func (m *GetEntryRequest) String() string            { return proto.CompactTextString(m) }
func (*GetEntryRequest) ProtoMessage()               {}
func (*GetEntryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

// GetEntryResponse returns a requested user entry.
type GetEntryResponse struct {
	// vrf is the output of VRF on user_id.
	Vrf []byte `protobuf:"bytes,1,opt,name=vrf,proto3" json:"vrf,omitempty"`
	// vrf_proof is the proof for VRF on user_id.
	VrfProof []byte `protobuf:"bytes,2,opt,name=vrf_proof,json=vrfProof,proto3" json:"vrf_proof,omitempty"`
	// committed contains the profile for this account and connects the data
	// in profile to the commitment in leaf_proof.
	Committed *Committed `protobuf:"bytes,3,opt,name=committed" json:"committed,omitempty"`
	// leaf_proof contains an Entry and an inclusion proof in the sparse merkle tree at end_epoch.
	LeafProof *ctmap.GetLeafResponse `protobuf:"bytes,5,opt,name=leaf_proof,json=leafProof" json:"leaf_proof,omitempty"`
	// smh contains the signed map head for the sparse merkle tree.
	// smh is also stored in the append only log.
	Smh *ctmap.SignedMapHead `protobuf:"bytes,6,opt,name=smh" json:"smh,omitempty"`
	// smh_sct is the SCT showing that smh was submitted to CT logs.
	// TODO: Support storing smh in multiple logs.
	SmhSct []byte `protobuf:"bytes,7,opt,name=smh_sct,json=smhSct,proto3" json:"smh_sct,omitempty"`
}

func (m *GetEntryResponse) Reset()                    { *m = GetEntryResponse{} }
func (m *GetEntryResponse) String() string            { return proto.CompactTextString(m) }
func (*GetEntryResponse) ProtoMessage()               {}
func (*GetEntryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *GetEntryResponse) GetCommitted() *Committed {
	if m != nil {
		return m.Committed
	}
	return nil
}

func (m *GetEntryResponse) GetLeafProof() *ctmap.GetLeafResponse {
	if m != nil {
		return m.LeafProof
	}
	return nil
}

func (m *GetEntryResponse) GetSmh() *ctmap.SignedMapHead {
	if m != nil {
		return m.Smh
	}
	return nil
}

// Get a list of historical values for a user.
type ListEntryHistoryRequest struct {
	// user_id is the user identifier.
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty"`
	// start is the starting epcoh.
	Start int64 `protobuf:"varint,2,opt,name=start" json:"start,omitempty"`
	// page_size is the maximum number of entries to return. The server can change
	// this value.
	PageSize int32 `protobuf:"varint,3,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
}

func (m *ListEntryHistoryRequest) Reset()                    { *m = ListEntryHistoryRequest{} }
func (m *ListEntryHistoryRequest) String() string            { return proto.CompactTextString(m) }
func (*ListEntryHistoryRequest) ProtoMessage()               {}
func (*ListEntryHistoryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

// A paginated history of values for a user.
type ListEntryHistoryResponse struct {
	// values represents the list of values this user_id has contained over time.
	Values []*GetEntryResponse `protobuf:"bytes,1,rep,name=values" json:"values,omitempty"`
	// next_start is the next page token to query for pagination.
	NextStart int64 `protobuf:"varint,2,opt,name=next_start,json=nextStart" json:"next_start,omitempty"`
}

func (m *ListEntryHistoryResponse) Reset()                    { *m = ListEntryHistoryResponse{} }
func (m *ListEntryHistoryResponse) String() string            { return proto.CompactTextString(m) }
func (*ListEntryHistoryResponse) ProtoMessage()               {}
func (*ListEntryHistoryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *ListEntryHistoryResponse) GetValues() []*GetEntryResponse {
	if m != nil {
		return m.Values
	}
	return nil
}

// Update a user's profile.
type UpdateEntryRequest struct {
	// user_id specifies the id for the new account to be registered.
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty"`
	// entry_update contains the user submitted update(s).
	EntryUpdate *EntryUpdate `protobuf:"bytes,2,opt,name=entry_update,json=entryUpdate" json:"entry_update,omitempty"`
}

func (m *UpdateEntryRequest) Reset()                    { *m = UpdateEntryRequest{} }
func (m *UpdateEntryRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateEntryRequest) ProtoMessage()               {}
func (*UpdateEntryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *UpdateEntryRequest) GetEntryUpdate() *EntryUpdate {
	if m != nil {
		return m.EntryUpdate
	}
	return nil
}

// UpdateEntryResponse contains a proof once the update has been included in
// the Merkel Tree.
type UpdateEntryResponse struct {
	// proof contains a proof that the update has been included in the tree.
	Proof *GetEntryResponse `protobuf:"bytes,1,opt,name=proof" json:"proof,omitempty"`
}

func (m *UpdateEntryResponse) Reset()                    { *m = UpdateEntryResponse{} }
func (m *UpdateEntryResponse) String() string            { return proto.CompactTextString(m) }
func (*UpdateEntryResponse) ProtoMessage()               {}
func (*UpdateEntryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *UpdateEntryResponse) GetProof() *GetEntryResponse {
	if m != nil {
		return m.Proof
	}
	return nil
}

// HkpLookupRequest contains query parameters for retrieving PGP keys.
type HkpLookupRequest struct {
	// Op specifies the operation to be performed on the keyserver.
	// - "get" returns the pgp key specified in the search parameter.
	// - "index" returns 501 (not implemented).
	// - "vindex" returns 501 (not implemented).
	Op string `protobuf:"bytes,1,opt,name=op" json:"op,omitempty"`
	// Search specifies the email address or key id being queried.
	Search string `protobuf:"bytes,2,opt,name=search" json:"search,omitempty"`
	// Options specifies what output format to use.
	// - "mr" machine readable will set the content type to "application/pgp-keys"
	// - other options will be ignored.
	Options string `protobuf:"bytes,3,opt,name=options" json:"options,omitempty"`
	// Exact specifies an exact match on search. Always on. If specified in the
	// URL, its value will be ignored.
	Exact string `protobuf:"bytes,4,opt,name=exact" json:"exact,omitempty"`
	// fingerprint is ignored.
	Fingerprint string `protobuf:"bytes,5,opt,name=fingerprint" json:"fingerprint,omitempty"`
}

func (m *HkpLookupRequest) Reset()                    { *m = HkpLookupRequest{} }
func (m *HkpLookupRequest) String() string            { return proto.CompactTextString(m) }
func (*HkpLookupRequest) ProtoMessage()               {}
func (*HkpLookupRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

// HttpBody represents an http body.
type HttpResponse struct {
	// Header content type.
	ContentType string `protobuf:"bytes,1,opt,name=content_type,json=contentType" json:"content_type,omitempty"`
	// The http body itself.
	Body []byte `protobuf:"bytes,2,opt,name=body,proto3" json:"body,omitempty"`
}

func (m *HttpResponse) Reset()                    { *m = HttpResponse{} }
func (m *HttpResponse) String() string            { return proto.CompactTextString(m) }
func (*HttpResponse) ProtoMessage()               {}
func (*HttpResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func init() {
	proto.RegisterType((*Committed)(nil), "keytransparency.v1.Committed")
	proto.RegisterType((*Profile)(nil), "keytransparency.v1.Profile")
	proto.RegisterType((*EntryUpdate)(nil), "keytransparency.v1.EntryUpdate")
	proto.RegisterType((*Entry)(nil), "keytransparency.v1.Entry")
	proto.RegisterType((*PublicKey)(nil), "keytransparency.v1.PublicKey")
	proto.RegisterType((*KeyValue)(nil), "keytransparency.v1.KeyValue")
	proto.RegisterType((*SignedKV)(nil), "keytransparency.v1.SignedKV")
	proto.RegisterType((*GetEntryRequest)(nil), "keytransparency.v1.GetEntryRequest")
	proto.RegisterType((*GetEntryResponse)(nil), "keytransparency.v1.GetEntryResponse")
	proto.RegisterType((*ListEntryHistoryRequest)(nil), "keytransparency.v1.ListEntryHistoryRequest")
	proto.RegisterType((*ListEntryHistoryResponse)(nil), "keytransparency.v1.ListEntryHistoryResponse")
	proto.RegisterType((*UpdateEntryRequest)(nil), "keytransparency.v1.UpdateEntryRequest")
	proto.RegisterType((*UpdateEntryResponse)(nil), "keytransparency.v1.UpdateEntryResponse")
	proto.RegisterType((*HkpLookupRequest)(nil), "keytransparency.v1.HkpLookupRequest")
	proto.RegisterType((*HttpResponse)(nil), "keytransparency.v1.HttpResponse")
}

func init() { proto.RegisterFile("core/proto/kt_types_v1/kt_types_v1.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 887 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xa4, 0x55, 0x6d, 0x6f, 0x1b, 0x45,
	0x10, 0xe6, 0xe2, 0xf8, 0xe5, 0xc6, 0x51, 0x53, 0x2d, 0x51, 0x6a, 0x02, 0x85, 0x72, 0x02, 0x94,
	0x0f, 0x60, 0x13, 0xd3, 0x40, 0x5b, 0x40, 0x48, 0x45, 0xa1, 0x46, 0x0d, 0x52, 0x38, 0x43, 0xbe,
	0x9e, 0x2e, 0x77, 0x63, 0xfb, 0x14, 0xfb, 0x76, 0xbb, 0xbb, 0x67, 0x6a, 0x24, 0x24, 0x7e, 0x00,
	0x3f, 0x83, 0x1f, 0xc4, 0xaf, 0xe1, 0x33, 0xb3, 0xbb, 0x77, 0xf6, 0xa5, 0x31, 0x2f, 0x12, 0x5f,
	0x92, 0x99, 0xd9, 0x67, 0xde, 0x9e, 0x19, 0xcf, 0xc1, 0x71, 0xc2, 0x25, 0x0e, 0x84, 0xe4, 0x9a,
	0x0f, 0xae, 0x75, 0xa4, 0x57, 0x02, 0x55, 0xb4, 0x3c, 0xa9, 0xcb, 0x7d, 0xfb, 0xca, 0xd8, 0x35,
	0xae, 0xb4, 0x8c, 0x73, 0x25, 0x62, 0x89, 0x79, 0xb2, 0xea, 0x2f, 0x4f, 0x8e, 0xbe, 0x9a, 0x66,
	0x7a, 0x56, 0x5c, 0xf5, 0x13, 0xbe, 0x18, 0x4c, 0x39, 0x9f, 0xce, 0x71, 0x40, 0xa8, 0x8f, 0xea,
	0xb0, 0x41, 0x2d, 0x41, 0xa2, 0x17, 0xb1, 0x70, 0x7f, 0x5d, 0xd0, 0xe0, 0x04, 0xfc, 0xaf, 0xf9,
	0x62, 0x91, 0x69, 0x8d, 0x29, 0xbb, 0x0b, 0x0d, 0xf2, 0xee, 0x79, 0x0f, 0xbc, 0xe3, 0xbd, 0xd0,
	0x88, 0x8c, 0xc1, 0x6e, 0x1a, 0xeb, 0xb8, 0xb7, 0x63, 0x4d, 0x56, 0x0e, 0x7e, 0x81, 0xf6, 0x85,
	0xe4, 0x93, 0x6c, 0x8e, 0xec, 0x31, 0xec, 0x12, 0x4a, 0x91, 0x47, 0xe3, 0xb8, 0x3b, 0x7c, 0xbf,
	0x7f, 0xbb, 0xc2, 0x7e, 0x09, 0xed, 0x3f, 0x27, 0xdc, 0x59, 0xae, 0xe5, 0x2a, 0xb4, 0x2e, 0x47,
	0x9f, 0x81, 0xbf, 0x36, 0xd5, 0x13, 0xfb, 0x2e, 0xf1, 0x01, 0x34, 0x97, 0xf1, 0xbc, 0xc0, 0x32,
	0xb3, 0x53, 0x9e, 0xec, 0x3c, 0xf2, 0x82, 0x5f, 0x3d, 0xe8, 0x5a, 0xaf, 0x1f, 0x05, 0x95, 0x83,
	0xec, 0x21, 0xb4, 0x0a, 0x2b, 0x59, 0x68, 0x77, 0xf8, 0xd6, 0xb6, 0x2a, 0xc6, 0xd9, 0x34, 0xc7,
	0xf4, 0xf9, 0x65, 0x58, 0x62, 0xd9, 0xe7, 0xe0, 0x27, 0x55, 0xdf, 0xbd, 0x86, 0x75, 0xbc, 0xbf,
	0xcd, 0x71, 0x4d, 0x4e, 0xb8, 0xc1, 0x07, 0x1c, 0x9a, 0xae, 0xee, 0xb7, 0x01, 0x9c, 0x75, 0x81,
	0xb9, 0x2e, 0x79, 0xab, 0x59, 0xd8, 0x37, 0xb0, 0x1f, 0x17, 0x7a, 0xc6, 0x65, 0xf6, 0x33, 0xa6,
	0x91, 0xa5, 0x6a, 0xc7, 0x52, 0xb5, 0x35, 0xd7, 0x45, 0x71, 0x35, 0xcf, 0x12, 0x62, 0x25, 0xbc,
	0xb3, 0xf1, 0x32, 0x24, 0x05, 0xbf, 0x7b, 0xe0, 0xaf, 0x5f, 0xd9, 0x11, 0xb4, 0x31, 0x1d, 0x9e,
	0x9e, 0x9e, 0x3c, 0x76, 0x29, 0x47, 0xaf, 0x85, 0x95, 0x81, 0xfa, 0x7a, 0x43, 0xaa, 0x38, 0x5a,
	0xa2, 0xcc, 0x26, 0xab, 0x2c, 0x9f, 0x46, 0x6a, 0x16, 0x0f, 0x4f, 0x3f, 0x8d, 0x86, 0x1f, 0x3f,
	0x7c, 0xe4, 0xb8, 0x24, 0xf4, 0x21, 0x41, 0x2e, 0x2b, 0xc4, 0xd8, 0x02, 0xcc, 0x3b, 0x1b, 0xc2,
	0x01, 0x26, 0xe9, 0x0d, 0x77, 0x41, 0x6f, 0x96, 0x1f, 0xe3, 0xc7, 0xec, 0xeb, 0xda, 0xf3, 0x82,
	0xde, 0x9e, 0x02, 0x74, 0xa8, 0x15, 0xbb, 0xab, 0xc1, 0x10, 0x3a, 0x54, 0xdf, 0xa5, 0x19, 0xd5,
	0x96, 0x5d, 0xda, 0x3a, 0xd2, 0xe0, 0x0f, 0x0f, 0x3a, 0xd5, 0x74, 0xd8, 0x9b, 0xe0, 0x9b, 0x60,
	0x0e, 0xe6, 0x5c, 0x4d, 0x74, 0x17, 0xf1, 0x1c, 0x40, 0x11, 0x30, 0xd6, 0x85, 0xc4, 0x8a, 0xc7,
	0x0f, 0xff, 0x69, 0xd8, 0x56, 0x70, 0x70, 0xb7, 0x79, 0x35, 0x7f, 0x22, 0xb1, 0x23, 0x24, 0x2e,
	0x33, 0x5e, 0x28, 0xd7, 0x5f, 0xb8, 0xd6, 0x8f, 0xbe, 0x84, 0xfd, 0x57, 0x5c, 0xeb, 0xed, 0xb4,
	0xfe, 0x6d, 0x43, 0x9f, 0xc1, 0xfe, 0x33, 0xd4, 0x2e, 0x25, 0xbe, 0x28, 0x50, 0x69, 0xd3, 0x18,
	0x0a, 0x9e, 0xcc, 0x22, 0xcc, 0x53, 0x1b, 0xa4, 0x11, 0x76, 0xac, 0xe1, 0x2c, 0x4f, 0xd9, 0x3d,
	0x68, 0x17, 0x0a, 0x65, 0x94, 0xa5, 0x36, 0x96, 0x4f, 0x4b, 0x4a, 0xea, 0xb7, 0x69, 0xf0, 0xa7,
	0x07, 0x77, 0x37, 0x91, 0x94, 0xe0, 0xb9, 0xb2, 0xc4, 0x2e, 0xe5, 0xa4, 0x22, 0x96, 0x44, 0x13,
	0x9c, 0xfe, 0x45, 0xf4, 0x83, 0xe6, 0x93, 0xb2, 0x9a, 0x0e, 0x19, 0x2e, 0x8c, 0xfe, 0xbf, 0x16,
	0x9d, 0x9d, 0x02, 0xcc, 0x31, 0xae, 0x42, 0x37, 0xad, 0xf7, 0x61, 0xdf, 0xdd, 0x0f, 0x2a, 0xec,
	0x9c, 0xde, 0xaa, 0xba, 0x42, 0xdf, 0x20, 0x5d, 0xce, 0x0f, 0xa0, 0xa1, 0x16, 0xb3, 0x5e, 0xcb,
	0xe2, 0x0f, 0x4a, 0xbc, 0x9b, 0xca, 0x77, 0xb1, 0x18, 0x61, 0x9c, 0x86, 0x06, 0x60, 0x1a, 0xa7,
	0x7f, 0x91, 0x4a, 0x74, 0xaf, 0x6d, 0xcb, 0x6e, 0x91, 0x3a, 0x4e, 0x74, 0x80, 0x70, 0xef, 0x3c,
	0x53, 0xae, 0xf1, 0x11, 0x09, 0x7c, 0xc3, 0x64, 0x8d, 0x2c, 0xaf, 0x4e, 0x96, 0x99, 0x87, 0xd2,
	0xb1, 0xd4, 0x96, 0x81, 0x46, 0xe8, 0x14, 0xc3, 0x8d, 0x88, 0xa7, 0x18, 0x29, 0xfa, 0x2d, 0xd9,
	0xf6, 0x9b, 0x34, 0x67, 0x32, 0x8c, 0x49, 0x0f, 0x7e, 0x82, 0xde, 0xed, 0x34, 0x25, 0xcd, 0x5f,
	0x40, 0xcb, 0x4e, 0xb4, 0x3a, 0x6e, 0xef, 0x6d, 0x23, 0xed, 0xd5, 0xe1, 0x84, 0xa5, 0x0f, 0xbb,
	0x0f, 0x90, 0xe3, 0x4b, 0x1d, 0xd5, 0x2b, 0xf2, 0x8d, 0x65, 0x6c, 0x0c, 0xc1, 0x0b, 0x60, 0xee,
	0x7a, 0xdd, 0x58, 0x92, 0xbf, 0x6d, 0xed, 0x29, 0xec, 0xa1, 0x01, 0x46, 0x37, 0x0e, 0xdd, 0x3b,
	0xdb, 0x2a, 0xaa, 0x5d, 0xc6, 0xb0, 0x8b, 0x1b, 0x25, 0xf8, 0x1e, 0x5e, 0xbf, 0x91, 0xb2, 0x6c,
	0xf3, 0x09, 0x34, 0xdd, 0x70, 0x3d, 0x1b, 0xf3, 0xbf, 0x75, 0xe9, 0x5c, 0x82, 0xdf, 0x68, 0x3d,
	0x47, 0xd7, 0xe2, 0x9c, 0xf3, 0xeb, 0x42, 0x54, 0x4d, 0xdc, 0x81, 0x1d, 0x2e, 0xca, 0xfa, 0x49,
	0x62, 0x87, 0xd0, 0x52, 0x18, 0xcb, 0x64, 0x56, 0xed, 0xb6, 0xd3, 0x58, 0x0f, 0xda, 0x5c, 0xe8,
	0x8c, 0xe2, 0xd9, 0xb1, 0xf8, 0x61, 0xa5, 0x9a, 0x41, 0xe2, 0xcb, 0x98, 0x76, 0x62, 0xd7, 0xda,
	0x9d, 0xc2, 0x1e, 0x40, 0x77, 0x42, 0x37, 0x07, 0xa5, 0x90, 0x19, 0xdd, 0xda, 0xa6, 0x7d, 0xab,
	0x9b, 0x82, 0x33, 0xd8, 0x1b, 0x69, 0x2d, 0xd6, 0xad, 0xbd, 0x0b, 0x7b, 0x09, 0xcf, 0x35, 0x91,
	0x60, 0xaf, 0x53, 0x59, 0x53, 0xb7, 0xb4, 0xfd, 0x40, 0x26, 0xf3, 0x79, 0xbb, 0xe2, 0xe9, 0xaa,
	0xfa, 0xbc, 0x19, 0xf9, 0xaa, 0x65, 0x3f, 0x8c, 0x9f, 0xfc, 0x15, 0x00, 0x00, 0xff, 0xff, 0x67,
	0xe2, 0x36, 0xae, 0x99, 0x07, 0x00, 0x00,
}
