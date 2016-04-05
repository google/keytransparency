// Code generated by protoc-gen-go.
// source: proto/security_e2ekeys_core/core.proto
// DO NOT EDIT!

/*
Package security_e2ekeys_core is a generated protocol buffer package.

It is generated from these files:
	proto/security_e2ekeys_core/core.proto

It has these top-level messages:
	EntryStorage
	EpochInfo
	DomainInfo
	VerifierInfo
*/
package security_e2ekeys_core

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import security_ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// EntryStorage is what gets serialized to disk / log.
type EntryStorage struct {
	// commitment_timestamp is a sequential update number of the SignedEntryUpdate.
	CommitmentTimestamp int64 `protobuf:"varint,1,opt,name=commitment_timestamp" json:"commitment_timestamp,omitempty"`
	// entry_update contains a SignedEntryUpdate proto with the actual update
	// contents.
	SignedEntryUpdate *security_ctmap.SignedEntryUpdate `protobuf:"bytes,2,opt,name=signed_entry_update" json:"signed_entry_update,omitempty"`
	// profile is the serialized protobuf Profile.
	// profile is private and must not be released to verifiers.
	Profile []byte `protobuf:"bytes,3,opt,name=profile,proto3" json:"profile,omitempty"`
	// commitment_key is at least 16 random bytes.
	CommitmentKey []byte `protobuf:"bytes,4,opt,name=commitment_key,proto3" json:"commitment_key,omitempty"`
	// domain allows servers to keep track of multiple trees at once.
	Domain string `protobuf:"bytes,5,opt,name=domain" json:"domain,omitempty"`
}

func (m *EntryStorage) Reset()                    { *m = EntryStorage{} }
func (m *EntryStorage) String() string            { return proto.CompactTextString(m) }
func (*EntryStorage) ProtoMessage()               {}
func (*EntryStorage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *EntryStorage) GetSignedEntryUpdate() *security_ctmap.SignedEntryUpdate {
	if m != nil {
		return m.SignedEntryUpdate
	}
	return nil
}

// EpochInfo is what gets serialized to disk / log.
type EpochInfo struct {
	// signed_epoch_head is the signed epoch head of the created epoch.
	SignedEpochHead *security_ctmap.SignedEpochHead `protobuf:"bytes,1,opt,name=signed_epoch_head" json:"signed_epoch_head,omitempty"`
	// last_commitment_timestamp is the timestamp of the last update included in
	// created epoch.
	LastCommitmentTimestamp int64 `protobuf:"varint,2,opt,name=last_commitment_timestamp" json:"last_commitment_timestamp,omitempty"`
}

func (m *EpochInfo) Reset()                    { *m = EpochInfo{} }
func (m *EpochInfo) String() string            { return proto.CompactTextString(m) }
func (*EpochInfo) ProtoMessage()               {}
func (*EpochInfo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *EpochInfo) GetSignedEpochHead() *security_ctmap.SignedEpochHead {
	if m != nil {
		return m.SignedEpochHead
	}
	return nil
}

// DomainInfo is the information that need to be baked into an application
// in order to verify information for a domain.
type DomainInfo struct {
	PublicKeys []*security_ctmap.PublicKey `protobuf:"bytes,1,rep,name=public_keys" json:"public_keys,omitempty"`
	// required_sigs is the number of valid signatures to require out of
	// public_keys before considering signed_tree heads legitimate.
	RequiredSigs uint32 `protobuf:"varint,2,opt,name=required_sigs" json:"required_sigs,omitempty"`
	// domain is the doman suffix to use when resolving a user_id to a domain.
	Domain string `protobuf:"bytes,3,opt,name=domain" json:"domain,omitempty"`
	// api_url is the url prefix to use when querying users on this domain.
	ApiUrl string `protobuf:"bytes,4,opt,name=api_url" json:"api_url,omitempty"`
}

func (m *DomainInfo) Reset()                    { *m = DomainInfo{} }
func (m *DomainInfo) String() string            { return proto.CompactTextString(m) }
func (*DomainInfo) ProtoMessage()               {}
func (*DomainInfo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *DomainInfo) GetPublicKeys() []*security_ctmap.PublicKey {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

type VerifierInfo struct {
	PublicKeys []*security_ctmap.PublicKey `protobuf:"bytes,1,rep,name=public_keys" json:"public_keys,omitempty"`
	// required_sigs is the number of valid signatures to require out of
	// public_keys before considering signed_tree heads legitimate.
	RequiredSigs uint32 `protobuf:"varint,2,opt,name=required_sigs" json:"required_sigs,omitempty"`
	// api_url is the url prefix to use when querying users on this domain.
	ApiUrl string `protobuf:"bytes,4,opt,name=api_url" json:"api_url,omitempty"`
	// domain is the doman suffix that this verifier is responsible for.
	Domain string `protobuf:"bytes,3,opt,name=domain" json:"domain,omitempty"`
}

func (m *VerifierInfo) Reset()                    { *m = VerifierInfo{} }
func (m *VerifierInfo) String() string            { return proto.CompactTextString(m) }
func (*VerifierInfo) ProtoMessage()               {}
func (*VerifierInfo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *VerifierInfo) GetPublicKeys() []*security_ctmap.PublicKey {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

func init() {
	proto.RegisterType((*EntryStorage)(nil), "security.e2ekeys.core.EntryStorage")
	proto.RegisterType((*EpochInfo)(nil), "security.e2ekeys.core.EpochInfo")
	proto.RegisterType((*DomainInfo)(nil), "security.e2ekeys.core.DomainInfo")
	proto.RegisterType((*VerifierInfo)(nil), "security.e2ekeys.core.VerifierInfo")
}

var fileDescriptor0 = []byte{
	// 365 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xac, 0x92, 0x4f, 0x4b, 0xeb, 0x40,
	0x14, 0xc5, 0xe9, 0xcb, 0x7b, 0x7d, 0x64, 0xfa, 0xe7, 0xf1, 0x46, 0x2b, 0xa9, 0x08, 0xda, 0x2c,
	0xc4, 0x4d, 0x13, 0xa8, 0x3b, 0x17, 0xba, 0xb1, 0xa0, 0xb8, 0x11, 0x8a, 0x6e, 0x87, 0x69, 0x72,
	0x9b, 0x8e, 0x26, 0x99, 0x38, 0x33, 0x29, 0xe4, 0x03, 0xf9, 0x3d, 0xbd, 0x33, 0x5a, 0xa8, 0x41,
	0x77, 0x2e, 0x12, 0x98, 0xb9, 0xe7, 0x9e, 0xdf, 0x39, 0x21, 0xe4, 0xb4, 0x52, 0xd2, 0xc8, 0x58,
	0x43, 0x52, 0x2b, 0x61, 0x1a, 0x06, 0x33, 0x78, 0x86, 0x46, 0xb3, 0x44, 0x2a, 0x88, 0xed, 0x2b,
	0x72, 0x02, 0x3a, 0xda, 0x2a, 0xa2, 0x0f, 0x45, 0x64, 0x87, 0x87, 0x57, 0x99, 0x30, 0xeb, 0x7a,
	0x89, 0x87, 0x22, 0xce, 0xa4, 0xcc, 0x72, 0x88, 0x71, 0x3e, 0x45, 0xc1, 0x54, 0x83, 0xda, 0x80,
	0x8a, 0x5b, 0xfe, 0x89, 0x29, 0x78, 0x15, 0xe3, 0xf3, 0xee, 0x1b, 0xbe, 0x76, 0x48, 0x7f, 0x5e,
	0x1a, 0xd5, 0x2c, 0x8c, 0x54, 0x3c, 0x03, 0x7a, 0x44, 0xf6, 0xd1, 0xac, 0x10, 0xa6, 0x80, 0xd2,
	0x30, 0x23, 0x0a, 0xd0, 0x86, 0x17, 0x55, 0xd0, 0x39, 0xe9, 0x9c, 0x79, 0xf4, 0x92, 0xec, 0x69,
	0x91, 0x95, 0x90, 0x32, 0xb0, 0x4b, 0xac, 0xae, 0x52, 0x6e, 0x20, 0xf8, 0x85, 0xc3, 0xde, 0x6c,
	0x12, 0x7d, 0xc6, 0x44, 0x0b, 0x27, 0x75, 0xf6, 0x0f, 0x4e, 0x48, 0xff, 0x91, 0xbf, 0xc8, 0x5d,
	0x89, 0x1c, 0x02, 0x0f, 0x77, 0xfa, 0xf4, 0x80, 0x0c, 0x77, 0x70, 0x98, 0x3b, 0xf8, 0xed, 0xee,
	0x87, 0xa4, 0x9b, 0xca, 0x82, 0x8b, 0x32, 0xf8, 0x83, 0x67, 0x3f, 0x7c, 0x22, 0xfe, 0xbc, 0x92,
	0xc9, 0xfa, 0xb6, 0x5c, 0x49, 0x7a, 0x41, 0xfe, 0x6f, 0x53, 0xd8, 0x3b, 0xb6, 0x06, 0x9e, 0xba,
	0x80, 0xbd, 0xd9, 0xf1, 0x37, 0x19, 0xac, 0xee, 0x06, 0x65, 0x74, 0x42, 0xc6, 0x39, 0xd7, 0x86,
	0x7d, 0x59, 0xd2, 0xf6, 0xf0, 0x42, 0x43, 0xc8, 0xb5, 0x63, 0x3b, 0x58, 0x44, 0x7a, 0x55, 0xbd,
	0xcc, 0x45, 0x62, 0xd3, 0x69, 0xc4, 0x78, 0x88, 0x19, 0xb7, 0x31, 0xf7, 0x4e, 0x72, 0x07, 0x0d,
	0x1d, 0x91, 0x81, 0x82, 0x97, 0x5a, 0x28, 0x8c, 0x87, 0x29, 0xb5, 0x33, 0x1d, 0xec, 0x14, 0xb2,
	0xc5, 0x7d, 0xfb, 0x25, 0x78, 0x25, 0x58, 0xad, 0x72, 0xd7, 0xd8, 0x0f, 0x37, 0xa4, 0xff, 0x08,
	0x4a, 0xac, 0x04, 0xa8, 0x9f, 0xe4, 0xb6, 0x39, 0xed, 0x20, 0xcb, 0xae, 0xfb, 0x11, 0xce, 0xdf,
	0x02, 0x00, 0x00, 0xff, 0xff, 0x81, 0xda, 0x86, 0x83, 0x8a, 0x02, 0x00, 0x00,
}
