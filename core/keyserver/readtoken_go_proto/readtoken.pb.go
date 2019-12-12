// Code generated by protoc-gen-go. DO NOT EDIT.
// source: readtoken.proto

package readtoken_go_proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	keytransparency_go_proto "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
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

// ReadToken can be serialized and handed to users for pagination.
type ReadToken struct {
	// slice_index identifies the source for reading.
	SliceIndex int64 `protobuf:"varint,1,opt,name=slice_index,json=sliceIndex,proto3" json:"slice_index,omitempty"`
	// start_watermark identifies the lowest (exclusive) row to return.
	StartWatermark       uint64   `protobuf:"varint,4,opt,name=start_watermark,json=startWatermark,proto3" json:"start_watermark,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReadToken) Reset()         { *m = ReadToken{} }
func (m *ReadToken) String() string { return proto.CompactTextString(m) }
func (*ReadToken) ProtoMessage()    {}
func (*ReadToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_735a2ae6888918c9, []int{0}
}

func (m *ReadToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReadToken.Unmarshal(m, b)
}
func (m *ReadToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReadToken.Marshal(b, m, deterministic)
}
func (m *ReadToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReadToken.Merge(m, src)
}
func (m *ReadToken) XXX_Size() int {
	return xxx_messageInfo_ReadToken.Size(m)
}
func (m *ReadToken) XXX_DiscardUnknown() {
	xxx_messageInfo_ReadToken.DiscardUnknown(m)
}

var xxx_messageInfo_ReadToken proto.InternalMessageInfo

func (m *ReadToken) GetSliceIndex() int64 {
	if m != nil {
		return m.SliceIndex
	}
	return 0
}

func (m *ReadToken) GetStartWatermark() uint64 {
	if m != nil {
		return m.StartWatermark
	}
	return 0
}

// ListUserRevisions token can be serialized and handed to users for pagination
// when listing revisions.
type ListUserRevisionsToken struct {
	// request is the query being paginated over, used for validation of
	// subsequent requests. Fields that are allowed to change between requests
	// (such as page_token or last_verified_tree_size) will not be validated and
	// should be omitted for brevity.
	Request *keytransparency_go_proto.ListUserRevisionsRequest `protobuf:"bytes,1,opt,name=request,proto3" json:"request,omitempty"`
	// revisions_returned is a running tally of the number of revisions that have
	// been returned across paginated requests in this query.
	RevisionsReturned    int64    `protobuf:"varint,2,opt,name=revisions_returned,json=revisionsReturned,proto3" json:"revisions_returned,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListUserRevisionsToken) Reset()         { *m = ListUserRevisionsToken{} }
func (m *ListUserRevisionsToken) String() string { return proto.CompactTextString(m) }
func (*ListUserRevisionsToken) ProtoMessage()    {}
func (*ListUserRevisionsToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_735a2ae6888918c9, []int{1}
}

func (m *ListUserRevisionsToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListUserRevisionsToken.Unmarshal(m, b)
}
func (m *ListUserRevisionsToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListUserRevisionsToken.Marshal(b, m, deterministic)
}
func (m *ListUserRevisionsToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListUserRevisionsToken.Merge(m, src)
}
func (m *ListUserRevisionsToken) XXX_Size() int {
	return xxx_messageInfo_ListUserRevisionsToken.Size(m)
}
func (m *ListUserRevisionsToken) XXX_DiscardUnknown() {
	xxx_messageInfo_ListUserRevisionsToken.DiscardUnknown(m)
}

var xxx_messageInfo_ListUserRevisionsToken proto.InternalMessageInfo

func (m *ListUserRevisionsToken) GetRequest() *keytransparency_go_proto.ListUserRevisionsRequest {
	if m != nil {
		return m.Request
	}
	return nil
}

func (m *ListUserRevisionsToken) GetRevisionsReturned() int64 {
	if m != nil {
		return m.RevisionsReturned
	}
	return 0
}

func init() {
	proto.RegisterType((*ReadToken)(nil), "google.keytransparency.v1.ReadToken")
	proto.RegisterType((*ListUserRevisionsToken)(nil), "google.keytransparency.v1.ListUserRevisionsToken")
}

func init() { proto.RegisterFile("readtoken.proto", fileDescriptor_735a2ae6888918c9) }

var fileDescriptor_735a2ae6888918c9 = []byte{
	// 271 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0x41, 0x4b, 0xc3, 0x40,
	0x10, 0x85, 0x49, 0x13, 0xb4, 0x6e, 0xc1, 0xd6, 0x3d, 0x48, 0xf4, 0x62, 0xe9, 0xc5, 0x5e, 0xdc,
	0x50, 0xfb, 0x0f, 0x14, 0x0f, 0x16, 0xbd, 0x2c, 0x8a, 0xe0, 0x65, 0xd9, 0x26, 0x43, 0x5c, 0xd2,
	0xee, 0xd6, 0xd9, 0x49, 0xb4, 0x7f, 0xc4, 0xdf, 0x2b, 0xdd, 0x10, 0x85, 0x8a, 0xa7, 0x81, 0x6f,
	0x78, 0xef, 0xf1, 0x1e, 0x1b, 0x22, 0xe8, 0x82, 0x5c, 0x05, 0x56, 0x6c, 0xd0, 0x91, 0xe3, 0x67,
	0xa5, 0x73, 0xe5, 0x0a, 0x44, 0x05, 0x5b, 0x42, 0x6d, 0xfd, 0x46, 0x23, 0xd8, 0x7c, 0x2b, 0x9a,
	0xd9, 0x79, 0xda, 0xcc, 0xb2, 0x7d, 0x1c, 0x44, 0x13, 0xcd, 0x8e, 0x24, 0xe8, 0xe2, 0x69, 0xe7,
	0xc3, 0x2f, 0xd8, 0xc0, 0xaf, 0x4c, 0x0e, 0xca, 0xd8, 0x02, 0x3e, 0xd3, 0x68, 0x1c, 0x4d, 0x63,
	0xc9, 0x02, 0xba, 0xdf, 0x11, 0x7e, 0xc9, 0x86, 0x9e, 0x34, 0x92, 0xfa, 0xd0, 0x04, 0xb8, 0xd6,
	0x58, 0xa5, 0xc9, 0x38, 0x9a, 0x26, 0xf2, 0x38, 0xe0, 0x97, 0x8e, 0x2e, 0x92, 0x7e, 0x6f, 0x14,
	0x2f, 0x92, 0x7e, 0x3c, 0x4a, 0x26, 0x5f, 0x11, 0x3b, 0x7d, 0x30, 0x9e, 0x9e, 0x3d, 0xa0, 0x84,
	0xc6, 0x78, 0xe3, 0xac, 0x6f, 0x03, 0x1f, 0xd9, 0x21, 0xc2, 0x7b, 0x0d, 0x9e, 0x42, 0xd8, 0xe0,
	0x7a, 0x2e, 0xfe, 0x2d, 0x21, 0xfe, 0x78, 0xc8, 0x56, 0x2a, 0x3b, 0x0f, 0x7e, 0xc5, 0x38, 0x76,
	0x4f, 0x85, 0x40, 0x35, 0x5a, 0x28, 0xd2, 0x5e, 0xa8, 0x71, 0x82, 0xbf, 0xb2, 0xf6, 0x71, 0x73,
	0xf7, 0x7a, 0x5b, 0x1a, 0x7a, 0xab, 0x97, 0x22, 0x77, 0xeb, 0xac, 0x0d, 0xde, 0x9f, 0x29, 0xcb,
	0x1d, 0x06, 0xe8, 0x01, 0x1b, 0xc0, 0xec, 0x67, 0x74, 0x55, 0x3a, 0x15, 0x26, 0x5c, 0x1e, 0x84,
	0x33, 0xff, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x14, 0x27, 0xbb, 0xe3, 0x91, 0x01, 0x00, 0x00,
}
