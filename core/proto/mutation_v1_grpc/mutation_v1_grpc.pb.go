// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/mutation_v1_grpc/mutation_v1_grpc.proto

/*
Package mutation_v1_grpc is a generated protocol buffer package.

Mutation Service

The Key Transparency mutation server service consists of APIs to fetch
mutations.

It is generated from these files:
	proto/mutation_v1_grpc/mutation_v1_grpc.proto

It has these top-level messages:
*/
package mutation_v1_grpc

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import keytransparency_v1_proto "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for MutationService service

type MutationServiceClient interface {
	// GetMutations returns a list of mutations in a specific epoch.
	//
	// Returns a list of mutations and their inclusion proofs along with the epoch
	// signed map root.
	GetMutations(ctx context.Context, in *keytransparency_v1_proto.GetMutationsRequest, opts ...grpc.CallOption) (*keytransparency_v1_proto.GetMutationsResponse, error)
	// GetMutationsStream is a streaming API similar to GetMutations.
	//
	// Returns a list of mutations and their inclusion proofs along with the epoch
	// signed map root.
	GetMutationsStream(ctx context.Context, in *keytransparency_v1_proto.GetMutationsRequest, opts ...grpc.CallOption) (MutationService_GetMutationsStreamClient, error)
}

type mutationServiceClient struct {
	cc *grpc.ClientConn
}

func NewMutationServiceClient(cc *grpc.ClientConn) MutationServiceClient {
	return &mutationServiceClient{cc}
}

func (c *mutationServiceClient) GetMutations(ctx context.Context, in *keytransparency_v1_proto.GetMutationsRequest, opts ...grpc.CallOption) (*keytransparency_v1_proto.GetMutationsResponse, error) {
	out := new(keytransparency_v1_proto.GetMutationsResponse)
	err := grpc.Invoke(ctx, "/mutation.v1.grpc.MutationService/GetMutations", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mutationServiceClient) GetMutationsStream(ctx context.Context, in *keytransparency_v1_proto.GetMutationsRequest, opts ...grpc.CallOption) (MutationService_GetMutationsStreamClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_MutationService_serviceDesc.Streams[0], c.cc, "/mutation.v1.grpc.MutationService/GetMutationsStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &mutationServiceGetMutationsStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type MutationService_GetMutationsStreamClient interface {
	Recv() (*keytransparency_v1_proto.GetMutationsResponse, error)
	grpc.ClientStream
}

type mutationServiceGetMutationsStreamClient struct {
	grpc.ClientStream
}

func (x *mutationServiceGetMutationsStreamClient) Recv() (*keytransparency_v1_proto.GetMutationsResponse, error) {
	m := new(keytransparency_v1_proto.GetMutationsResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for MutationService service

type MutationServiceServer interface {
	// GetMutations returns a list of mutations in a specific epoch.
	//
	// Returns a list of mutations and their inclusion proofs along with the epoch
	// signed map root.
	GetMutations(context.Context, *keytransparency_v1_proto.GetMutationsRequest) (*keytransparency_v1_proto.GetMutationsResponse, error)
	// GetMutationsStream is a streaming API similar to GetMutations.
	//
	// Returns a list of mutations and their inclusion proofs along with the epoch
	// signed map root.
	GetMutationsStream(*keytransparency_v1_proto.GetMutationsRequest, MutationService_GetMutationsStreamServer) error
}

func RegisterMutationServiceServer(s *grpc.Server, srv MutationServiceServer) {
	s.RegisterService(&_MutationService_serviceDesc, srv)
}

func _MutationService_GetMutations_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(keytransparency_v1_proto.GetMutationsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MutationServiceServer).GetMutations(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mutation.v1.grpc.MutationService/GetMutations",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MutationServiceServer).GetMutations(ctx, req.(*keytransparency_v1_proto.GetMutationsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MutationService_GetMutationsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(keytransparency_v1_proto.GetMutationsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(MutationServiceServer).GetMutationsStream(m, &mutationServiceGetMutationsStreamServer{stream})
}

type MutationService_GetMutationsStreamServer interface {
	Send(*keytransparency_v1_proto.GetMutationsResponse) error
	grpc.ServerStream
}

type mutationServiceGetMutationsStreamServer struct {
	grpc.ServerStream
}

func (x *mutationServiceGetMutationsStreamServer) Send(m *keytransparency_v1_proto.GetMutationsResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _MutationService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "mutation.v1.grpc.MutationService",
	HandlerType: (*MutationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetMutations",
			Handler:    _MutationService_GetMutations_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetMutationsStream",
			Handler:       _MutationService_GetMutationsStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "proto/mutation_v1_grpc/mutation_v1_grpc.proto",
}

func init() { proto.RegisterFile("proto/mutation_v1_grpc/mutation_v1_grpc.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 254 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x2d, 0x28, 0xca, 0x2f,
	0xc9, 0xd7, 0xcf, 0x2d, 0x2d, 0x49, 0x2c, 0xc9, 0xcc, 0xcf, 0x8b, 0x2f, 0x33, 0x8c, 0x4f, 0x2f,
	0x2a, 0x48, 0xc6, 0x10, 0xd0, 0x03, 0xab, 0x13, 0x12, 0x80, 0x89, 0xeb, 0x95, 0x19, 0xea, 0x81,
	0xc4, 0xa5, 0x64, 0xd2, 0xf3, 0xf3, 0xd3, 0x73, 0x52, 0xf5, 0x13, 0x0b, 0x32, 0xf5, 0x13, 0xf3,
	0xf2, 0xf2, 0x21, 0xd2, 0xc5, 0x10, 0xf5, 0x52, 0xb6, 0x10, 0xe3, 0xb3, 0x53, 0x2b, 0x4b, 0x8a,
	0x12, 0xf3, 0x8a, 0x0b, 0x12, 0x8b, 0x52, 0xf3, 0x92, 0x2b, 0x41, 0x86, 0xe2, 0x97, 0x80, 0x68,
	0x37, 0xda, 0xc0, 0xc4, 0xc5, 0xef, 0x0b, 0xb5, 0x31, 0x38, 0xb5, 0xa8, 0x2c, 0x33, 0x39, 0x55,
	0xa8, 0x93, 0x91, 0x8b, 0xc7, 0x3d, 0xb5, 0x04, 0x26, 0x5c, 0x2c, 0xa4, 0xab, 0x87, 0x66, 0x0a,
	0xc8, 0x6d, 0x10, 0x53, 0x90, 0xd5, 0x05, 0xa5, 0x16, 0x96, 0xa6, 0x16, 0x97, 0x48, 0xe9, 0x11,
	0xab, 0xbc, 0xb8, 0x20, 0x3f, 0xaf, 0x38, 0x55, 0x49, 0xaa, 0xe9, 0xf2, 0x93, 0xc9, 0x4c, 0x22,
	0x42, 0x42, 0xfa, 0x65, 0x86, 0xfa, 0xa9, 0x05, 0xf9, 0xc9, 0x19, 0xc5, 0xfa, 0xd5, 0x60, 0xba,
	0x56, 0x68, 0x02, 0x23, 0x97, 0x10, 0xb2, 0xa6, 0xe0, 0x92, 0xa2, 0xd4, 0xc4, 0x5c, 0x5a, 0xbb,
	0x48, 0x12, 0xec, 0x22, 0x61, 0x21, 0x41, 0x84, 0x8b, 0xac, 0x8a, 0xc1, 0x36, 0x1b, 0x30, 0x3a,
	0xd9, 0x47, 0xd9, 0xa6, 0x67, 0x96, 0x64, 0x94, 0x26, 0xe9, 0x25, 0xe7, 0xe7, 0xea, 0x43, 0x23,
	0x07, 0xcd, 0x7c, 0xfd, 0xe4, 0xfc, 0xa2, 0x54, 0x7d, 0xec, 0x31, 0x9f, 0xc4, 0x06, 0x16, 0x37,
	0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0x60, 0x3a, 0xfe, 0xf2, 0x1a, 0x02, 0x00, 0x00,
}
