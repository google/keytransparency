// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: proto/sequencer_v1_grpc/sequencer_v1_grpc.proto

/*
Package sequencer_v1_grpc is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package sequencer_v1_grpc

import (
	"io"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/utilities"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
)

var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray

func request_SequencerService_GetEpochs_0(ctx context.Context, marshaler runtime.Marshaler, client SequencerServiceClient, req *http.Request, pathParams map[string]string) (SequencerService_GetEpochsClient, runtime.ServerMetadata, error) {
	var protoReq keytransparency_v1_grpc.GetEpochsRequest
	var metadata runtime.ServerMetadata

	stream, err := client.GetEpochs(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

// RegisterSequencerServiceHandlerFromEndpoint is same as RegisterSequencerServiceHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterSequencerServiceHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Printf("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Printf("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterSequencerServiceHandler(ctx, mux, conn)
}

// RegisterSequencerServiceHandler registers the http handlers for service SequencerService to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterSequencerServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterSequencerServiceHandlerClient(ctx, mux, NewSequencerServiceClient(conn))
}

// RegisterSequencerServiceHandler registers the http handlers for service SequencerService to "mux".
// The handlers forward requests to the grpc endpoint over the given implementation of "SequencerServiceClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "SequencerServiceClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "SequencerServiceClient" to call the correct interceptors.
func RegisterSequencerServiceHandlerClient(ctx context.Context, mux *runtime.ServeMux, client SequencerServiceClient) error {

	mux.Handle("GET", pattern_SequencerService_GetEpochs_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_SequencerService_GetEpochs_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_SequencerService_GetEpochs_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_SequencerService_GetEpochs_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"v1", "epochs"}, "stream"))
)

var (
	forward_SequencerService_GetEpochs_0 = runtime.ForwardResponseStream
)
