package monitor

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"testing"
)

func TestGetSignedMapRoot(t *testing.T) {
	srv := server{}
	_, err := srv.GetSignedMapRoot(context.TODO(), nil)
	if got, want := grpc.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetSignedMapRootStream(_, _): %v, want %v", got, want)
	}
}

func TestGetSignedMapRootStream(t *testing.T) {
	srv := server{}
	err := srv.GetSignedMapRootStream(nil, nil)
	if got, want := grpc.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetSignedMapRootStream(_, _): %v, want %v", got, want)
	}
}
