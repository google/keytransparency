package monitor

import (
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/trillian"

	tcrypto "github.com/google/trillian/crypto"

	cmon "github.com/google/keytransparency/core/monitor"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_types"

	mupb "github.com/google/keytransparency/impl/proto/mutation_v1_service"
)

// Server holds internal state for the monitor server. It serves monitoring
// responses via a grpc and HTTP API.
type Server struct {
	client *MutationsClient

	monitor        *cmon.Monitor
}

// New creates a new instance of the monitor server.
func New(cli mupb.MutationServiceClient,
	signer *tcrypto.Signer,
	logTree, mapTree *trillian.Tree,
	poll time.Duration) *Server {
	mon, err := cmon.New(logTree, mapTree, signer)
	if err != nil {
		glog.Fatalf("Could not create monitor: %v", err)
	}
	return &Server{
		client: &MutationsClient{
			client:     cli,
			pollPeriod: poll,
		},
		monitor:        mon,
	}
}

// GetSignedMapRoot returns the latest valid signed map root the monitor
// observed. Additionally, the response contains additional data necessary to
// reproduce errors on failure.
//
// Returns the signed map root for the latest epoch the monitor observed. If
// the monitor could not reconstruct the map root given the set of mutations
// from the previous to the current epoch it won't sign the map root and
// additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRoot(ctx context.Context, in *mopb.GetMonitoringRequest) (*mopb.GetMonitoringResponse, error) {
	return nil, ErrNothingProcessed
}

// GetSignedMapRootByRevision works similar to GetSignedMapRoot but returns
// the monitor's result for a specific map revision.
//
// Returns the signed map root for the specified epoch the monitor observed.
// If the monitor could not reconstruct the map root given the set of
// mutations from the previous to the current epoch it won't sign the map root
// and additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRootByRevision(ctx context.Context, in *mopb.GetMonitoringRequest) (*mopb.GetMonitoringResponse, error) {
	// TODO(ismail): implement by revision API
	return nil, grpc.Errorf(codes.Unimplemented, "GetSignedMapRoot is unimplemented")
}
