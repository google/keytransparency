package monitor

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/keytransparency/core/monitor/storage"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_types"
)

var (
	// ErrNothingProcessed occurs when the monitor did not process any mutations /
	// smrs yet.
	ErrNothingProcessed = errors.New("did not process any mutations yet")
)

// Server holds internal state for the monitor server. It serves monitoring
// responses via a grpc and HTTP API.
type Server struct {
	storage *storage.Storage
}

// New creates a new instance of the monitor server.
func New(storage *storage.Storage) *Server {
	return &Server{
		storage: storage,
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
	latestEpoch := s.storage.LatestEpoch()
	return s.getResponseByRevision(latestEpoch)
}

// GetSignedMapRootByRevision works similar to GetSignedMapRoot but returns
// the monitor's result for a specific map revision.
//
// Returns the signed map root for the specified epoch the monitor observed.
// If the monitor could not reconstruct the map root given the set of
// mutations from the previous to the current epoch it won't sign the map root
// and additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRootByRevision(ctx context.Context, in *mopb.GetMonitoringRequest) (*mopb.GetMonitoringResponse, error) {
	return s.getResponseByRevision(in.GetStart())
}

func (s *Server) getResponseByRevision(epoch int64) (*mopb.GetMonitoringResponse, error) {
	res, err := s.storage.Get(epoch)
	if err == storage.ErrNotFound {
		return nil, grpc.Errorf(codes.NotFound,
			"Could not find monitoring response for epoch %d", epoch)
	}

	resp := &mopb.GetMonitoringResponse{
		Smr:                res.Smr,
		SeenTimestampNanos: res.Seen,
	}

	if len(res.Errors) > 0 {
		for _, err := range resp.Errors {
			resp.Errors = append(resp.Errors, err)
		}
		// data to replay the verification steps:
		resp.ErrorData = res.Response
	}

	return resp, nil
}
