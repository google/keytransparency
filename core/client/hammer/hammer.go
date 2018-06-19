// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hammer sends multiple requests to Key Transparency at the same time.
package hammer

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/tink/go/tink"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/mutator/entry"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// DialFunc returns a connected grpc client for Key Transparency.
type DialFunc func(ctx context.Context, addr string, opts ...grpc.DialOption) (pb.KeyTransparencyClient, error)

// CallOptions returns PerRPCCredentials for the requested user.
type CallOptions func(userID string) []grpc.CallOption

// Config tells the hammer how fast to go.
type Config struct {
	WriteQPS   int
	WriteCount int

	BatchWriteQPS   int
	BatchWriteCount int
	BatchWriteSize  int

	ReadQPS   int
	ReadCount int

	HistoryQPS       int
	HistoryCount     int
	HistoryBatchSize int

	Duration time.Duration
}

// Hammer represents a single run of the hammer.
type Hammer struct {
	callOptions CallOptions
	timeout     time.Duration
	ktCli       pb.KeyTransparencyClient
	appID       string
	domain      *pb.Domain

	signers        []*tink.KeysetHandle
	authorizedKeys *tinkpb.Keyset
}

// New returns a new hammer job
func New(ctx context.Context, dial DialFunc, callOptions CallOptions,
	ktAddr, domainID string, timeout time.Duration, keyset *tink.KeysetHandle) (*Hammer, error) {
	ktCli, err := dial(ctx, ktAddr)
	if err != nil {
		return nil, err
	}

	domain, err := ktCli.GetDomain(ctx, &pb.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, err
	}

	authorizedKeys, err := keyset.GetPublicKeysetHandle()
	if err != nil {
		return nil, fmt.Errorf("keyset.GetPublicKeysetHandle() failed: %v", err)
	}

	return &Hammer{
		callOptions: callOptions,
		timeout:     timeout,
		ktCli:       ktCli,
		appID:       fmt.Sprintf("hammer_%v", time.Now().Format("2006-01-02/15:04:05")),
		domain:      domain,

		signers:        []*tink.KeysetHandle{keyset},
		authorizedKeys: authorizedKeys.Keyset(),
	}, nil
}

// Run runs operationCount with up to maxWorkers over ramp duration.
// workers should roughly be (goal QPS / timeout seconds)
func (h *Hammer) Run(ctx context.Context, numWorkers int, c Config) error {
	workers, err := h.newWorkers(numWorkers)
	if err != nil {
		return err
	}

	// Batch Write users
	log.Printf("Batch Write")
	requests := genRequests(ctx, c.BatchWriteQPS, c.BatchWriteSize, c.BatchWriteCount, c.Duration)
	handlers := make([]ReqHandler, 0, len(workers))
	for _, w := range workers {
		handlers = append(handlers, w.writeOp)
	}
	generateReport(ctx, requests, handlers)

	// Write users
	log.Printf("User Write")
	requests = genRequests(ctx, c.WriteQPS, 1, c.WriteCount, c.Duration)
	handlers = make([]ReqHandler, 0, len(workers))
	for _, w := range workers {
		handlers = append(handlers, w.writeOp)
	}
	generateReport(ctx, requests, handlers)

	// Read users
	log.Printf("User Read")
	requests = genRequests(ctx, c.ReadQPS, 1, c.ReadCount, c.Duration)
	handlers = make([]ReqHandler, 0, len(workers))
	for _, w := range workers {
		handlers = append(handlers, w.readOp)
	}
	generateReport(ctx, requests, handlers)

	// History
	log.Printf("User Audit History")
	requests = genRequests(ctx, c.HistoryQPS, c.HistoryBatchSize, c.HistoryCount, c.Duration)
	handlers = make([]ReqHandler, 0, len(workers))
	for _, w := range workers {
		handlers = append(handlers, w.historyOp)
	}
	generateReport(ctx, requests, handlers)

	return nil
}

func genRequests(ctx context.Context, qps, batch, count int, duration time.Duration) <-chan request {
	inflightReqs := make(chan request)
	go func() {
		cctx, cancel := context.WithTimeout(ctx, duration)
		defer cancel()
		defer close(inflightReqs)

		rateLimiter := rate.NewLimiter(rate.Limit(qps), qps)
		for i := 0; i < count; i++ {
			userIDs := make([]string, 0, batch)
			for j := 0; j < batch; j++ {
				userIDs = append(userIDs, fmt.Sprintf("user_%v", i*batch+j))
			}
			if err := rateLimiter.Wait(cctx); err != nil {
				return
			}
			inflightReqs <- request{
				UserIDs:   userIDs,
				BatchSize: batch,
			}
		}
	}()
	return inflightReqs
}

type worker struct {
	*Hammer
	client *client.Client
}

func (h *Hammer) newWorkers(n int) ([]worker, error) {
	workers := make([]worker, n)
	for i := range workers {
		// Give each worker it's own client.
		client, err := client.NewFromConfig(h.ktCli, h.domain)
		if err != nil {
			return nil, err
		}

		workers[i] = worker{Hammer: h, client: client}
	}
	return workers, nil
}

// batchWriteOp queues many user mutations, waits, and then verifies them all.
func (w *worker) writeOp(ctx context.Context, req *request) error {
	users := make([]*tpb.User, 0, req.BatchSize)
	for _, userID := range req.UserIDs {
		users = append(users, &tpb.User{
			DomainId:       w.domain.DomainId,
			AppId:          w.appID,
			UserId:         userID,
			PublicKeyData:  []byte("publickey"),
			AuthorizedKeys: w.authorizedKeys,
		})
	}

	mutations := make([]*entry.Mutation, 0, len(users))
	for _, u := range users {
		callOptions := w.callOptions(u.UserId)
		cctx, cancel := context.WithTimeout(ctx, w.timeout)
		defer cancel()
		m, err := w.client.CreateMutation(cctx, u)
		if err != nil {
			return err
		}
		if err := w.client.QueueMutation(cctx, m, w.signers, callOptions...); err != nil {
			return err
		}
	}

	for _, m := range mutations {
		cctx, cancel := context.WithTimeout(ctx, w.timeout)
		defer cancel()
		if _, err := w.client.WaitForUserUpdate(cctx, m); err != nil {
			return err
		}
	}
	return nil
}

// readOp simulates a read operation, typically performed during conversation setup.
func (w *worker) readOp(ctx context.Context, req *request) error {
	for _, userID := range req.UserIDs {
		_, _, err := w.client.GetEntry(ctx, userID, w.appID)
		if err != nil {
			return err
		}
	}
	return nil
}

// auditHistoryOp simulates the daily check-in.
func (w *worker) historyOp(ctx context.Context, req *request) error {
	for _, userID := range req.UserIDs {
		_, _, err := w.client.PaginateHistory(ctx, userID, w.appID, 0, int64(req.BatchSize))
		if err != nil {
			return err
		}
	}
	return nil
}
