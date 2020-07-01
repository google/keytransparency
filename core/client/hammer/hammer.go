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

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/client/verifier"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
)

// DialFunc returns a connected grpc client for Key Transparency.
type DialFunc func(ctx context.Context) (pb.KeyTransparencyClient, error)

// CallOptions returns PerRPCCredentials for the requested user.
type CallOptions func(userID string) []grpc.CallOption

// Config tells the hammer what operations to do and how fast to go.
type Config struct {
	TestTypes map[string]bool

	WriteQPS   int
	WriteCount int

	BatchWriteQPS   int
	BatchWriteCount int
	BatchWriteSize  int

	ReadQPS      int
	ReadCount    int
	ReadPageSize int

	HistoryQPS      int
	HistoryCount    int
	HistoryPageSize int

	Duration time.Duration
}

// Hammer represents a single run of the hammer.
type Hammer struct {
	callOptions CallOptions
	timeout     time.Duration
	ktCli       pb.KeyTransparencyClient
	directory   *pb.Directory

	signers        []tink.Signer
	authorizedKeys *keyset.Handle
}

// New returns a new hammer job
func New(ctx context.Context, dial DialFunc, callOptions CallOptions,
	directoryID string, timeout time.Duration, keyset *keyset.Handle) (*Hammer, error) {
	ktCli, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	directory, err := ktCli.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: directoryID})
	if err != nil {
		return nil, err
	}

	authorizedKeys, err := keyset.Public()
	if err != nil {
		return nil, fmt.Errorf("keyset.Public() failed: %v", err)
	}

	signer, err := signature.NewSigner(keyset)
	if err != nil {
		return nil, err
	}

	return &Hammer{
		callOptions: callOptions,
		timeout:     timeout,
		ktCli:       ktCli,
		directory:   directory,

		signers:        []tink.Signer{signer},
		authorizedKeys: authorizedKeys,
	}, nil
}

// Run runs a total of operationCount operations across numWorkers.
// The number of workers should roughly be (goal QPS) * (timeout seconds).
func (h *Hammer) Run(ctx context.Context, numWorkers int, c Config) error {
	workers, err := h.newWorkers(numWorkers)
	if err != nil {
		return err
	}

	if ok := c.TestTypes["create"]; ok {
		// Batch Write users
		log.Print("Batch Write")
		args := genArgs(ctx, c.BatchWriteQPS, c.BatchWriteSize, c.BatchWriteCount, c.Duration)
		handlers := make([]ReqHandler, 0, len(workers))
		for i := range workers {
			handlers = append(handlers, workers[i].createOp)
		}
		log.Printf("workers: %v", len(handlers))
		executeRequests(ctx, args, handlers)
		fmt.Print("\n")
	}

	if ok := c.TestTypes["batch"]; ok {
		// Batch Write users
		log.Print("Batch Write")
		args := genArgs(ctx, c.BatchWriteQPS, c.BatchWriteSize, c.BatchWriteCount, c.Duration)
		handlers := make([]ReqHandler, 0, len(workers))
		for i := range workers {
			handlers = append(handlers, workers[i].writeOp)
		}
		log.Printf("workers: %v", len(handlers))
		executeRequests(ctx, args, handlers)
		fmt.Print("\n")
	}

	if ok := c.TestTypes["write"]; ok {
		// Write users
		log.Print("User Write")
		args := genArgs(ctx, c.WriteQPS, 1, c.WriteCount, c.Duration)
		handlers := make([]ReqHandler, 0, len(workers))
		for i := range workers {
			handlers = append(handlers, workers[i].writeOp)
		}
		executeRequests(ctx, args, handlers)
		fmt.Print("\n")
	}

	if ok := c.TestTypes["read"]; ok {
		// Read users
		log.Print("User Read")
		args := genArgs(ctx, c.ReadQPS, c.ReadPageSize, c.ReadCount, c.Duration)
		handlers := make([]ReqHandler, 0, len(workers))
		for i := range workers {
			handlers = append(handlers, workers[i].readOp)
		}
		executeRequests(ctx, args, handlers)
		fmt.Print("\n")
	}

	if ok := c.TestTypes["audit"]; ok {
		// History
		log.Print("User Audit History")
		args := genArgs(ctx, c.HistoryQPS, c.HistoryPageSize, c.HistoryCount, c.Duration)
		handlers := make([]ReqHandler, 0, len(workers))
		for i := range workers {
			handlers = append(handlers, workers[i].historyOp)
		}
		executeRequests(ctx, args, handlers)
		fmt.Print("\n")
	}

	return nil
}

func genArgs(ctx context.Context, qps, batch, count int, duration time.Duration) <-chan reqArgs {
	inflightReqs := make(chan reqArgs, qps)
	go func() {
		cctx, cancel := context.WithTimeout(ctx, duration)
		defer cancel()
		defer close(inflightReqs)

		rateLimiter := rate.NewLimiter(rate.Limit(qps), batch)
		for i := 0; i < count; i++ {
			userIDs := make([]string, 0, batch)
			for j := 0; j < batch; j++ {
				userIDs = append(userIDs, fmt.Sprintf("user_%v", i*batch+j))
			}
			if err := rateLimiter.WaitN(cctx, batch); err != nil {
				log.Printf("stopping request generation: ratelimiter.WaitN():  %v", err)
				return
			}
			inflightReqs <- reqArgs{
				UserIDs:  userIDs,
				PageSize: batch,
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
	workers := make([]worker, 0, n)
	for i := 0; i < n; i++ {
		// Give each worker its own client.
		client, err := client.NewFromConfig(h.ktCli, h.directory,
			func(lv *tclient.LogVerifier) verifier.LogTracker { return tracker.NewSynchronous(lv) },
		)
		if err != nil {
			return nil, err
		}

		workers = append(workers, worker{
			Hammer: h,
			client: client,
		})
	}
	return workers, nil
}

// createOp queues many user mutations, waits, and then verifies them all.
func (w *worker) createOp(ctx context.Context, req *reqArgs) error {
	users := make([]*client.User, 0, len(req.UserIDs))
	for _, userID := range req.UserIDs {
		users = append(users, &client.User{
			UserID:         userID,
			PublicKeyData:  []byte("publickey"),
			AuthorizedKeys: w.authorizedKeys,
		})
	}

	cctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if err := w.client.BatchCreateUser(cctx, users, w.signers); err != nil {
		return err
	}

	fmt.Print(".")
	return nil
}

// writeOp queues many user mutations, waits, and then verifies them all.
func (w *worker) writeOp(ctx context.Context, req *reqArgs) error {
	users := make([]*client.User, 0, len(req.UserIDs))
	for _, userID := range req.UserIDs {
		users = append(users, &client.User{
			UserID:         userID,
			PublicKeyData:  []byte("publickey"),
			AuthorizedKeys: w.authorizedKeys,
		})
	}

	cctx, cancel := context.WithTimeout(ctx, w.timeout)
	mutations, err := w.client.BatchCreateMutation(cctx, users)
	cancel()
	if err != nil {
		return err
	}

	cctx, cancel = context.WithTimeout(ctx, w.timeout)
	err = w.client.BatchQueueUserUpdate(cctx, mutations, w.signers)
	cancel()
	if err != nil {
		return err
	}

	for _, m := range mutations {
		cctx, cancel := context.WithTimeout(ctx, w.timeout)
		_, err := w.client.WaitForUserUpdate(cctx, m)
		cancel()
		if err != nil {
			return err
		}
		fmt.Print(".")
	}
	return nil
}

// readOp simulates multiple read operations by a single client.
// Typical conversation setup involves querying two userIDs: self and other.
func (w *worker) readOp(ctx context.Context, req *reqArgs) error {
	for _, userID := range req.UserIDs {
		if _, _, err := w.client.GetUser(ctx, userID); err != nil {
			return err
		}
		fmt.Print(".")
	}
	return nil
}

// historyOp simulates the daily check-in.
func (w *worker) historyOp(ctx context.Context, req *reqArgs) error {
	for _, userID := range req.UserIDs {
		if _, _, err := w.client.PaginateHistory(ctx, userID, 0, int64(req.PageSize)); err != nil {
			return err
		}
		fmt.Print(".")
	}
	return nil
}
