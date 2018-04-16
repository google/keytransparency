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
	"sync"
	"time"

	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/client"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// CustomDial returns a grpc connection.
var CustomDial func(ctx context.Context, addr string, opts ...grpc.DialOption) (pb.KeyTransparencyClient, error)

// Hammer represents a single run of the hammer.
type Hammer struct {
	workers int

	timeout time.Duration
	ktAddr  string
	appID   string
	config  *pb.Domain

	signers        []*tink.KeysetHandle
	authorizedKeys *tinkpb.Keyset
}

// New returns a new hammer job
func New(ctx context.Context, ktAddr, domainID string, timeout time.Duration, keyset *tink.KeysetHandle) (*Hammer, error) {
	client, err := CustomDial(ctx, ktAddr)
	if err != nil {
		return nil, err
	}

	config, err := client.GetDomain(ctx, &pb.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, err
	}

	authorizedKeys, err := keyset.GetPublicKeysetHandle()
	if err != nil {
		return nil, fmt.Errorf("keyset.GetPublicKeysetHandle() failed: %v", err)
	}

	return &Hammer{
		timeout: timeout,
		ktAddr:  ktAddr,
		appID:   fmt.Sprintf("hammer_%v", time.Now().Format("2006-01-02/15:04:05")),
		config:  config,

		signers:        []*tink.KeysetHandle{keyset},
		authorizedKeys: authorizedKeys.Keyset(),
	}, nil
}

// Run runs operationCount with up to maxWorkers over ramp duration.
func (h *Hammer) Run(ctx context.Context, operationCount, maxWorkers int, ramp time.Duration) {
	jobs := gen(ctx, operationCount)
	outputs := h.launchWorkers(ctx, jobs, maxWorkers, ramp)
	h.printStats(1*time.Second, outputs)
}

// launchWorkers gradually adds workers to the worker pool over ramp up to workers.
func (h *Hammer) launchWorkers(ctx context.Context, jobs <-chan int, workers int, ramp time.Duration) <-chan error {
	outputs := make(chan error)

	go func() {
		rampTicker := time.NewTicker(ramp / time.Duration(workers))
		var wg sync.WaitGroup
		for ; h.workers < workers; h.workers++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.worker(ctx, jobs, outputs)
			}()
			<-rampTicker.C
		}
		rampTicker.Stop()

		wg.Wait()
		close(outputs)
	}()

	return outputs
}

// gen produces a channel of integers from 0 up to count-1 and then closes.
func gen(ctx context.Context, count int) <-chan int {
	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := 0; i < count; i++ {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()
	return jobs
}

// printStats prints stats repeatedly every period until outputs closes.
func (h *Hammer) printStats(period time.Duration, outputs <-chan error) {
	startTime := time.Now()
	var totalRequests float64

	// Print stats asyncronously until refresh closes.
	refresh := time.NewTicker(period)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-refresh.C:
				rate := totalRequests / time.Since(startTime).Seconds()
				log.Printf("QPS: %v, \tRequests: %v, \tWorkers: %v", rate, totalRequests, h.workers)
			case <-stop:
				rate := totalRequests / time.Since(startTime).Seconds()
				log.Printf("QPS: %v, \tRequests: %v, \tWorkers: %v", rate, totalRequests, h.workers)
				refresh.Stop()
				return
			}
		}
	}()

	// Collect outputs until output closes.
	for err := range outputs {
		totalRequests++
		if err != nil {
			log.Printf("writeOp(): %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

func (h *Hammer) worker(ctx context.Context, jobs <-chan int, outputs chan<- error) {
	for i := range jobs {
		userID := fmt.Sprintf("user_%v", i)
		outputs <- h.writeOp(ctx, userID)
	}
}

// writeOp performs one write command.
func (h *Hammer) writeOp(ctx context.Context, userID string) error {
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	u := &tpb.User{
		DomainId:       h.config.DomainId,
		AppId:          h.appID,
		UserId:         userID,
		PublicKeyData:  []byte("publickey"),
		AuthorizedKeys: h.authorizedKeys,
	}
	c, err := h.getClientWithUser(cctx, userID)
	if err != nil {
		return fmt.Errorf("getClient(): %v", err)
	}
	_, err = c.Update(cctx, u, h.signers)
	return fmt.Errorf("Update(): %v", err)
}

// getClient connects to the server and returns a key transparency verification client.
func (h *Hammer) getClientWithUser(ctx context.Context, userID string) (*client.Client, error) {
	userCreds := authentication.GetFakeCredential(userID)

	ktCli, err := CustomDial(ctx, h.ktAddr, grpc.WithPerRPCCredentials(userCreds))
	if err != nil {
		return nil, fmt.Errorf("Dial(): %v", err)
	}

	return client.NewFromConfig(ktCli, h.config)
}
