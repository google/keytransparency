// Copyright 2015 Google Inc. All Rights Reserved.
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

package storage

import (
	"encoding/base64"
	"strings"

	"github.com/gogo/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	etcderr "github.com/coreos/etcd/error"
	"github.com/coreos/go-etcd/etcd"
	pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	promisesDirectory = "promises"
)

type EtcdConfiguration struct {
	Machines []string
	// When ConsistentReads is set, we'll use etcd quorum reads
	ConsistentReads bool
	// TODO: TLS certificates, etc
}

// Due to limitations in the etcd Go bindings, this implementation is not thread-safe
type EtcdConsistentStore struct {
	client *etcd.Client
}

func OpenEtcdStore(config *EtcdConfiguration) *EtcdConsistentStore {
	client := etcd.NewClient(config.Machines)
	if config.ConsistentReads {
		client.SetConsistency(etcd.STRONG_CONSISTENCY)
	} else {
		client.SetConsistency(etcd.WEAK_CONSISTENCY)
	}
	return &EtcdConsistentStore{client}
}

func (s *EtcdConsistentStore) Close() {
	s.client.Close()
}

// Returns a codes.AlreadyExists error if a promise for the same (user_id, key_id) already exists
func (s *EtcdConsistentStore) InsertPromise(promise *pb.KeyPromise) error {
	userId := promise.SignedKeyTimestamp.UserId
	keyId := promise.SignedKeyTimestamp.SignedKey.KeyId
	// TODO: can etcd (and this client's use of HTTP) handle arbitrary bytes in keyId?
	etcdKey := strings.Join([]string{promisesDirectory, userId, keyId}, "/")
	etcdValue, err := proto.Marshal(promise)
	if err != nil {
		return err
	}
	_, err = s.client.Create(etcdKey, base64.StdEncoding.EncodeToString(etcdValue), 0)
	if err == nil {
		return nil
	} else {
		switch e := err.(type) {
		case *etcd.EtcdError:
			if e.ErrorCode == etcderr.EcodeNodeExist {
				return grpc.Errorf(codes.AlreadyExists, "Promise %s/%s already exists", userId, keyId)
			} else {
				return e
			}
		default:
			return err
		}
	}
}

// Lists the current promises for that user
func (s *EtcdConsistentStore) ListPromises(userId string) ([]*pb.KeyPromise, error) {
	etcdKey := strings.Join([]string{promisesDirectory, userId}, "/")
	response, err := s.client.Get(etcdKey, false, true)
	if err != nil {
		switch e := err.(type) {
		case *etcd.EtcdError:
			if e.ErrorCode == etcderr.EcodeKeyNotFound {
				// No promises yet for the user
				return []*pb.KeyPromise{}, nil
			} else {
				return nil, err
			}
		default:
			return nil, err
		}
	}
	promises := []*pb.KeyPromise{}
	for _, node := range response.Node.Nodes {
		marshaled, err := base64.StdEncoding.DecodeString(node.Value)
		promise := new(pb.KeyPromise)
		err = proto.Unmarshal(marshaled, promise)
		if err != nil {
			return nil, err
		}
		promises = append(promises, promise)
	}
	return promises, nil
}
