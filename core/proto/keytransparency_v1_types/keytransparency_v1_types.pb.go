// Code generated by protoc-gen-go. DO NOT EDIT.
// source: keytransparency_v1_types.proto

/*
Package keytransparency_v1_types is a generated protocol buffer package.

Key Transparency Service

The Key Transparency Service API consists of a map of user names to public
keys. Each user name also has a history of public keys that have been
associated with it.

It is generated from these files:
	keytransparency_v1_types.proto

It has these top-level messages:
	Committed
	EntryUpdate
	Entry
	MutationProof
	MapperMetadata
	GetEntryRequest
	GetEntryResponse
	ListEntryHistoryRequest
	ListEntryHistoryResponse
	UpdateEntryRequest
	UpdateEntryResponse
	GetMutationsRequest
	GetMutationsResponse
	GetDomainInfoRequest
	GetDomainInfoResponse
	UserProfile
	BatchUpdateEntriesRequest
	BatchUpdateEntriesResponse
	GetEpochsRequest
	GetEpochsResponse
*/
package keytransparency_v1_types

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import keyspb "github.com/google/trillian/crypto/keyspb"
import sigpb "github.com/google/trillian/crypto/sigpb"
import trillian "github.com/google/trillian"
import trillian1 "github.com/google/trillian"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Committed represents the data committed to in a cryptographic commitment.
// commitment = HMAC_SHA512_256(key, data)
type Committed struct {
	// key is the 16 byte random commitment key.
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// data is the data being committed to.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Committed) Reset()                    { *m = Committed{} }
func (m *Committed) String() string            { return proto.CompactTextString(m) }
func (*Committed) ProtoMessage()               {}
func (*Committed) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Committed) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *Committed) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

// EntryUpdate contains the user entry update(s).
type EntryUpdate struct {
	// mutation authorizes the change to entry.
	Mutation *Entry `protobuf:"bytes,2,opt,name=mutation" json:"mutation,omitempty"`
	// commitment contains the data committed to in update.commitment.
	Committed *Committed `protobuf:"bytes,3,opt,name=committed" json:"committed,omitempty"`
}

func (m *EntryUpdate) Reset()                    { *m = EntryUpdate{} }
func (m *EntryUpdate) String() string            { return proto.CompactTextString(m) }
func (*EntryUpdate) ProtoMessage()               {}
func (*EntryUpdate) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *EntryUpdate) GetMutation() *Entry {
	if m != nil {
		return m.Mutation
	}
	return nil
}

func (m *EntryUpdate) GetCommitted() *Committed {
	if m != nil {
		return m.Committed
	}
	return nil
}

// Entry is a signed change to a map entry.
// Entry contains a commitment to profile and a set of authorized update keys.
// Entry is placed in the verifiable map as leaf data.
type Entry struct {
	// index is the location of this leaf in the sparse merkle tree.
	Index []byte `protobuf:"bytes,3,opt,name=index,proto3" json:"index,omitempty"`
	// commitment is a cryptographic commitment to arbitrary data.
	Commitment []byte `protobuf:"bytes,6,opt,name=commitment,proto3" json:"commitment,omitempty"`
	// authorized_keys is the set of keys allowed to sign updates for this entry.
	AuthorizedKeys []*keyspb.PublicKey `protobuf:"bytes,7,rep,name=authorized_keys,json=authorizedKeys" json:"authorized_keys,omitempty"`
	// previous contains the hash of the previous entry that this mutation is
	// modifying creating a hash chain of all mutations. The hash used is
	// CommonJSON in "github.com/benlaurie/objecthash/go/objecthash".
	Previous []byte `protobuf:"bytes,8,opt,name=previous,proto3" json:"previous,omitempty"`
	// signatures on key_value. Must be signed by keys from both previous and
	// current epochs. The first proves ownership of new epoch key, and the
	// second proves that the correct owner is making this change.
	Signatures map[string]*sigpb.DigitallySigned `protobuf:"bytes,2,rep,name=signatures" json:"signatures,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *Entry) Reset()                    { *m = Entry{} }
func (m *Entry) String() string            { return proto.CompactTextString(m) }
func (*Entry) ProtoMessage()               {}
func (*Entry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Entry) GetIndex() []byte {
	if m != nil {
		return m.Index
	}
	return nil
}

func (m *Entry) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

func (m *Entry) GetAuthorizedKeys() []*keyspb.PublicKey {
	if m != nil {
		return m.AuthorizedKeys
	}
	return nil
}

func (m *Entry) GetPrevious() []byte {
	if m != nil {
		return m.Previous
	}
	return nil
}

func (m *Entry) GetSignatures() map[string]*sigpb.DigitallySigned {
	if m != nil {
		return m.Signatures
	}
	return nil
}

// MutationProof contains the information necessary to compute the new leaf value.
// It contains a) the old leaf value with it's inclusion proof and b) the mutation.
// The new leaf value is computed via:
//       Mutate(leaf_value, mutation)
type MutationProof struct {
	// mutation contains the information needed to modify the old leaf.
	// The format of a mutation is specific to the particular Mutate function being used.
	Mutation *Entry `protobuf:"bytes,1,opt,name=mutation" json:"mutation,omitempty"`
	// leaf_proof contains the leaf and its inclusion proof for a particular map revision.
	LeafProof *trillian1.MapLeafInclusion `protobuf:"bytes,2,opt,name=leaf_proof,json=leafProof" json:"leaf_proof,omitempty"`
}

func (m *MutationProof) Reset()                    { *m = MutationProof{} }
func (m *MutationProof) String() string            { return proto.CompactTextString(m) }
func (*MutationProof) ProtoMessage()               {}
func (*MutationProof) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *MutationProof) GetMutation() *Entry {
	if m != nil {
		return m.Mutation
	}
	return nil
}

func (m *MutationProof) GetLeafProof() *trillian1.MapLeafInclusion {
	if m != nil {
		return m.LeafProof
	}
	return nil
}

// MapperMetadata tracks the mutations that have been mapped so far. It is
// embedded in the Trillian SignedMapHead.
type MapperMetadata struct {
	HighestFullyCompletedSeq int64 `protobuf:"varint,1,opt,name=highest_fully_completed_seq,json=highestFullyCompletedSeq" json:"highest_fully_completed_seq,omitempty"`
}

func (m *MapperMetadata) Reset()                    { *m = MapperMetadata{} }
func (m *MapperMetadata) String() string            { return proto.CompactTextString(m) }
func (*MapperMetadata) ProtoMessage()               {}
func (*MapperMetadata) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *MapperMetadata) GetHighestFullyCompletedSeq() int64 {
	if m != nil {
		return m.HighestFullyCompletedSeq
	}
	return 0
}

// GetEntryRequest for a user object.
type GetEntryRequest struct {
	// user_id is the user identifier. Most commonly an email address.
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty"`
	// app_id is the identifier for the application.
	AppId string `protobuf:"bytes,2,opt,name=app_id,json=appId" json:"app_id,omitempty"`
	// first_tree_size is the tree_size of the currently trusted log root.
	// Omitting this field will omit the log consistency proof from the response.
	FirstTreeSize int64 `protobuf:"varint,3,opt,name=first_tree_size,json=firstTreeSize" json:"first_tree_size,omitempty"`
}

func (m *GetEntryRequest) Reset()                    { *m = GetEntryRequest{} }
func (m *GetEntryRequest) String() string            { return proto.CompactTextString(m) }
func (*GetEntryRequest) ProtoMessage()               {}
func (*GetEntryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *GetEntryRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *GetEntryRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

func (m *GetEntryRequest) GetFirstTreeSize() int64 {
	if m != nil {
		return m.FirstTreeSize
	}
	return 0
}

// GetEntryResponse returns a requested user entry.
type GetEntryResponse struct {
	// vrf_proof is the proof for VRF on user_id.
	VrfProof []byte `protobuf:"bytes,1,opt,name=vrf_proof,json=vrfProof,proto3" json:"vrf_proof,omitempty"`
	// committed contains the profile for this account and connects the data
	// in profile to the commitment in leaf_proof.
	Committed *Committed `protobuf:"bytes,2,opt,name=committed" json:"committed,omitempty"`
	// leaf_proof contains an Entry and an inclusion proof in the sparse Merkle
	// Tree.
	LeafProof *trillian1.MapLeafInclusion `protobuf:"bytes,3,opt,name=leaf_proof,json=leafProof" json:"leaf_proof,omitempty"`
	// smr contains the signed map head for the sparse Merkle Tree.
	// smr is also stored in the append only log.
	Smr *trillian.SignedMapRoot `protobuf:"bytes,4,opt,name=smr" json:"smr,omitempty"`
	// log_root is the latest globally consistent log root.
	// TODO: gossip the log root to verify global consistency.
	LogRoot *trillian.SignedLogRoot `protobuf:"bytes,5,opt,name=log_root,json=logRoot" json:"log_root,omitempty"`
	// log_consistency proves that log_root is consistent with previously seen roots.
	LogConsistency [][]byte `protobuf:"bytes,6,rep,name=log_consistency,json=logConsistency,proto3" json:"log_consistency,omitempty"`
	// log_inclusion proves that smr is part of log_root at index=srm.MapRevision.
	LogInclusion [][]byte `protobuf:"bytes,7,rep,name=log_inclusion,json=logInclusion,proto3" json:"log_inclusion,omitempty"`
}

func (m *GetEntryResponse) Reset()                    { *m = GetEntryResponse{} }
func (m *GetEntryResponse) String() string            { return proto.CompactTextString(m) }
func (*GetEntryResponse) ProtoMessage()               {}
func (*GetEntryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *GetEntryResponse) GetVrfProof() []byte {
	if m != nil {
		return m.VrfProof
	}
	return nil
}

func (m *GetEntryResponse) GetCommitted() *Committed {
	if m != nil {
		return m.Committed
	}
	return nil
}

func (m *GetEntryResponse) GetLeafProof() *trillian1.MapLeafInclusion {
	if m != nil {
		return m.LeafProof
	}
	return nil
}

func (m *GetEntryResponse) GetSmr() *trillian.SignedMapRoot {
	if m != nil {
		return m.Smr
	}
	return nil
}

func (m *GetEntryResponse) GetLogRoot() *trillian.SignedLogRoot {
	if m != nil {
		return m.LogRoot
	}
	return nil
}

func (m *GetEntryResponse) GetLogConsistency() [][]byte {
	if m != nil {
		return m.LogConsistency
	}
	return nil
}

func (m *GetEntryResponse) GetLogInclusion() [][]byte {
	if m != nil {
		return m.LogInclusion
	}
	return nil
}

// ListEntryHistoryRequest gets a list of historical keys for a user.
type ListEntryHistoryRequest struct {
	// user_id is the user identifier.
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty"`
	// start is the starting epoch.
	Start int64 `protobuf:"varint,2,opt,name=start" json:"start,omitempty"`
	// page_size is the maximum number of entries to return.
	PageSize int32 `protobuf:"varint,3,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
	// app_id is the identifier for the application.
	AppId string `protobuf:"bytes,4,opt,name=app_id,json=appId" json:"app_id,omitempty"`
	// first_tree_size is the tree_size of the currently trusted log root.
	// Omitting this field will omit the log consistency proof from the response.
	FirstTreeSize int64 `protobuf:"varint,5,opt,name=first_tree_size,json=firstTreeSize" json:"first_tree_size,omitempty"`
}

func (m *ListEntryHistoryRequest) Reset()                    { *m = ListEntryHistoryRequest{} }
func (m *ListEntryHistoryRequest) String() string            { return proto.CompactTextString(m) }
func (*ListEntryHistoryRequest) ProtoMessage()               {}
func (*ListEntryHistoryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *ListEntryHistoryRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *ListEntryHistoryRequest) GetStart() int64 {
	if m != nil {
		return m.Start
	}
	return 0
}

func (m *ListEntryHistoryRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListEntryHistoryRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

func (m *ListEntryHistoryRequest) GetFirstTreeSize() int64 {
	if m != nil {
		return m.FirstTreeSize
	}
	return 0
}

// ListEntryHistoryResponse requests a paginated history of keys for a user.
type ListEntryHistoryResponse struct {
	// values represents the list of keys this user_id has contained over time.
	Values []*GetEntryResponse `protobuf:"bytes,1,rep,name=values" json:"values,omitempty"`
	// next_start is the next page token to query for pagination.
	// next_start is 0 when there are no more results to fetch.
	NextStart int64 `protobuf:"varint,2,opt,name=next_start,json=nextStart" json:"next_start,omitempty"`
}

func (m *ListEntryHistoryResponse) Reset()                    { *m = ListEntryHistoryResponse{} }
func (m *ListEntryHistoryResponse) String() string            { return proto.CompactTextString(m) }
func (*ListEntryHistoryResponse) ProtoMessage()               {}
func (*ListEntryHistoryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *ListEntryHistoryResponse) GetValues() []*GetEntryResponse {
	if m != nil {
		return m.Values
	}
	return nil
}

func (m *ListEntryHistoryResponse) GetNextStart() int64 {
	if m != nil {
		return m.NextStart
	}
	return 0
}

// UpdateEntryRequest updates a user's profile.
type UpdateEntryRequest struct {
	// user_id specifies the id for the user who's profile is being updated.
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty"`
	// app_id is the identifier for the application.
	AppId string `protobuf:"bytes,2,opt,name=app_id,json=appId" json:"app_id,omitempty"`
	// first_tree_size is the tree_size of the currently trusted log root.
	// Omitting this field will omit the log consistency proof from the response.
	FirstTreeSize int64 `protobuf:"varint,3,opt,name=first_tree_size,json=firstTreeSize" json:"first_tree_size,omitempty"`
	// entry_update contains the user submitted update.
	EntryUpdate *EntryUpdate `protobuf:"bytes,4,opt,name=entry_update,json=entryUpdate" json:"entry_update,omitempty"`
}

func (m *UpdateEntryRequest) Reset()                    { *m = UpdateEntryRequest{} }
func (m *UpdateEntryRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateEntryRequest) ProtoMessage()               {}
func (*UpdateEntryRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *UpdateEntryRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *UpdateEntryRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

func (m *UpdateEntryRequest) GetFirstTreeSize() int64 {
	if m != nil {
		return m.FirstTreeSize
	}
	return 0
}

func (m *UpdateEntryRequest) GetEntryUpdate() *EntryUpdate {
	if m != nil {
		return m.EntryUpdate
	}
	return nil
}

// UpdateEntryResponse contains a proof once the update has been included in
// the Merkle Tree.
type UpdateEntryResponse struct {
	// proof contains a proof that the update has been included in the tree.
	Proof *GetEntryResponse `protobuf:"bytes,1,opt,name=proof" json:"proof,omitempty"`
}

func (m *UpdateEntryResponse) Reset()                    { *m = UpdateEntryResponse{} }
func (m *UpdateEntryResponse) String() string            { return proto.CompactTextString(m) }
func (*UpdateEntryResponse) ProtoMessage()               {}
func (*UpdateEntryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *UpdateEntryResponse) GetProof() *GetEntryResponse {
	if m != nil {
		return m.Proof
	}
	return nil
}

// GetMutationsRequest contains the input parameters of the GetMutation APIs.
type GetMutationsRequest struct {
	// epoch specifies the epoch number in which mutations will be returned.
	Epoch int64 `protobuf:"varint,1,opt,name=epoch" json:"epoch,omitempty"`
	// first_tree_size is the tree_size of the currently trusted log root.
	// Omitting this field will omit the log consistency proof from the response.
	FirstTreeSize int64 `protobuf:"varint,2,opt,name=first_tree_size,json=firstTreeSize" json:"first_tree_size,omitempty"`
	// page_token defines the starting point for pagination. An empty
	// value means start from the beginning. A non-empty value requests the next
	// page of values.
	PageToken string `protobuf:"bytes,3,opt,name=page_token,json=pageToken" json:"page_token,omitempty"`
	// page_size is the maximum number of epochs to return.
	PageSize int32 `protobuf:"varint,4,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
}

func (m *GetMutationsRequest) Reset()                    { *m = GetMutationsRequest{} }
func (m *GetMutationsRequest) String() string            { return proto.CompactTextString(m) }
func (*GetMutationsRequest) ProtoMessage()               {}
func (*GetMutationsRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *GetMutationsRequest) GetEpoch() int64 {
	if m != nil {
		return m.Epoch
	}
	return 0
}

func (m *GetMutationsRequest) GetFirstTreeSize() int64 {
	if m != nil {
		return m.FirstTreeSize
	}
	return 0
}

func (m *GetMutationsRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

func (m *GetMutationsRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

// GetMutationsResponse contains the results of GetMutation APIs.
type GetMutationsResponse struct {
	// epoch specifies the epoch number of the returned mutations.
	Epoch int64 `protobuf:"varint,1,opt,name=epoch" json:"epoch,omitempty"`
	// smr contains the signed map root for the sparse Merkle Tree.
	Smr *trillian.SignedMapRoot `protobuf:"bytes,2,opt,name=smr" json:"smr,omitempty"`
	// log_root is the latest globally consistent log root.
	LogRoot *trillian.SignedLogRoot `protobuf:"bytes,3,opt,name=log_root,json=logRoot" json:"log_root,omitempty"`
	// log_consistency proves that log_root is consistent with previously seen roots.
	LogConsistency [][]byte `protobuf:"bytes,4,rep,name=log_consistency,json=logConsistency,proto3" json:"log_consistency,omitempty"`
	// log_inclusion proves that smr is part of log_root at index=srm.MapRevision.
	LogInclusion [][]byte `protobuf:"bytes,5,rep,name=log_inclusion,json=logInclusion,proto3" json:"log_inclusion,omitempty"`
	// mutation contains mutation information.
	Mutations []*MutationProof `protobuf:"bytes,6,rep,name=mutations" json:"mutations,omitempty"`
	// next_page_token is the next page token to query for pagination.
	// An empty value means there are no more results to fetch.
	// A non-zero value may be used by the client to fetch the next page of
	// results.
	NextPageToken string `protobuf:"bytes,7,opt,name=next_page_token,json=nextPageToken" json:"next_page_token,omitempty"`
}

func (m *GetMutationsResponse) Reset()                    { *m = GetMutationsResponse{} }
func (m *GetMutationsResponse) String() string            { return proto.CompactTextString(m) }
func (*GetMutationsResponse) ProtoMessage()               {}
func (*GetMutationsResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *GetMutationsResponse) GetEpoch() int64 {
	if m != nil {
		return m.Epoch
	}
	return 0
}

func (m *GetMutationsResponse) GetSmr() *trillian.SignedMapRoot {
	if m != nil {
		return m.Smr
	}
	return nil
}

func (m *GetMutationsResponse) GetLogRoot() *trillian.SignedLogRoot {
	if m != nil {
		return m.LogRoot
	}
	return nil
}

func (m *GetMutationsResponse) GetLogConsistency() [][]byte {
	if m != nil {
		return m.LogConsistency
	}
	return nil
}

func (m *GetMutationsResponse) GetLogInclusion() [][]byte {
	if m != nil {
		return m.LogInclusion
	}
	return nil
}

func (m *GetMutationsResponse) GetMutations() []*MutationProof {
	if m != nil {
		return m.Mutations
	}
	return nil
}

func (m *GetMutationsResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

// GetDomainInfoRequest contains an empty request to query the GetDomainInfo
// APIs.
type GetDomainInfoRequest struct {
}

func (m *GetDomainInfoRequest) Reset()                    { *m = GetDomainInfoRequest{} }
func (m *GetDomainInfoRequest) String() string            { return proto.CompactTextString(m) }
func (*GetDomainInfoRequest) ProtoMessage()               {}
func (*GetDomainInfoRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

// GetDomainInfoResponse contains the results of GetDomainInfo APIs.
type GetDomainInfoResponse struct {
	// Log contains the Log-Tree's info.
	Log *trillian.Tree `protobuf:"bytes,1,opt,name=log" json:"log,omitempty"`
	// Map contains the Map-Tree's info.
	Map *trillian.Tree `protobuf:"bytes,2,opt,name=map" json:"map,omitempty"`
	// Vrf contains the VRF public key.
	Vrf *keyspb.PublicKey `protobuf:"bytes,3,opt,name=vrf" json:"vrf,omitempty"`
}

func (m *GetDomainInfoResponse) Reset()                    { *m = GetDomainInfoResponse{} }
func (m *GetDomainInfoResponse) String() string            { return proto.CompactTextString(m) }
func (*GetDomainInfoResponse) ProtoMessage()               {}
func (*GetDomainInfoResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func (m *GetDomainInfoResponse) GetLog() *trillian.Tree {
	if m != nil {
		return m.Log
	}
	return nil
}

func (m *GetDomainInfoResponse) GetMap() *trillian.Tree {
	if m != nil {
		return m.Map
	}
	return nil
}

func (m *GetDomainInfoResponse) GetVrf() *keyspb.PublicKey {
	if m != nil {
		return m.Vrf
	}
	return nil
}

// UserProfile is the data that a client would like to store on the server.
type UserProfile struct {
	// data is the public key data for the user.
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *UserProfile) Reset()                    { *m = UserProfile{} }
func (m *UserProfile) String() string            { return proto.CompactTextString(m) }
func (*UserProfile) ProtoMessage()               {}
func (*UserProfile) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{15} }

func (m *UserProfile) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

// SetEntriesRequest will update the accounts of the given user_ids to be set to
// user data if those accounts have key_id in their set of authorized_keys.
type BatchUpdateEntriesRequest struct {
	// users is a map from user_ids to user data.
	Users map[string]*UserProfile `protobuf:"bytes,1,rep,name=users" json:"users,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	// app_id is the application to make this change for.
	AppId string `protobuf:"bytes,2,opt,name=app_id,json=appId" json:"app_id,omitempty"`
	// key_id is the id of the authorized_public key to use when updating accounts.
	// This must be a key that this server has the private key for.
	KeyId string `protobuf:"bytes,3,opt,name=key_id,json=keyId" json:"key_id,omitempty"`
}

func (m *BatchUpdateEntriesRequest) Reset()                    { *m = BatchUpdateEntriesRequest{} }
func (m *BatchUpdateEntriesRequest) String() string            { return proto.CompactTextString(m) }
func (*BatchUpdateEntriesRequest) ProtoMessage()               {}
func (*BatchUpdateEntriesRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{16} }

func (m *BatchUpdateEntriesRequest) GetUsers() map[string]*UserProfile {
	if m != nil {
		return m.Users
	}
	return nil
}

func (m *BatchUpdateEntriesRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

func (m *BatchUpdateEntriesRequest) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

// BatchUpdateEntriesResponse returns a list of users for which the set operation
// was unsuccessful.
type BatchUpdateEntriesResponse struct {
	// errors is a map from user_ids to errors, if there was an error for that user.
	Errors map[string]string `protobuf:"bytes,1,rep,name=errors" json:"errors,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *BatchUpdateEntriesResponse) Reset()                    { *m = BatchUpdateEntriesResponse{} }
func (m *BatchUpdateEntriesResponse) String() string            { return proto.CompactTextString(m) }
func (*BatchUpdateEntriesResponse) ProtoMessage()               {}
func (*BatchUpdateEntriesResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{17} }

func (m *BatchUpdateEntriesResponse) GetErrors() map[string]string {
	if m != nil {
		return m.Errors
	}
	return nil
}

// GetEpochsRequest is an empty proto message used as input to GetEpochs API.
type GetEpochsRequest struct {
}

func (m *GetEpochsRequest) Reset()                    { *m = GetEpochsRequest{} }
func (m *GetEpochsRequest) String() string            { return proto.CompactTextString(m) }
func (*GetEpochsRequest) ProtoMessage()               {}
func (*GetEpochsRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{18} }

// GetEpochsResponse contains mutations of a newly created epoch.
type GetEpochsResponse struct {
	// mutations contains all mutations information of a newly created epoch.
	Mutations *GetMutationsResponse `protobuf:"bytes,1,opt,name=mutations" json:"mutations,omitempty"`
}

func (m *GetEpochsResponse) Reset()                    { *m = GetEpochsResponse{} }
func (m *GetEpochsResponse) String() string            { return proto.CompactTextString(m) }
func (*GetEpochsResponse) ProtoMessage()               {}
func (*GetEpochsResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{19} }

func (m *GetEpochsResponse) GetMutations() *GetMutationsResponse {
	if m != nil {
		return m.Mutations
	}
	return nil
}

func init() {
	proto.RegisterType((*Committed)(nil), "keytransparency.v1.types.Committed")
	proto.RegisterType((*EntryUpdate)(nil), "keytransparency.v1.types.EntryUpdate")
	proto.RegisterType((*Entry)(nil), "keytransparency.v1.types.Entry")
	proto.RegisterType((*MutationProof)(nil), "keytransparency.v1.types.MutationProof")
	proto.RegisterType((*MapperMetadata)(nil), "keytransparency.v1.types.MapperMetadata")
	proto.RegisterType((*GetEntryRequest)(nil), "keytransparency.v1.types.GetEntryRequest")
	proto.RegisterType((*GetEntryResponse)(nil), "keytransparency.v1.types.GetEntryResponse")
	proto.RegisterType((*ListEntryHistoryRequest)(nil), "keytransparency.v1.types.ListEntryHistoryRequest")
	proto.RegisterType((*ListEntryHistoryResponse)(nil), "keytransparency.v1.types.ListEntryHistoryResponse")
	proto.RegisterType((*UpdateEntryRequest)(nil), "keytransparency.v1.types.UpdateEntryRequest")
	proto.RegisterType((*UpdateEntryResponse)(nil), "keytransparency.v1.types.UpdateEntryResponse")
	proto.RegisterType((*GetMutationsRequest)(nil), "keytransparency.v1.types.GetMutationsRequest")
	proto.RegisterType((*GetMutationsResponse)(nil), "keytransparency.v1.types.GetMutationsResponse")
	proto.RegisterType((*GetDomainInfoRequest)(nil), "keytransparency.v1.types.GetDomainInfoRequest")
	proto.RegisterType((*GetDomainInfoResponse)(nil), "keytransparency.v1.types.GetDomainInfoResponse")
	proto.RegisterType((*UserProfile)(nil), "keytransparency.v1.types.UserProfile")
	proto.RegisterType((*BatchUpdateEntriesRequest)(nil), "keytransparency.v1.types.BatchUpdateEntriesRequest")
	proto.RegisterType((*BatchUpdateEntriesResponse)(nil), "keytransparency.v1.types.BatchUpdateEntriesResponse")
	proto.RegisterType((*GetEpochsRequest)(nil), "keytransparency.v1.types.GetEpochsRequest")
	proto.RegisterType((*GetEpochsResponse)(nil), "keytransparency.v1.types.GetEpochsResponse")
}

func init() { proto.RegisterFile("keytransparency_v1_types.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 1154 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x56, 0xdd, 0x6e, 0x13, 0x47,
	0x14, 0xd6, 0xda, 0x59, 0x27, 0x3e, 0xce, 0x0f, 0x0c, 0x01, 0xb6, 0x46, 0xd0, 0x74, 0x51, 0x0b,
	0xad, 0x2a, 0x23, 0xd2, 0x9b, 0x02, 0x6a, 0x45, 0xf9, 0x29, 0x44, 0x24, 0x22, 0xda, 0x80, 0xda,
	0xbb, 0xd5, 0xc4, 0x3e, 0x76, 0x46, 0x59, 0xef, 0x0c, 0x33, 0x63, 0x8b, 0x45, 0xaa, 0xc4, 0x5d,
	0xaf, 0xaa, 0xbe, 0x44, 0x5f, 0xa0, 0x37, 0xbd, 0xeb, 0x7d, 0x9f, 0xa1, 0x4f, 0x53, 0xcd, 0xcf,
	0xda, 0xeb, 0xc4, 0x06, 0xc2, 0x45, 0x6f, 0x12, 0xcf, 0xf9, 0x9b, 0x73, 0xbe, 0xf3, 0x9d, 0xb3,
	0x03, 0xd7, 0x8e, 0xb1, 0xd0, 0x92, 0xe6, 0x4a, 0x50, 0x89, 0x79, 0xb7, 0x48, 0xc7, 0xb7, 0x53,
	0x5d, 0x08, 0x54, 0x1d, 0x21, 0xb9, 0xe6, 0x24, 0x3a, 0xa1, 0xef, 0x8c, 0x6f, 0x77, 0xac, 0xbe,
	0xdd, 0xee, 0xca, 0x42, 0x68, 0x7e, 0xeb, 0x18, 0x0b, 0x25, 0x0e, 0xfd, 0x3f, 0xe7, 0xd5, 0x8e,
	0xbc, 0x4e, 0xb1, 0x81, 0x38, 0x74, 0x7f, 0xbd, 0x66, 0x5d, 0x4b, 0x96, 0x65, 0x8c, 0xe6, 0xfe,
	0x7c, 0xa9, 0x3c, 0xa7, 0x43, 0x2a, 0x52, 0x2a, 0x98, 0x93, 0xc7, 0xb7, 0xa1, 0xf9, 0x90, 0x0f,
	0x87, 0x4c, 0x6b, 0xec, 0x91, 0x73, 0x50, 0x3f, 0xc6, 0x22, 0x0a, 0xb6, 0x82, 0x9b, 0xab, 0x89,
	0xf9, 0x49, 0x08, 0x2c, 0xf5, 0xa8, 0xa6, 0x51, 0xcd, 0x8a, 0xec, 0xef, 0xf8, 0xb7, 0x00, 0x5a,
	0x8f, 0x73, 0x2d, 0x8b, 0x97, 0xa2, 0x47, 0x35, 0x92, 0x7b, 0xb0, 0x32, 0x1c, 0x69, 0xaa, 0x19,
	0xcf, 0xad, 0x5d, 0x6b, 0xfb, 0xd3, 0xce, 0xa2, 0x6a, 0x3a, 0xd6, 0x31, 0x99, 0x38, 0x90, 0x1f,
	0xa0, 0xd9, 0x2d, 0xef, 0x8f, 0xea, 0xd6, 0xfb, 0xfa, 0x62, 0xef, 0x49, 0xaa, 0xc9, 0xd4, 0x2b,
	0xfe, 0xbb, 0x06, 0xa1, 0x0d, 0x4b, 0x36, 0x21, 0x64, 0x79, 0x0f, 0x5f, 0xdb, 0x40, 0xab, 0x89,
	0x3b, 0x90, 0x6b, 0x00, 0xce, 0x78, 0x88, 0xb9, 0x8e, 0x1a, 0x56, 0x55, 0x91, 0x90, 0xbb, 0xb0,
	0x41, 0x47, 0xfa, 0x88, 0x4b, 0xf6, 0x06, 0x7b, 0xa9, 0xc1, 0x37, 0x5a, 0xde, 0xaa, 0xdf, 0x6c,
	0x6d, 0x9f, 0xef, 0x78, 0xb0, 0xf7, 0x47, 0x87, 0x19, 0xeb, 0x3e, 0xc3, 0x22, 0x59, 0x9f, 0x5a,
	0x3e, 0xc3, 0x42, 0x91, 0x36, 0xac, 0x08, 0x89, 0x63, 0xc6, 0x47, 0x2a, 0x5a, 0xb1, 0x91, 0x27,
	0x67, 0xf2, 0x1c, 0x40, 0xb1, 0x41, 0x4e, 0xf5, 0x48, 0xa2, 0x8a, 0x6a, 0x36, 0xe4, 0xad, 0xf7,
	0x20, 0xd3, 0x39, 0x98, 0x78, 0x38, 0xa4, 0x2a, 0x21, 0xda, 0x2f, 0x61, 0xe3, 0x84, 0xba, 0xda,
	0xb1, 0xa6, 0xeb, 0xd8, 0xd7, 0x10, 0x8e, 0x69, 0x36, 0x42, 0xdf, 0x8a, 0x4b, 0x1d, 0xc7, 0x8a,
	0x47, 0x6c, 0xc0, 0x34, 0xcd, 0xb2, 0xc2, 0x44, 0xc0, 0x5e, 0xe2, 0x8c, 0xee, 0xd6, 0xbe, 0x0d,
	0xe2, 0x5f, 0x03, 0x58, 0xdb, 0xf3, 0xfd, 0xd8, 0x97, 0x9c, 0xf7, 0x67, 0x3a, 0x1a, 0x9c, 0xb5,
	0xa3, 0x77, 0x00, 0x32, 0xa4, 0xfd, 0x54, 0x98, 0x50, 0x3e, 0x8b, 0x76, 0x67, 0x42, 0xc7, 0x3d,
	0x2a, 0x76, 0x91, 0xf6, 0x77, 0xf2, 0x6e, 0x36, 0x52, 0x8c, 0xe7, 0x49, 0xd3, 0x58, 0xdb, 0x7b,
	0xe3, 0xe7, 0xb0, 0xbe, 0x47, 0x85, 0x40, 0xb9, 0x87, 0x9a, 0x1a, 0xae, 0x91, 0xef, 0xe0, 0xca,
	0x11, 0x1b, 0x1c, 0xa1, 0xd2, 0x69, 0x7f, 0x94, 0x65, 0x45, 0xda, 0xe5, 0x43, 0x91, 0xa1, 0xc6,
	0x5e, 0xaa, 0xf0, 0x95, 0x4d, 0xae, 0x9e, 0x44, 0xde, 0xe4, 0x47, 0x63, 0xf1, 0xb0, 0x34, 0x38,
	0xc0, 0x57, 0x31, 0x83, 0x8d, 0x27, 0xa8, 0x5d, 0x86, 0xf8, 0x6a, 0x84, 0x4a, 0x93, 0xcb, 0xb0,
	0x3c, 0x52, 0x28, 0x53, 0xd6, 0xf3, 0xa8, 0x35, 0xcc, 0x71, 0xa7, 0x47, 0x2e, 0x42, 0x83, 0x0a,
	0x61, 0xe4, 0x35, 0x2b, 0x0f, 0xa9, 0x10, 0x3b, 0x3d, 0xf2, 0x05, 0x6c, 0xf4, 0x99, 0x54, 0x3a,
	0xd5, 0x12, 0x31, 0x55, 0xec, 0x0d, 0x5a, 0x76, 0xd5, 0x93, 0x35, 0x2b, 0x7e, 0x21, 0x11, 0x0f,
	0xd8, 0x1b, 0x8c, 0xff, 0xad, 0xc1, 0xb9, 0xe9, 0x5d, 0x4a, 0xf0, 0x5c, 0x21, 0xb9, 0x02, 0xcd,
	0xb1, 0x2c, 0xa1, 0x70, 0x63, 0xb5, 0x32, 0x96, 0xae, 0xda, 0x59, 0xea, 0xd7, 0x3e, 0x86, 0xfa,
	0x27, 0xb0, 0xae, 0x9f, 0x01, 0x6b, 0xf2, 0x25, 0xd4, 0xd5, 0x50, 0x46, 0x4b, 0xd6, 0xe7, 0xf2,
	0xd4, 0xc7, 0xf1, 0x63, 0x8f, 0x8a, 0x84, 0x73, 0x9d, 0x18, 0x1b, 0xb2, 0x0d, 0x2b, 0x19, 0x1f,
	0xa4, 0x92, 0x73, 0x1d, 0x85, 0xf3, 0xed, 0x77, 0xf9, 0xc0, 0xda, 0x2f, 0x67, 0xee, 0x07, 0xb9,
	0x01, 0x1b, 0xc6, 0xa7, 0xcb, 0x73, 0xc5, 0x94, 0x36, 0xa5, 0x44, 0x8d, 0xad, 0xfa, 0xcd, 0xd5,
	0x64, 0x3d, 0xe3, 0x83, 0x87, 0x53, 0x29, 0xb9, 0x0e, 0x6b, 0xc6, 0x90, 0x95, 0x39, 0xda, 0xd9,
	0x5b, 0x4d, 0x56, 0x33, 0x3e, 0x98, 0xe4, 0x1d, 0xff, 0x11, 0xc0, 0xe5, 0x5d, 0xa6, 0x1c, 0xba,
	0x4f, 0x99, 0xd2, 0xfc, 0x03, 0x1a, 0xba, 0x09, 0xa1, 0xd2, 0x54, 0x6a, 0x8b, 0x6d, 0x3d, 0x71,
	0x07, 0xd3, 0x12, 0x41, 0x07, 0x95, 0x4e, 0x86, 0xc9, 0x8a, 0x11, 0x98, 0x26, 0x56, 0x38, 0xb0,
	0xf4, 0x1e, 0x0e, 0x84, 0xf3, 0x38, 0xf0, 0x0b, 0x44, 0xa7, 0xb3, 0xf4, 0x54, 0x78, 0x00, 0x0d,
	0x3b, 0x72, 0x2a, 0x0a, 0xec, 0x26, 0xf8, 0x6a, 0x71, 0xab, 0x4f, 0xd2, 0x28, 0xf1, 0x9e, 0xe4,
	0x2a, 0x40, 0x8e, 0xaf, 0x75, 0x5a, 0x2d, 0xab, 0x69, 0x24, 0x07, 0x46, 0x10, 0xff, 0x15, 0x00,
	0x71, 0x3b, 0xf9, 0xff, 0x60, 0x3c, 0x79, 0x0a, 0xab, 0x68, 0xee, 0x49, 0x47, 0xf6, 0x4e, 0x4f,
	0xa5, 0xcf, 0xdf, 0xb3, 0x29, 0x5c, 0x82, 0x49, 0x0b, 0xa7, 0x87, 0xf8, 0x27, 0xb8, 0x30, 0x93,
	0xb7, 0x87, 0xec, 0x3e, 0x84, 0xd3, 0xc9, 0x39, 0x1b, 0x62, 0xce, 0x31, 0xfe, 0x3d, 0x80, 0x0b,
	0x4f, 0x50, 0x97, 0xdb, 0x4d, 0x95, 0x90, 0x6c, 0x42, 0x88, 0x82, 0x77, 0x8f, 0xfc, 0x02, 0x71,
	0x87, 0x79, 0x85, 0xd7, 0xe6, 0x15, 0x7e, 0x15, 0xc0, 0x52, 0x48, 0xf3, 0x63, 0xcc, 0x2d, 0x36,
	0xcd, 0xc4, 0x92, 0xea, 0x85, 0x11, 0xcc, 0x32, 0x6c, 0x69, 0x96, 0x61, 0xf1, 0x3f, 0x35, 0xd8,
	0x9c, 0xcd, 0xc8, 0x17, 0x3b, 0x3f, 0x25, 0x3f, 0xa5, 0xb5, 0x33, 0x4e, 0x69, 0xfd, 0xe3, 0xa7,
	0x74, 0xe9, 0xc3, 0xa6, 0x34, 0x3c, 0x3d, 0xa5, 0xe4, 0x31, 0x34, 0xcb, 0xaf, 0x80, 0xb2, 0xd3,
	0xde, 0xda, 0xbe, 0xb1, 0xb8, 0x67, 0x33, 0x9f, 0x9c, 0x64, 0xea, 0x69, 0xda, 0x60, 0x59, 0x5e,
	0xc1, 0x78, 0xd9, 0x62, 0xbc, 0x66, 0xc4, 0xfb, 0x25, 0xce, 0xf1, 0x25, 0x8b, 0xe4, 0x23, 0x3e,
	0xa4, 0x2c, 0xdf, 0xc9, 0xfb, 0xdc, 0x37, 0x37, 0x7e, 0x1b, 0xc0, 0xc5, 0x13, 0x0a, 0x8f, 0xf1,
	0x16, 0xd4, 0x33, 0x3e, 0xf0, 0x74, 0x5a, 0x9f, 0xa2, 0x63, 0x3a, 0x9b, 0x18, 0x95, 0xb1, 0x18,
	0x52, 0xe1, 0xf1, 0x3e, 0x65, 0x31, 0xa4, 0x82, 0x5c, 0x87, 0xfa, 0x58, 0x96, 0xbb, 0x76, 0xce,
	0x0b, 0xc1, 0x68, 0xe3, 0xcf, 0xa0, 0xf5, 0x52, 0xa1, 0xdc, 0x97, 0xbc, 0xcf, 0x32, 0x9c, 0xbc,
	0xa2, 0x82, 0xca, 0x2b, 0xea, 0x6d, 0x0d, 0x3e, 0x79, 0x40, 0x75, 0xf7, 0x68, 0xca, 0x7c, 0x86,
	0x13, 0x82, 0xbe, 0x80, 0xd0, 0x0c, 0x69, 0xb9, 0x2c, 0xbe, 0x5f, 0x0c, 0xe3, 0xc2, 0x18, 0x1d,
	0x93, 0x81, 0x7f, 0x45, 0xb8, 0x60, 0x8b, 0x06, 0xfe, 0x22, 0x34, 0x8e, 0xb1, 0x30, 0x62, 0xc7,
	0xe5, 0xf0, 0x18, 0x8b, 0x9d, 0x5e, 0x3b, 0x05, 0x98, 0x86, 0x98, 0xf3, 0xd2, 0xb8, 0x37, 0xfb,
	0xd2, 0x78, 0xc7, 0xe0, 0x57, 0xb0, 0xa8, 0x3e, 0x3c, 0xfe, 0x0c, 0xa0, 0x3d, 0x2f, 0x7d, 0xdf,
	0xad, 0x9f, 0xa1, 0x81, 0x52, 0xf2, 0x09, 0x08, 0xf7, 0xcf, 0x06, 0x82, 0x8b, 0xd2, 0x79, 0x6c,
	0x43, 0x38, 0x18, 0x7c, 0xbc, 0xf6, 0x1d, 0x68, 0x55, 0xc4, 0x73, 0x4a, 0xdb, 0xac, 0x96, 0xd6,
	0xac, 0xe6, 0x4c, 0xdc, 0x57, 0xde, 0x0c, 0x67, 0x09, 0x74, 0x4c, 0xe1, 0x7c, 0x45, 0xe6, 0xb3,
	0xdf, 0xad, 0x0e, 0x83, 0x63, 0x5c, 0xe7, 0x9d, 0x0b, 0xec, 0xd4, 0x4a, 0xa8, 0xcc, 0xc4, 0x61,
	0xc3, 0xbe, 0xd6, 0xbf, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0xff, 0x24, 0x82, 0x82, 0x52, 0x47, 0x0c,
	0x00, 0x00,
}
