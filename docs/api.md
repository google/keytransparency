# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [v1/keytransparency.proto](#v1/keytransparency.proto)
    - [BatchGetUserIndexRequest](#google.keytransparency.v1.BatchGetUserIndexRequest)
    - [BatchGetUserIndexResponse](#google.keytransparency.v1.BatchGetUserIndexResponse)
    - [BatchGetUserIndexResponse.ProofsEntry](#google.keytransparency.v1.BatchGetUserIndexResponse.ProofsEntry)
    - [BatchGetUserRequest](#google.keytransparency.v1.BatchGetUserRequest)
    - [BatchGetUserResponse](#google.keytransparency.v1.BatchGetUserResponse)
    - [BatchGetUserResponse.MapLeavesByUserIdEntry](#google.keytransparency.v1.BatchGetUserResponse.MapLeavesByUserIdEntry)
    - [BatchListUserRevisionsRequest](#google.keytransparency.v1.BatchListUserRevisionsRequest)
    - [BatchListUserRevisionsResponse](#google.keytransparency.v1.BatchListUserRevisionsResponse)
    - [BatchMapRevision](#google.keytransparency.v1.BatchMapRevision)
    - [BatchMapRevision.MapLeavesByUserIdEntry](#google.keytransparency.v1.BatchMapRevision.MapLeavesByUserIdEntry)
    - [BatchQueueUserUpdateRequest](#google.keytransparency.v1.BatchQueueUserUpdateRequest)
    - [Committed](#google.keytransparency.v1.Committed)
    - [Entry](#google.keytransparency.v1.Entry)
    - [EntryUpdate](#google.keytransparency.v1.EntryUpdate)
    - [GetLatestRevisionRequest](#google.keytransparency.v1.GetLatestRevisionRequest)
    - [GetRevisionRequest](#google.keytransparency.v1.GetRevisionRequest)
    - [GetUserRequest](#google.keytransparency.v1.GetUserRequest)
    - [GetUserResponse](#google.keytransparency.v1.GetUserResponse)
    - [ListEntryHistoryRequest](#google.keytransparency.v1.ListEntryHistoryRequest)
    - [ListEntryHistoryResponse](#google.keytransparency.v1.ListEntryHistoryResponse)
    - [ListMutationsRequest](#google.keytransparency.v1.ListMutationsRequest)
    - [ListMutationsResponse](#google.keytransparency.v1.ListMutationsResponse)
    - [ListUserRevisionsRequest](#google.keytransparency.v1.ListUserRevisionsRequest)
    - [ListUserRevisionsResponse](#google.keytransparency.v1.ListUserRevisionsResponse)
    - [LogRoot](#google.keytransparency.v1.LogRoot)
    - [LogRootRequest](#google.keytransparency.v1.LogRootRequest)
    - [MapLeaf](#google.keytransparency.v1.MapLeaf)
    - [MapRevision](#google.keytransparency.v1.MapRevision)
    - [MapRoot](#google.keytransparency.v1.MapRoot)
    - [MapperMetadata](#google.keytransparency.v1.MapperMetadata)
    - [MutationProof](#google.keytransparency.v1.MutationProof)
    - [Revision](#google.keytransparency.v1.Revision)
    - [SignedEntry](#google.keytransparency.v1.SignedEntry)
    - [UpdateEntryRequest](#google.keytransparency.v1.UpdateEntryRequest)
  
    - [KeyTransparency](#google.keytransparency.v1.KeyTransparency)
  
- [v1/admin.proto](#v1/admin.proto)
    - [CreateDirectoryRequest](#google.keytransparency.v1.CreateDirectoryRequest)
    - [DeleteDirectoryRequest](#google.keytransparency.v1.DeleteDirectoryRequest)
    - [Directory](#google.keytransparency.v1.Directory)
    - [GarbageCollectRequest](#google.keytransparency.v1.GarbageCollectRequest)
    - [GarbageCollectResponse](#google.keytransparency.v1.GarbageCollectResponse)
    - [GetDirectoryRequest](#google.keytransparency.v1.GetDirectoryRequest)
    - [InputLog](#google.keytransparency.v1.InputLog)
    - [ListDirectoriesRequest](#google.keytransparency.v1.ListDirectoriesRequest)
    - [ListDirectoriesResponse](#google.keytransparency.v1.ListDirectoriesResponse)
    - [ListInputLogsRequest](#google.keytransparency.v1.ListInputLogsRequest)
    - [ListInputLogsResponse](#google.keytransparency.v1.ListInputLogsResponse)
    - [UndeleteDirectoryRequest](#google.keytransparency.v1.UndeleteDirectoryRequest)
  
    - [KeyTransparencyAdmin](#google.keytransparency.v1.KeyTransparencyAdmin)
  
- [v1/frontend.proto](#v1/frontend.proto)
    - [QueueKeyUpdateRequest](#google.keytransparency.v1.QueueKeyUpdateRequest)
  
    - [KeyTransparencyFrontend](#google.keytransparency.v1.KeyTransparencyFrontend)
  
- [Scalar Value Types](#scalar-value-types)



<a name="v1/keytransparency.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/keytransparency.proto



<a name="google.keytransparency.v1.BatchGetUserIndexRequest"></a>

### BatchGetUserIndexRequest
BatchGetUserIndexRequest identifies a set of users.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the users live. |
| user_ids | [string](#string) | repeated | user_ids are the user identifiers |






<a name="google.keytransparency.v1.BatchGetUserIndexResponse"></a>

### BatchGetUserIndexResponse
BatchGetUserIndexRequest identifies a single user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| proofs | [BatchGetUserIndexResponse.ProofsEntry](#google.keytransparency.v1.BatchGetUserIndexResponse.ProofsEntry) | repeated | proofs is a map from user_id to its VRF proof. Clients get the index by verifying the VRF proof. |






<a name="google.keytransparency.v1.BatchGetUserIndexResponse.ProofsEntry"></a>

### BatchGetUserIndexResponse.ProofsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |






<a name="google.keytransparency.v1.BatchGetUserRequest"></a>

### BatchGetUserRequest
BatchGetUserRequest contains multiple user_ids to fetch.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the users live. |
| user_ids | [string](#string) | repeated | user_ids are the user identifiers, the format for which is defined by the application. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.BatchGetUserResponse"></a>

### BatchGetUserResponse
BatchGetUserResponse contains the leaf entries for a set of users at the most
recently published revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| revision | [Revision](#google.keytransparency.v1.Revision) |  | revision is the most recently published revision. |
| map_leaves_by_user_id | [BatchGetUserResponse.MapLeavesByUserIdEntry](#google.keytransparency.v1.BatchGetUserResponse.MapLeavesByUserIdEntry) | repeated | map_leaves_by_user_id is a map from user_id to the map leaf at the most recently published revision. |






<a name="google.keytransparency.v1.BatchGetUserResponse.MapLeavesByUserIdEntry"></a>

### BatchGetUserResponse.MapLeavesByUserIdEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [MapLeaf](#google.keytransparency.v1.MapLeaf) |  |  |






<a name="google.keytransparency.v1.BatchListUserRevisionsRequest"></a>

### BatchListUserRevisionsRequest
BatchListUserRevisionsRequest contains a list of users and a range of revisions.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the users live. |
| user_ids | [string](#string) | repeated | user_ids are the user identifiers. |
| start_revision | [int64](#int64) |  | start_revision is the starting revision. |
| end_revision | [int64](#int64) |  | end_revision is the ending epoch. |
| page_size | [int32](#int32) |  | page_size is the maximum number of entries to return. If page_size is unspecified, the server will decide how to paginate results. |
| page_token | [string](#string) |  | page_token is a continuation token for paginating through results. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.BatchListUserRevisionsResponse"></a>

### BatchListUserRevisionsResponse
BatchListUserRevisionsResponse contains multiple map leaves across multiple revisions.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| latest_log_root | [LogRoot](#google.keytransparency.v1.LogRoot) |  | latest_log_root contains the latest log root and its consistency proof. |
| map_revisions | [BatchMapRevision](#google.keytransparency.v1.BatchMapRevision) | repeated | map_revisions is a list of map revisions. At most page_size revisions will be returned. |






<a name="google.keytransparency.v1.BatchMapRevision"></a>

### BatchMapRevision
BatchMapRevision contains a set of map leaves at a speific revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map_root | [MapRoot](#google.keytransparency.v1.MapRoot) |  | map_root contains the map root and its inclusion in the log. |
| map_leaves_by_user_id | [BatchMapRevision.MapLeavesByUserIdEntry](#google.keytransparency.v1.BatchMapRevision.MapLeavesByUserIdEntry) | repeated | map_leaves_by_user_id contains a mapping from user_id to the map leaf at this revision. |






<a name="google.keytransparency.v1.BatchMapRevision.MapLeavesByUserIdEntry"></a>

### BatchMapRevision.MapLeavesByUserIdEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [MapLeaf](#google.keytransparency.v1.MapLeaf) |  |  |






<a name="google.keytransparency.v1.BatchQueueUserUpdateRequest"></a>

### BatchQueueUserUpdateRequest
BatchQueueUserUpdateRequest enqueues multiple changes to user profiles.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the users live. |
| updates | [EntryUpdate](#google.keytransparency.v1.EntryUpdate) | repeated | updates contains user updates. |






<a name="google.keytransparency.v1.Committed"></a>

### Committed
Committed represents the data committed to in a cryptographic commitment.
commitment = HMAC_SHA512_256(key, data)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [bytes](#bytes) |  | key is the 16 byte random commitment key. |
| data | [bytes](#bytes) |  | data is the data being committed to. |






<a name="google.keytransparency.v1.Entry"></a>

### Entry
Entry is a signed change to a map entry.
Entry contains a commitment to profile and a set of authorized update keys.
Entry is placed in the verifiable map as leaf data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| index | [bytes](#bytes) |  | index is the location of this leaf in the sparse merkle tree. |
| commitment | [bytes](#bytes) |  | commitment is a cryptographic commitment to arbitrary data. |
| authorized_keyset | [bytes](#bytes) |  | authorized_keys is the tink keyset that validates the signatures on the next entry. |
| previous | [bytes](#bytes) |  | previous contains the SHA256 hash of SignedEntry.Entry the last time it was modified. |






<a name="google.keytransparency.v1.EntryUpdate"></a>

### EntryUpdate
EntryUpdate contains the user entry update(s).
EntryUpdate will be placed in a Log of mutations.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [string](#string) |  | user_id specifies the id for the user whose profile is being updated. |
| mutation | [SignedEntry](#google.keytransparency.v1.SignedEntry) |  | mutation authorizes the change to entry. |
| committed | [Committed](#google.keytransparency.v1.Committed) |  | committed contains the data committed to in mutation.commitment. |






<a name="google.keytransparency.v1.GetLatestRevisionRequest"></a>

### GetLatestRevisionRequest
GetLatestRevisionRequest identifies a particular revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id is the directory for which revisions are being requested. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.GetRevisionRequest"></a>

### GetRevisionRequest
GetRevisionRequest identifies a particular revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id is the directory for which revisions are being requested. |
| revision | [int64](#int64) |  | revision specifies the revision number in which mutations will be returned. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.GetUserRequest"></a>

### GetUserRequest
Gets the leaf entry for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the user lives. |
| user_id | [string](#string) |  | user_id is the user identifier, the format for which is defined by the application. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.GetUserResponse"></a>

### GetUserResponse
Contains the leaf entry for a user at the most recently published revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| revision | [Revision](#google.keytransparency.v1.Revision) |  | revision is the most recently published revision. |
| leaf | [MapLeaf](#google.keytransparency.v1.MapLeaf) |  | leaf is the leaf entry for the requested user. |






<a name="google.keytransparency.v1.ListEntryHistoryRequest"></a>

### ListEntryHistoryRequest
ListEntryHistoryRequest gets a list of historical keys for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the user lives. |
| user_id | [string](#string) |  | user_id is the user identifier. |
| start | [int64](#int64) |  | start is the starting revision. |
| page_size | [int32](#int32) |  | page_size is the maximum number of entries to return. The server can return fewer entries than requested. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.ListEntryHistoryResponse"></a>

### ListEntryHistoryResponse
ListEntryHistoryResponse requests a paginated history of keys for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| values | [GetUserResponse](#google.keytransparency.v1.GetUserResponse) | repeated | values represents the list of keys this user_id has contained over time. |
| next_start | [int64](#int64) |  | next_start is the next page token to query for pagination. next_start is 0 when there are no more results to fetch. |






<a name="google.keytransparency.v1.ListMutationsRequest"></a>

### ListMutationsRequest
ListMutationsRequest requests the mutations that created a given revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id is the directory identifier. |
| revision | [int64](#int64) |  | revision specifies the revision number. |
| page_token | [string](#string) |  | page_token defines the starting point for pagination. To request the next page, pass next_page_token from the previous response. To start at the beginning, simply omit page_token from the request. |
| page_size | [int32](#int32) |  | page_size is the maximum number of mutations to return in a single request. The server may choose a smaller page_size than the one requested.

TODO(gbelvin): Add field mask. |






<a name="google.keytransparency.v1.ListMutationsResponse"></a>

### ListMutationsResponse
ListMutationsResponse contains the mutations that produced an revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mutations | [MutationProof](#google.keytransparency.v1.MutationProof) | repeated | mutations contains the mutation object and the leaf value it operated on. |
| next_page_token | [string](#string) |  | next_page_token is the next page token to query for pagination. An empty value means there are no more results to fetch. |






<a name="google.keytransparency.v1.ListUserRevisionsRequest"></a>

### ListUserRevisionsRequest
ListUserRevisionsRequest gets a list of historical keys for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the user lives. |
| user_id | [string](#string) |  | user_id is the user identifier. |
| start_revision | [int64](#int64) |  | start_revision is the starting epoch. |
| end_revision | [int64](#int64) |  | end_revision is the ending epoch. |
| page_size | [int32](#int32) |  | page_size is the maximum number of entries to return. If page_size is unspecified, the server will decide how to paginate results. |
| page_token | [string](#string) |  | page_token is a continuation token for paginating through results. |
| last_verified | [LogRootRequest](#google.keytransparency.v1.LogRootRequest) |  | last_verified is the last log root the client verified. Omitting this field will omit the log consistency proof from the response. |






<a name="google.keytransparency.v1.ListUserRevisionsResponse"></a>

### ListUserRevisionsResponse
ListUserRevisionsResponse requests a paginated history of keys for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| latest_log_root | [LogRoot](#google.keytransparency.v1.LogRoot) |  | latest_log_root contains the latest log root and its consistency proof. |
| map_revisions | [MapRevision](#google.keytransparency.v1.MapRevision) | repeated | map_revisions represents the list of keys this user_id has contained over time. At most page_size results will be returned. |
| next_page_token | [string](#string) |  | next_page_token is a pagination token which will be set if more than page_size results are available. Clients can pass this value as the page_token in the next request in order to continue pagination. |






<a name="google.keytransparency.v1.LogRoot"></a>

### LogRoot
LogRoot contains the latest log root and its consistency proof.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| log_root | [trillian.SignedLogRoot](#trillian.SignedLogRoot) |  | log_root is the latest globally consistent log root. |
| log_consistency | [bytes](#bytes) | repeated | log_consistency proves that log_root is consistent with previously seen roots. |






<a name="google.keytransparency.v1.LogRootRequest"></a>

### LogRootRequest
LogRootRequest contains the information needed to request and verify LogRoot.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| root_hash | [bytes](#bytes) |  | root_hash is the root hash of the last log root the client verified. |
| tree_size | [int64](#int64) |  | tree_size is the tree size of the last log root the client verified. |






<a name="google.keytransparency.v1.MapLeaf"></a>

### MapLeaf
Leaf entry for a user.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vrf_proof | [bytes](#bytes) |  | vrf_proof is the proof for the VRF on user_id. |
| map_inclusion | [trillian.MapLeafInclusion](#trillian.MapLeafInclusion) |  | map_inclusion is an inclusion proof for the map leaf in an accompanying trillian.SignedMapRoot. If the leaf is non-empty, its leaf.leaf_value stores a serialized Entry proto. |
| committed | [Committed](#google.keytransparency.v1.Committed) |  | committed contains the data and nonce used to make a cryptographic commitment, which is stored in the commitment field of the serialized Entry proto from map_inclusion. Note: committed can also be found serialized in map_inclusion.leaf.extra_data. |






<a name="google.keytransparency.v1.MapRevision"></a>

### MapRevision
MapRevision contains a map leaf at a speific revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map_root | [MapRoot](#google.keytransparency.v1.MapRoot) |  | map_root contains the map root and its inclusion in the log. |
| map_leaf | [MapLeaf](#google.keytransparency.v1.MapLeaf) |  | map_leaf contains a leaf and its inclusion proof to map_root. |






<a name="google.keytransparency.v1.MapRoot"></a>

### MapRoot
MapRoot contains the map root and its inclusion proof in the log.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map_root | [trillian.SignedMapRoot](#trillian.SignedMapRoot) |  | map_root contains the signed map root for the sparse Merkle Tree. |
| log_inclusion | [bytes](#bytes) | repeated | log_inclusion proves that map_root is part of log_root at index=map_root.MapRevision. |






<a name="google.keytransparency.v1.MapperMetadata"></a>

### MapperMetadata
MapperMetadata tracks the mutations that have been mapped so far. It is
embedded in the Trillian SignedMapHead.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| highest_fully_completed_seq | [int64](#int64) |  |  |






<a name="google.keytransparency.v1.MutationProof"></a>

### MutationProof
MutationProof contains the information necessary to compute the new leaf
value. It contains a) the old leaf value with it&#39;s inclusion proof and b) the
mutation. The new leaf value is computed via:
      Mutate(leaf_value, mutation)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mutation | [SignedEntry](#google.keytransparency.v1.SignedEntry) |  | mutation contains the information needed to modify the old leaf. The format of a mutation is specific to the particular Mutate function being used. |
| leaf_proof | [trillian.MapLeafInclusion](#trillian.MapLeafInclusion) |  | leaf_proof contains the leaf and its inclusion proof for a particular map revision. |






<a name="google.keytransparency.v1.Revision"></a>

### Revision
Revision represents a snapshot of the entire key directory and
a diff of what changed between this revision and the previous revision.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id is the directory identifier. |
| map_root | [MapRoot](#google.keytransparency.v1.MapRoot) |  | map_root contains the map root and its inclusion in the log. |
| latest_log_root | [LogRoot](#google.keytransparency.v1.LogRoot) |  | latest_log_root contains the most recent log root and its consistency proof to the client&#39;s last seen log root. |






<a name="google.keytransparency.v1.SignedEntry"></a>

### SignedEntry
SignedEntry is a cryptographically signed Entry.
SignedEntry will be storead as a trillian.Map leaf.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [bytes](#bytes) |  | entry contains a serialized Entry. |
| signatures | [bytes](#bytes) | repeated | signatures on entry. Must be signed by keys from both previous and current revisions. The first proves ownership of new revision key, and the second proves that the correct owner is making this change. The signature scheme is specified by the authorized_keys tink.Keyset. |






<a name="google.keytransparency.v1.UpdateEntryRequest"></a>

### UpdateEntryRequest
UpdateEntryRequest updates a user&#39;s profile.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the user lives. |
| entry_update | [EntryUpdate](#google.keytransparency.v1.EntryUpdate) |  | entry_update contains the user submitted update. |





 

 

 


<a name="google.keytransparency.v1.KeyTransparency"></a>

### KeyTransparency
The KeyTransparency API represents a directory of public keys.

The API has a collection of directories:
`/v1/directories/`
 * Each directory has a single sparse merkle tree, append only log,
   and other public key material that is needed to verify server responses.

Each Directory has a collection of snapshots called revisions:
`/v1/directories/*/revisions/`
 * Each Revision contains the root of the sparse merkle tree and the changes
 that
   occurred that revision and the previous.

Each Revision has a collection of mutations:
`/v1/directories/*/revisions/*/mutations/`.
 * Each mutation contains the leafvalue of the previous revision that it
 operated on.
 * The full set of mutations for an revision allows the receiver to compute the
    Merkle Tree Root of this revision from the previous revision.

Each Directory has a collection of Users:
`/v1/directories/*/users/`
 * Each User contains public key material, permissions for who is allowed to
   change that user, and signatures indicating who made the last change.

Each User also has a collection of historical values for user:
`/v1/directories/*/users/*/history`

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetDirectory | [GetDirectoryRequest](#google.keytransparency.v1.GetDirectoryRequest) | [Directory](#google.keytransparency.v1.Directory) | GetDirectory returns the information needed to verify the specified directory. |
| GetRevision | [GetRevisionRequest](#google.keytransparency.v1.GetRevisionRequest) | [Revision](#google.keytransparency.v1.Revision) | GetRevision returns a SignedMapRoot by the by the requested revision number along with its inclusion proof in the log and the log&#39;s consistency proofs. |
| GetLatestRevision | [GetLatestRevisionRequest](#google.keytransparency.v1.GetLatestRevisionRequest) | [Revision](#google.keytransparency.v1.Revision) | GetLatestRevision returns the latest SignedMapRoot along with its inclusion proof in the log and the log&#39;s consistency proofs. |
| GetRevisionStream | [GetRevisionRequest](#google.keytransparency.v1.GetRevisionRequest) | [Revision](#google.keytransparency.v1.Revision) stream | GetRevisionStream streams new revisions from a requested starting point and continues as new revisions are created. |
| ListMutations | [ListMutationsRequest](#google.keytransparency.v1.ListMutationsRequest) | [ListMutationsResponse](#google.keytransparency.v1.ListMutationsResponse) | ListMutations returns a list of mutations in a specific revision. |
| ListMutationsStream | [ListMutationsRequest](#google.keytransparency.v1.ListMutationsRequest) | [MutationProof](#google.keytransparency.v1.MutationProof) stream | ListMutationsStream is a streaming list of mutations in a specific revision. |
| GetUser | [GetUserRequest](#google.keytransparency.v1.GetUserRequest) | [GetUserResponse](#google.keytransparency.v1.GetUserResponse) | GetUser returns a user&#39;s leaf entry in the Merkle Tree. |
| BatchGetUser | [BatchGetUserRequest](#google.keytransparency.v1.BatchGetUserRequest) | [BatchGetUserResponse](#google.keytransparency.v1.BatchGetUserResponse) | BatchGetUser returns a batch of user leaf entries in the Merkle tree at the same revision. |
| BatchGetUserIndex | [BatchGetUserIndexRequest](#google.keytransparency.v1.BatchGetUserIndexRequest) | [BatchGetUserIndexResponse](#google.keytransparency.v1.BatchGetUserIndexResponse) | BatchGetUserIndex returns the VRF proof for a set of userIDs. |
| ListEntryHistory | [ListEntryHistoryRequest](#google.keytransparency.v1.ListEntryHistoryRequest) | [ListEntryHistoryResponse](#google.keytransparency.v1.ListEntryHistoryResponse) | ListEntryHistory returns a list of historic GetUser values.

Clients verify their account history by observing correct values for their account over time. |
| ListUserRevisions | [ListUserRevisionsRequest](#google.keytransparency.v1.ListUserRevisionsRequest) | [ListUserRevisionsResponse](#google.keytransparency.v1.ListUserRevisionsResponse) | ListUserRevisions returns a list of historic leaf values for a user.

Clients verify their account history by observing correct values for their account over time. |
| BatchListUserRevisions | [BatchListUserRevisionsRequest](#google.keytransparency.v1.BatchListUserRevisionsRequest) | [BatchListUserRevisionsResponse](#google.keytransparency.v1.BatchListUserRevisionsResponse) | BatchListUserRevisions returns a list of revisions for multiple users. |
| QueueEntryUpdate | [UpdateEntryRequest](#google.keytransparency.v1.UpdateEntryRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | QueueUserUpdate enqueues an update to a user&#39;s profile.

Clients should poll GetUser until the update appears, and retry if no update appears after a timeout. |
| BatchQueueUserUpdate | [BatchQueueUserUpdateRequest](#google.keytransparency.v1.BatchQueueUserUpdateRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | BatchQueueUserUpdate enqueues a list of user profiles. |

 



<a name="v1/admin.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/admin.proto



<a name="google.keytransparency.v1.CreateDirectoryRequest"></a>

### CreateDirectoryRequest
CreateDirectoryRequest creates a new directory


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |
| min_interval | [google.protobuf.Duration](#google.protobuf.Duration) |  |  |
| max_interval | [google.protobuf.Duration](#google.protobuf.Duration) |  |  |
| vrf_private_key | [google.protobuf.Any](#google.protobuf.Any) |  | The private_key fields allows callers to set the private key. |
| log_private_key | [google.protobuf.Any](#google.protobuf.Any) |  |  |
| map_private_key | [google.protobuf.Any](#google.protobuf.Any) |  |  |






<a name="google.keytransparency.v1.DeleteDirectoryRequest"></a>

### DeleteDirectoryRequest
DeleteDirectoryRequest deletes a directory


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |






<a name="google.keytransparency.v1.Directory"></a>

### Directory
Directory contains information on a single directory


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | DirectoryId can be any URL safe string. |
| log | [trillian.Tree](#trillian.Tree) |  | Log contains the Log-Tree&#39;s info. |
| map | [trillian.Tree](#trillian.Tree) |  | Map contains the Map-Tree&#39;s info. |
| vrf | [keyspb.PublicKey](#keyspb.PublicKey) |  | Vrf contains the VRF public key. |
| min_interval | [google.protobuf.Duration](#google.protobuf.Duration) |  | min_interval is the minimum time between revisions. |
| max_interval | [google.protobuf.Duration](#google.protobuf.Duration) |  | max_interval is the maximum time between revisions. |
| deleted | [bool](#bool) |  | Deleted indicates whether the directory has been marked as deleted. By its presence in a response, this directory has not been garbage collected. |






<a name="google.keytransparency.v1.GarbageCollectRequest"></a>

### GarbageCollectRequest
GarbageCollect request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| before | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Soft-deleted directories with a deleted timestamp before this will be fully deleted. |






<a name="google.keytransparency.v1.GarbageCollectResponse"></a>

### GarbageCollectResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directories | [Directory](#google.keytransparency.v1.Directory) | repeated |  |






<a name="google.keytransparency.v1.GetDirectoryRequest"></a>

### GetDirectoryRequest
GetDirectoryRequest specifies the directory to retrieve information for.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |
| show_deleted | [bool](#bool) |  | showDeleted requests directories that have been marked for deletion but have not been garbage collected. |






<a name="google.keytransparency.v1.InputLog"></a>

### InputLog
InputLog is an input log for a directory.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |
| log_id | [int64](#int64) |  |  |
| writable | [bool](#bool) |  | writable controls whether new log items will be sent to this log. writable is not set by ListInputLogs. |






<a name="google.keytransparency.v1.ListDirectoriesRequest"></a>

### ListDirectoriesRequest
ListDirectories request.
No pagination options are provided.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| show_deleted | [bool](#bool) |  | showDeleted requests directories that have been marked for deletion but have not been garbage collected. |






<a name="google.keytransparency.v1.ListDirectoriesResponse"></a>

### ListDirectoriesResponse
ListDirectories response contains directories.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directories | [Directory](#google.keytransparency.v1.Directory) | repeated |  |






<a name="google.keytransparency.v1.ListInputLogsRequest"></a>

### ListInputLogsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |
| filter_writable | [bool](#bool) |  | filter_writable will only return writable logs when set. |






<a name="google.keytransparency.v1.ListInputLogsResponse"></a>

### ListInputLogsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| logs | [InputLog](#google.keytransparency.v1.InputLog) | repeated |  |






<a name="google.keytransparency.v1.UndeleteDirectoryRequest"></a>

### UndeleteDirectoryRequest
UndeleteDirectoryRequest deletes a directory


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  |  |





 

 

 


<a name="google.keytransparency.v1.KeyTransparencyAdmin"></a>

### KeyTransparencyAdmin
The KeyTransparencyAdmin API provides the following resources:
- Directories
  Namespaces on which which Key Transparency operates. A directory determines
  a unique Trillian map to use. It also determines the authentication
  policies for users and apps within a directory.
  - /v1/directories

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListDirectories | [ListDirectoriesRequest](#google.keytransparency.v1.ListDirectoriesRequest) | [ListDirectoriesResponse](#google.keytransparency.v1.ListDirectoriesResponse) | ListDirectories returns a list of all directories this Key Transparency server operates on. |
| GetDirectory | [GetDirectoryRequest](#google.keytransparency.v1.GetDirectoryRequest) | [Directory](#google.keytransparency.v1.Directory) | GetDirectory returns the confiuration information for a given directory. |
| CreateDirectory | [CreateDirectoryRequest](#google.keytransparency.v1.CreateDirectoryRequest) | [Directory](#google.keytransparency.v1.Directory) | CreateDirectory creates a new Trillian log/map pair. A unique directoryId must be provided. To create a new directory with the same name as a previously deleted directory, a user must wait X days until the directory is garbage collected. |
| DeleteDirectory | [DeleteDirectoryRequest](#google.keytransparency.v1.DeleteDirectoryRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | DeleteDirectory marks a directory as deleted. Directories will be garbage collected after X days. |
| UndeleteDirectory | [UndeleteDirectoryRequest](#google.keytransparency.v1.UndeleteDirectoryRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | UndeleteDirectory marks a previously deleted directory as active if it has not already been garbage collected. |
| ListInputLogs | [ListInputLogsRequest](#google.keytransparency.v1.ListInputLogsRequest) | [ListInputLogsResponse](#google.keytransparency.v1.ListInputLogsResponse) | ListInputLogs returns a list of input logs for a directory. |
| CreateInputLog | [InputLog](#google.keytransparency.v1.InputLog) | [InputLog](#google.keytransparency.v1.InputLog) | CreateInputLog returns a the created log. |
| UpdateInputLog | [InputLog](#google.keytransparency.v1.InputLog) | [InputLog](#google.keytransparency.v1.InputLog) | UpdateInputLog updates the write bit for an input log. |
| GarbageCollect | [GarbageCollectRequest](#google.keytransparency.v1.GarbageCollectRequest) | [GarbageCollectResponse](#google.keytransparency.v1.GarbageCollectResponse) | Fully delete soft-deleted directories that have been soft-deleted before the specified timestamp. |

 



<a name="v1/frontend.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/frontend.proto



<a name="google.keytransparency.v1.QueueKeyUpdateRequest"></a>

### QueueKeyUpdateRequest
QueueKeyUpdateRequest enqueues an update to a user&#39;s identity keys.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| directory_id | [string](#string) |  | directory_id identifies the directory in which the user lives. |
| user_id | [string](#string) |  | user_id specifies the id for the user whose keys are being updated. |
| key_data | [bytes](#bytes) |  | key_data is the key data to store. |





 

 

 


<a name="google.keytransparency.v1.KeyTransparencyFrontend"></a>

### KeyTransparencyFrontend
Manages user keys stored in Key Transparency with a client-friendly API.
This service is operated by the application provider, and is authorized to
make key changes on users&#39; behalves.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| QueueKeyUpdate | [QueueKeyUpdateRequest](#google.keytransparency.v1.QueueKeyUpdateRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | Enqueues an update to a user&#39;s identity keys. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

