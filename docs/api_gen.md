# Key Transparency API

A transparency key server API for End to End projects.

## Service: keytransparency.v1

## [KeyTransparencyService](#KeyTransparencyService)

[GetEntry](#KeyTransparencyService.GetEntry) GetEntry
returns a user's entry in the Merkle Tree. [HkpLookup]
(#KeyTransparencyService.HkpLookup) HkpLookup implements a
SKS server lookup functions. [ListEntryHistory]
(#KeyTransparencyService.ListEntryHistory) ListEntryHistory
returns a list of historic GetEntry values. [UpdateEntry]
(#KeyTransparencyService.UpdateEntry) UpdateEntry submits a
SignedEntryUpdate.

# Reference

<a name="rpc_ctmap"/>

## Package ctmap

<a name="rpc_ctmap_index"/>

### Index

*   [DigitallySigned](#ctmap.DigitallySigned) (message)
*   [DigitallySigned.HashAlgorith](#ctmap.DigitallySigned.HashAlgorithm) (enum)
*   [DigitallySigned.SignatureAlgorithm]
    (#ctmap.DigitallySigned.SignatureAlgorithm) (enum)
*   [GetLeafResponse](#ctmap.GetLeafResponse) (message)
*   [MapHead](#ctmap.MapHead) (message)
*   [SignedMapHead](#ctmap.SignedMapHead) (message)

<a name="ctmap.DigitallySigned"/>

### DigitallySigned

DigitallySigned defines a way to sign digital objects.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ctmap.DigitallySigned.hash_algorithm"/>
 <tr>
  <td><code>hash_algorithm</code></td>
  <td><a href="#ctmap.DigitallySigned.HashAlgorithm">HashAlgorithm</a></td>
  <td></td>
 </tr>
<a name="ctmap.DigitallySigned.sig_algorithm"/>
 <tr>
  <td><code>sig_algorithm</code></td>
  <td><a href="#ctmap.DigitallySigned.SignatureAlgorithm">SignatureAlgorithm</a></td>
  <td></td>
 </tr>
<a name="ctmap.DigitallySigned.signature"/>
 <tr>
  <td><code>signature</code></td>
  <td>bytes</td>
  <td></td>
 </tr>
</table>

<a name="ctmap.DigitallySigned.HashAlgorithm"/>

### HashAlgorithm

HashAlgorithm defines the approved ways to hash the object.

<table>
 <tr>
  <th>Value</th>
  <th>Description</th>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.NONE"/>
 <tr>
  <td>NONE</td>
  <td></td>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.SHA256"/>
 <tr>
  <td>SHA256</td>
  <td></td>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.SHA512"/>
 <tr>
  <td>SHA512</td>
  <td></td>
 </tr>
</table>

<a name="ctmap.DigitallySigned.SignatureAlgorithm"/>

### SignatureAlgorithm

SignatureAlgorithm defines the way to sign the object.

<table>
 <tr>
  <th>Value</th>
  <th>Description</th>
 </tr>
<a name="ctmap.DigitallySigned.SignatureAlgorithm.ANONYMOUS"/>
 <tr>
  <td>ANONYMOUS</td>
  <td></td>
 </tr>
<a name="ctmap.DigitallySigned.SignatureAlgorithm.ECDSA"/>
 <tr>
  <td>ECDSA</td>
  <td></td>
 </tr>
</table>

<a name="ctmap.GetLeafResponse"/>

### GetLeafResponse

GetLeafResponse for a verifiable map leaf.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ctmap.GetLeafResponse.leaf_data"/>
 <tr>
  <td><code>leaf_data</code></td>
  <td>bytes</td>
  <td></td>
 </tr>
<a name="ctmap.GetLeafResponse.neighbors"/>
 <tr>
  <td><code>neighbors[]</code></td>
  <td>repeated bytes</td>
  <td>neighbors is a list of all the adjacent nodes along the path from the bottommost node to the head.</td>
 </tr>
</table>

<a name="ctmap.MapHead"/>

### MapHead

MapHead is the head node of the Merkle Tree as well as additional metadata for
the tree.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ctmap.MapHead.realm"/>
 <tr>
  <td><code>realm</code></td>
  <td>string</td>
  <td>realm is the domain identifier for the transparent map.</td>
 </tr>
<a name="ctmap.MapHead.epoch"/>
 <tr>
  <td><code>epoch</code></td>
  <td>int64</td>
  <td>epoch number</td>
 </tr>
<a name="ctmap.MapHead.root"/>
 <tr>
  <td><code>root</code></td>
  <td>bytes</td>
  <td>root is the value of the root node of the merkle tree.</td>
 </tr>
<a name="ctmap.MapHead.issue_time"/>
 <tr>
  <td><code>issue_time</code></td>
  <td><a href="#google.protobuf.Timestamp">Timestamp</a></td>
  <td>issue_time is the time when this epoch was released. Monotonically increasing.</td>
 </tr>
</table>

<a name="ctmap.SignedMapHead"/>

### SignedMapHead

SignedMapHead represents a signed state of the Merkel tree.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ctmap.SignedMapHead.map_head"/>
 <tr>
  <td><code>map_head</code></td>
  <td><a href="#ctmap.MapHead">MapHead</a></td>
  <td></td>
 </tr>
<a name="ctmap.SignedMapHead.signatures"/>
 <tr>
  <td><code>signatures</code></td>
  <td>repeated map&lt;string, <a href="#ctmap.DigitallySigned">DigitallySigned</a>&gt;</td>
  <td>Signature of head, using the signature type of the key. keyed by the first 64 bits bytes of the hash of the key.</td>
 </tr>
</table>

<a name="rpc_/>

## Package key_transparency.v1

<a name="rpc_index"/>

### Index

*   [KeyTransparencyService](#KeyTransparencyService)
    (interface)
*   [Committed](#Committed) (message)
*   [EntryUpdate](#EntryUpdate) (message)
*   [GetEntryRequest](#GetEntryRequest) (message)
*   [GetEntryResponse](#GetEntryResponse) (message)
*   [HkpLookupRequest](#HkpLookupRequest) (message)
*   [HttpResponse](#HttpResponse) (message)
*   [ListEntryHistoryRequest](#ListEntryHistoryRequest)
    (message)
*   [ListEntryHistoryResponse](#ListEntryHistoryResponse)
    (message)
*   [SignedKV](#SignedKV) (message)
*   [UpdateEntryRequest](#UpdateEntryRequest) (message)
*   [UpdateEntryResponse](#UpdateEntryResponse) (message)

<a name="KeyTransparencyService"/>

### KeyTransparencyService

The KeyTransparencyService API represents a directory of public keys. The API
defines the following resource model:

-   The API has a collection of Entry resources named `/user/*`.

-   Entries have a collection of historical Entry resources named
    `/users/*/history`.

<a name="KeyTransparencyService.GetEntry"/>

#### GetEntry

<code> rpc GetEntry([GetEntryRequest](#GetEntryRequest))
returns ([GetEntryResponse](#GetEntryResponse)) </code>
GetEntry returns a user's entry in the Merkle Tree.

Entries contain signed commitments to a profile, which is also returned.

<a name="KeyTransparencyService.HkpLookup"/>

#### HkpLookup

<code> rpc HkpLookup([HkpLookupRequest](#HkpLookupRequest))
returns ([HttpResponse](#HttpResponse)) </code> HkpLookup
implements a SKS server lookup functions.

<a name="KeyTransparencyService.ListEntryHistory"/>

#### ListEntryHistory

<code> rpc ListEntryHistory([ListEntryHistoryRequest]
(#ListEntryHistoryRequest)) returns
([ListEntryHistoryResponse](#ListEntryHistoryResponse))
</code> ListEntryHistory returns a list of historic GetEntry values.

Clients verify their account history by observing correct values for their
account over time.

<a name="KeyTransparencyService.UpdateEntry"/>

#### UpdateEntry

<code> rpc UpdateEntry([UpdateEntryRequest]
(#UpdateEntryRequest)) returns ([UpdateEntryResponse]
(#UpdateEntryResponse)) </code> UpdateEntry submits a
SignedEntryUpdate.

Returns empty until this update has been included in an epoch. Clients must
retry until this function returns a proof.

<a name="Committed"/>

### Committed

Committed represents the data comitted to in a cryptographic commitment.
commitment = HMAC_SHA512_256(key, data)

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="Committed.key"/>
 <tr>
  <td><code>key</code></td>
  <td>bytes</td>
  <td>key is the 16 byte random commitment key.</td>
 </tr>
<a name="Committed.data"/>
 <tr>
  <td><code>data</code></td>
  <td>bytes</td>
  <td>data is the data being comitted to.</td>
 </tr>
</table>

<a name="EntryUpdate"/>

### EntryUpdate

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="EntryUpdate.update"/>
 <tr>
  <td><code>update</code></td>
  <td><a href="#SignedKV">SignedKV</a></td>
  <td>update authorizes the change to profile.</td>
 </tr>
<a name="EntryUpdate.committed"/>
 <tr>
  <td><code>committed</code></td>
  <td><a href="#Committed">Committed</a></td>
  <td>commitment contains the serialized Profile protobuf. Last trusted epoch by the client. int64 epoch_start = 6;</td>
 </tr>
</table>

<a name="GetEntryRequest"/>

### GetEntryRequest

Get request for a user object.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="GetEntryRequest.epoch_end"/>
 <tr>
  <td><code>epoch_end</code></td>
  <td>int64</td>
  <td>Last trusted epoch by the client. int64 epoch_start = 3; Absence of the epoch_end field indicates a request for the current value.</td>
 </tr>
<a name="GetEntryRequest.user_id"/>
 <tr>
  <td><code>user_id</code></td>
  <td>string</td>
  <td>User identifier. Most commonly an email address.</td>
 </tr>
</table>

<a name="GetEntryResponse"/>

### GetEntryResponse

GetEntryResponse

Privacy layer hides user_id and profile data until requested.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="GetEntryResponse.vrf"/>
 <tr>
  <td><code>vrf</code></td>
  <td>bytes</td>
  <td>vrf is the output of VRF on user_id.</td>
 </tr>
<a name="GetEntryResponse.vrf_proof"/>
 <tr>
  <td><code>vrf_proof</code></td>
  <td>bytes</td>
  <td>vrf_proof is the proof for VRF on user_id.</td>
 </tr>
<a name="GetEntryResponse.committed"/>
 <tr>
  <td><code>committed</code></td>
  <td><a href="#Committed">Committed</a></td>
  <td>committed contains the profile for this account and connects the data in profile to the commitment in leaf_proof.</td>
 </tr>
<a name="GetEntryResponse.leaf_proof"/>
 <tr>
  <td><code>leaf_proof</code></td>
  <td><a href="#ctmap.GetLeafResponse">GetLeafResponse</a></td>
  <td>leaf_proof contains an Entry and an inclusion proof in the sparse merkle tree at end_epoch.</td>
 </tr>
<a name="GetEntryResponse.smh"/>
 <tr>
  <td><code>smh</code></td>
  <td><a href="#ctmap.SignedMapHead">SignedMapHead</a></td>
  <td>smh contains the signed map head for the sparse merkle tree. smh is also stored in the append only log.</td>
 </tr>
<a name="GetEntryResponse.smh_sct"/>
 <tr>
  <td><code>smh_sct</code></td>
  <td>bytes</td>
  <td>smh_sct is the SCT showing that smh was submitted to CT logs.</td>
 </tr>
</table>

<a name="HkpLookupRequest"/>

### HkpLookupRequest

HkpLookupRequest contains query parameters for retrieving PGP keys.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="HkpLookupRequest.op"/>
 <tr>
  <td><code>op</code></td>
  <td>string</td>
  <td>Op specifies the operation to be performed on the keyserver. - "get" returns the pgp key specified in the search parameter. - "index" returns 501 (not implemented). - "vindex" returns 501 (not implemented).</td>
 </tr>
<a name="HkpLookupRequest.search"/>
 <tr>
  <td><code>search</code></td>
  <td>string</td>
  <td>Search specifies the email address or key id being queried.</td>
 </tr>
<a name="HkpLookupRequest.options"/>
 <tr>
  <td><code>options</code></td>
  <td>string</td>
  <td>Options specifies what output format to use. - "mr" machine readable will set the content type to "application/pgp-keys" - other options will be ignored.</td>
 </tr>
<a name="HkpLookupRequest.exact"/>
 <tr>
  <td><code>exact</code></td>
  <td>string</td>
  <td>Exact specifies an exact match on search. Always on. If specified in the URL, its value will be ignored.</td>
 </tr>
<a name="HkpLookupRequest.fingerprint"/>
 <tr>
  <td><code>fingerprint</code></td>
  <td>string</td>
  <td>fingerprint is ignored.</td>
 </tr>
</table>

<a name="HttpResponse"/>

### HttpResponse

HttpBody represents an http body.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="HttpResponse.content_type"/>
 <tr>
  <td><code>content_type</code></td>
  <td>string</td>
  <td>Header content type.</td>
 </tr>
<a name="HttpResponse.body"/>
 <tr>
  <td><code>body</code></td>
  <td>bytes</td>
  <td>The http body itself.</td>
 </tr>
</table>

<a name="ListEntryHistoryRequest"/>

### ListEntryHistoryRequest

Get a list of historical values for a user.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ListEntryHistoryRequest.user_id"/>
 <tr>
  <td><code>user_id</code></td>
  <td>string</td>
  <td>The user identifier.</td>
 </tr>
<a name="ListEntryHistoryRequest.start_epoch"/>
 <tr>
  <td><code>start_epoch</code></td>
  <td>int64</td>
  <td>from_epoch is the starting epcoh.</td>
 </tr>
<a name="ListEntryHistoryRequest.page_size"/>
 <tr>
  <td><code>page_size</code></td>
  <td>int32</td>
  <td>The maximum number of entries to return.</td>
 </tr>
</table>

<a name="ListEntryHistoryResponse"/>

### ListEntryHistoryResponse

A paginated history of values for a user.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="ListEntryHistoryResponse.values"/>
 <tr>
  <td><code>values[]</code></td>
  <td>repeated <a href="#GetEntryResponse">GetEntryResponse</a></td>
  <td>The list of values this user_id has contained over time.</td>
 </tr>
<a name="ListEntryHistoryResponse.next_epoch"/>
 <tr>
  <td><code>next_epoch</code></td>
  <td>int64</td>
  <td>The next time to query for pagination.</td>
 </tr>
</table>

<a name="SignedKV"/>

### SignedKV

SignedKV is a signed change to a map entry.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="SignedKV.key_value"/>
 <tr>
  <td><code>key_value</code></td>
  <td>bytes</td>
  <td>key_value is a serialized KeyValue.</td>
 </tr>
<a name="SignedKV.signatures"/>
 <tr>
  <td><code>signatures</code></td>
  <td>repeated map&lt;fixed64, bytes&gt;</td>
  <td>signatures on keyvalue. Must be signed by keys from both previous and current epochs. The first proves ownership of new epoch key, and the second proves the the correct owner is making this change.</td>
 </tr>
<a name="SignedKV.previous"/>
 <tr>
  <td><code>previous</code></td>
  <td>bytes</td>
  <td>previous contains the hash of the previous entry that this mutation is modifying creating a hash chain of all mutations. The hash used is CommonJSON in "github.com/benlaurie/objecthash/go/objecthash".</td>
 </tr>
</table>

<a name="UpdateEntryRequest"/>

### UpdateEntryRequest

Update a user's profile.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="UpdateEntryRequest.user_id"/>
 <tr>
  <td><code>user_id</code></td>
  <td>string</td>
  <td>user_id specifies the id for the new account to be registered.</td>
 </tr>
<a name="UpdateEntryRequest.entry_update"/>
 <tr>
  <td><code>entry_update</code></td>
  <td><a href="#EntryUpdate">EntryUpdate</a></td>
  <td></td>
 </tr>
</table>

<a name="UpdateEntryResponse"/>

### UpdateEntryResponse

UpdateEntryResponse contains a proof once the update has been included in the
Merkel Tree.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="UpdateEntryResponse.proof"/>
 <tr>
  <td><code>proof</code></td>
  <td><a href="#GetEntryResponse">GetEntryResponse</a></td>
  <td></td>
 </tr>
</table>

<!-- mdlint on -->
