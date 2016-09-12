# Key Transparency API

A transparency key server API for End to End projects.

## KeyTransparencyService

The KeyTransparencyService API represents a directory of public keys. The API
defines the following resource model:
-   The API has a collection of Entry resources named `/users/*`.
-   Entries have a collection of historical Entry resources named `/users/*/history`.

The API has the following methods:
* [GetEntry](#KeyTransparencyService.GetEntry) returns a user's entry in the Merkle Tree.
* [UpdateEntry](#KeyTransparencyService.UpdateEntry) updates a users profile.
* [ListEntryHistory](#KeyTransparencyService.ListEntryHistory) returns a list of historic GetEntry values.

# Reference

## Package keytransparency.v1.service

*   [KeyTransparencyService](#KeyTransparencyService) (interface)

#### GetEntry

<code> rpc GetEntry([GetEntryRequest](#GetEntryRequest))
returns ([GetEntryResponse](#GetEntryResponse)) </code>

GetEntry returns a user's entry in the Merkle Tree.  
Entries contain signed commitments to a profile, which is also returned.

#### ListEntryHistory

<code> rpc ListEntryHistory([ListEntryHistoryRequest](#ListEntryHistoryRequest)) returns
([ListEntryHistoryResponse](#ListEntryHistoryResponse))
</code>

ListEntryHistory returns a list of historic GetEntry values.  
Clients verify their account history by observing correct values for their
account over time.

#### UpdateEntry

<code> rpc UpdateEntry([UpdateEntryRequest](#UpdateEntryRequest)) returns ([UpdateEntryResponse]
(#UpdateEntryResponse)) </code>   

UpdateEntry updates a user's profile.  
Returns the current user profile.
Clients must retry until this function returns a proof containing the desired value.

## Package keytransparency.v1.types

*   [Committed](#committed) (message)
*   [EntryUpdate](#entryUpdate) (message)
*   [GetEntryRequest](#getEntryRequest) (message)
*   [GetEntryResponse](#GetEntryResponse) (message)
*   [ListEntryHistoryRequest](#ListEntryHistoryRequest) (message)
*   [ListEntryHistoryResponse](#ListEntryHistoryResponse) (message)
*   [SignedKV](#SignedKV) (message)
*   [UpdateEntryRequest](#UpdateEntryRequest) (message)
*   [UpdateEntryResponse](#UpdateEntryResponse) (message)

### Committed

Committed represents the data committed to in a cryptographic commitment.
`commitment = HMAC_SHA512_256(key, data)`

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
  <td>commitment contains the serialized Profile protobuf.</td>
 </tr>
</table>

<a name="GetEntryRequest"/>

### GetEntryRequest

Get request for a user profile.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
  <th>Description</th>
 </tr>
<a name="GetEntryRequest.user_id"/>
 <tr>
  <td><code>user_id</code></td>
  <td>string</td>
  <td>user_id is the user identifier. Most commonly an email address.</td>
 </tr>
</table>

<a name="GetEntryResponse"/>

### GetEntryResponse

GetEntryResponse returns a requested user entry.

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
  <td>leaf_proof contains an Entry and an inclusion proof in the sparse Merkle Tree.</td>
 </tr>
<a name="GetEntryResponse.smh"/>
 <tr>
  <td><code>smh</code></td>
  <td><a href="#ctmap.SignedMapHead">SignedMapHead</a></td>
  <td>smh contains the signed map head for the sparse Merkle Tree. smh is also stored in the append only log.</td>
 </tr>
<a name="GetEntryResponse.smh_sct"/>
 <tr>
  <td><code>smh_sct</code></td>
  <td>bytes</td>
  <td>smh_sct is the signed certificate timestamp (SCT) showing that SMH was submitted to CT logs.</td>
 </tr>
</table>

### ListEntryHistoryRequest

ListEntryHistoryReques gets a list of historical keys for a user.

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
  <td>user_id is the user identifier.</td>
 </tr>
<a name="ListEntryHistoryRequest.start_epoch"/>
 <tr>
  <td><code>start</code></td>
  <td>int64</td>
  <td>start is the starting epcoh.</td>
 </tr>
<a name="ListEntryHistoryRequest.page_size"/>
 <tr>
  <td><code>page_size</code></td>
  <td>int32</td>
  <td>page_size is the maximum number of entries to return.</td>
 </tr>
</table>

<a name="ListEntryHistoryResponse"/>

### ListEntryHistoryResponse

ListEntryHistoryResponse requests a paginated history of keys for a user.

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
  <td>values represents the list of keys this user_id has contained over time.</td>
 </tr>
<a name="ListEntryHistoryResponse.next_epoch"/>
 <tr>
  <td><code>next_epoch</code></td>
  <td>int64</td>
  <td>The next epoch to query for pagination.</td>
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
  <td>map&lt;fixed64, bytes&gt;</td>
  <td>signatures on key_value. Must be signed by keys from both previous and current epochs. The first proves ownership of new epoch key, and the second proves the correct owner is making this change.</td>
 </tr>
<a name="SignedKV.previous"/>
 <tr>
  <td><code>previous</code></td>
  <td>bytes</td>
  <td>previous contains the hash of the previous entry that this mutation is modifying/creating a hash chain of all mutations. The hash used is CommonJSON in "github.com/benlaurie/objecthash/go/objecthash".</td>
 </tr>
</table>

<a name="UpdateEntryRequest"/>

### UpdateEntryRequest

UpdateEntryRequest updates a user's profile.

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
  <td>user_id specifies the id for the user who's profile is being updated.</td>
 </tr>
<a name="UpdateEntryRequest.entry_update"/>
 <tr>
  <td><code>entry_update</code></td>
  <td><a href="#EntryUpdate">EntryUpdate</a></td>
  <td>entry_update contains the user submitted update.</td>
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
  <td>proof contains a proof that the update has been included in the tree.</td>
 </tr>
</table>

## Package ctmap

CT Map represents a Certificate Transparency style [verifiable map](https://github.com/google/trillian/blob/master/docs/VerifiableDataStructures.pdf).

### Index

*   [DigitallySigned](#ctmap.DigitallySigned) (message)
*   [DigitallySigned.HashAlgorith](#ctmap.DigitallySigned.HashAlgorithm) (enum)
*   [DigitallySigned.SignatureAlgorithm](#ctmap.DigitallySigned.SignatureAlgorithm) (enum)
*   [GetLeafResponse](#ctmap.GetLeafResponse) (message)
*   [MapHead](#ctmap.MapHead) (message)
*   [SignedMapHead](#ctmap.SignedMapHead) (message)

<a name="ctmap.DigitallySigned"/>

### DigitallySigned

DigitallySigned defines a way to digitally sign objects.

<table>
 <tr>
  <th>Field</th>
  <th>Type</th>
 </tr>
 <tr>
  <td><code>hash_algorithm</code></td>
  <td><a href="#ctmap.DigitallySigned.HashAlgorithm">HashAlgorithm</a></td>
 </tr>
 <tr>
  <td><code>sig_algorithm</code></td>
  <td><a href="#ctmap.DigitallySigned.SignatureAlgorithm">SignatureAlgorithm</a></td>
 </tr>
<a name="ctmap.DigitallySigned.signature"/>
 <tr>
  <td><code>signature</code></td>
  <td>bytes</td>
 </tr>
</table>

<a name="ctmap.DigitallySigned.HashAlgorithm"/>

### HashAlgorithm

HashAlgorithm defines the approved methods for object hashing.

<table>
 <tr>
  <th>Value</th>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.NONE"/>
 <tr>
  <td>NONE</td>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.SHA256"/>
 <tr>
  <td>SHA256</td>
 </tr>
<a name="ctmap.DigitallySigned.HashAlgorithm.SHA512"/>
 <tr>
  <td>SHA512</td>
 </tr>
</table>

<a name="ctmap.DigitallySigned.SignatureAlgorithm"/>

### SignatureAlgorithm

SignatureAlgorithm defines the algorithm used to sign the object.

<table>
 <tr>
  <th>Value</th>
 </tr>
<a name="ctmap.DigitallySigned.SignatureAlgorithm.ANONYMOUS"/>
 <tr>
  <td>ANONYMOUS</td>
 </tr>
<a name="ctmap.DigitallySigned.SignatureAlgorithm.ECDSA"/>
 <tr>
  <td>ECDSA</td>
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
  <td>leaf_data contains an entry stored in the leaf node.</td>
 </tr>
<a name="ctmap.GetLeafResponse.neighbors"/>
 <tr>
  <td><code>neighbors[]</code></td>
  <td>repeated bytes</td>
  <td>neighbors is a list of all the adjacent nodes along the path from the deepest node to the head.</td>
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
  <td>epoch is the epoch number of this map head.</td>
 </tr>
<a name="ctmap.MapHead.root"/>
 <tr>
  <td><code>root</code></td>
  <td>bytes</td>
  <td>root is the value of the root node of the Merkle Tree.</td>
 </tr>
<a name="ctmap.MapHead.issue_time"/>
 <tr>
  <td><code>issue_time</code></td>
  <td><a href="#google.protobuf.Timestamp">Timestamp</a></td>
  <td>issue_time is the time when this epoch was created. Monotonically increasing.</td>
 </tr>
</table>

<a name="ctmap.SignedMapHead"/>

### SignedMapHead

SignedMapHead represents a signed state of the Merkel Tree.

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
  <td>map_head contains the head node of the Merkle Tree along with other metadata.</td>
 </tr>
<a name="ctmap.SignedMapHead.signatures"/>
 <tr>
  <td><code>signatures</code></td>
  <td>map&lt;string, <a href="#ctmap.DigitallySigned">DigitallySigned</a>&gt;</td>
  <td>signatures is a set of map_head signatures. Each signature is identified by the first 64 bits of the public key that verifies it.</td>
 </tr>
</table>
